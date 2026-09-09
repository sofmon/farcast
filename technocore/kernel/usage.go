package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sofmon/farcast/technocore/kube"
	"github.com/sofmon/farcast/technocore/usage"
)

// sampleUsage folds current consumption into the profiles.
//
// It runs after the workload set is known, and only attributes a reading to a
// pod the meter already saw. That ordering is the attribution rule: the
// profile set can never name an application the cost path does not, and a
// reading for a pod that vanished between the two calls is dropped rather
// than filed under a guess.
//
// Nothing here can fail the tick. Per [ADR 0014] decision 2 usage is
// advisory, so every namespace refusing is still only a finding — the exact
// opposite of metering, where reading nothing means reporting $0 for an
// instance that is spending.
//
// [ADR 0014]: ../../docs/adr/0014-observed-usage.md
func (r *Reconciler) sampleUsage(ctx context.Context, namespaces []string, rep *Report) {
	if r.Usage == nil {
		return
	}
	type key struct{ ns, name string }
	index := make(map[key]*Workload, len(rep.Workloads))
	for i := range rep.Workloads {
		w := &rep.Workloads[i]
		index[key{w.Namespace, w.Name}] = w
	}

	byApp := map[string][]usage.PodUsage{}
	fresh := make(map[string]time.Time, len(rep.Workloads))
	for _, ns := range namespaces {
		items, err := r.Cluster.ListPodMetrics(ctx, ns, r.Selector)
		if err != nil {
			rep.UsageUnavailable = append(rep.UsageUnavailable,
				fmt.Sprintf("%s: %v", ns, safeNamespaceError(err)))
			continue
		}
		for _, m := range items {
			w := index[key{ns, m.Metadata.Name}]
			if w == nil {
				continue
			}
			// Remembered whether or not it is new. Recording only the new
			// ones would erase the memory of a repeat on the very tick that
			// saw it, and the same reading would be taken in again next tick.
			// Remembered whether or not it is new. Recording only the new
			// ones would erase the memory of a repeat on the very tick that
			// saw it, and the same reading would be taken in again next tick.
			id := ns + "/" + m.Metadata.Name
			fresh[id] = m.Timestamp
			if !r.newReading(id, m.Timestamp) {
				rep.UsageRepeated++
				continue
			}
			cpu, mem, err := m.Usage()
			if err != nil {
				// A reading this build cannot parse is skipped, not fatal:
				// the same input on the request path IS fatal, because there
				// it becomes money.
				rep.UsageUnavailable = append(rep.UsageUnavailable, fmt.Sprintf("%s: %v", id, err))
				continue
			}
			byApp[w.App] = append(byApp[w.App], usage.PodUsage{
				Pod: m.Metadata.Name, CPUMilli: cpu, MemMiB: mem,
				RequestCPUMilli: w.CPUMilli, RequestMemMiB: w.MemMiB,
			})
			rep.UsageSampled++
		}
	}
	for app, pods := range byApp {
		r.Usage.Record(rep.At, app, pods)
	}
	// Replaced rather than merged, so the map cannot grow with every pod the
	// instance has ever scheduled. A pod that comes back after an absence is
	// simply new again, which costs one duplicate-free sample.
	r.lastReading = fresh
	r.usageUnavailable = rep.UsageUnavailable
}

// newReading reports whether this is a measurement the kernel has not already
// taken in.
//
// metrics-server refreshes on its own cadence — roughly every fifteen seconds
// — and serves the same reading until it does. A kernel polling every thirty
// seconds usually gets a new one, and occasionally does not; counting the
// repeat would weight whatever the sampler happened to catch. A reading with
// no timestamp at all is taken as new, because the alternative is a server
// whose readings are never sampled.
func (r *Reconciler) newReading(id string, at time.Time) bool {
	if at.IsZero() {
		return true
	}
	return !at.Equal(r.lastReading[id])
}

// Profiles is the persisted usage document — what `farcast usage` reads.
type Profiles struct {
	Version int       `json:"version"`
	At      time.Time `json:"at"`

	Store usage.Snapshot `json:"store"`

	// Unavailable names namespaces whose metrics could not be read when this
	// was written. An empty profile with this set means "not measured", which
	// is a different thing from "measured as zero" — and the difference is
	// the whole reason it is recorded rather than inferred from emptiness.
	Unavailable []string `json:"unavailable,omitempty"`

	// Advice is what the kernel would do to each application's reservation,
	// and why it is holding where it is. It is published whether or not
	// adapting is switched on: an operator deciding whether to switch it on
	// needs to see what it would have done.
	Advice []Adaptation `json:"advice,omitempty"`

	// Adapting records whether the kernel is acting on that advice. Without
	// it a report cannot tell a kernel that is holding back from one that is
	// merely thinking out loud.
	Adapting bool `json:"adapting,omitempty"`

	// TrimmedTo is the window actually retained when the byte budget
	// shortened it, and Dropped names applications the budget cost. Both are
	// published because a reader would otherwise see a short window and
	// conclude the instance had just started.
	TrimmedTo int      `json:"trimmed_to,omitempty"`
	Dropped   []string `json:"dropped,omitempty"`
}

// ProfilesVersion is the shape of the persisted usage document.
const ProfilesVersion = 1

// Defaults for where the profiles live. They are a separate ConfigMap from
// the ledger deliberately: the ledger must always be writable, and an
// advisory document must never be able to make the cost checkpoint fail.
const (
	DefaultProfilesName = "technocore-profiles"
	profilesKey         = "profiles.json"
)

// ProfilesKey is where the document lives inside its ConfigMap, exported so a
// reader outside this package cannot disagree with the writer about it.
func ProfilesKey() string { return profilesKey }

// ProfileStore persists the usage document.
type ProfileStore interface {
	// Load returns the stored document. The bool is false when there is
	// none, which is a first run rather than a failure.
	Load(ctx context.Context) (Profiles, bool, error)
	Save(ctx context.Context, p Profiles) error
	// Budget is the largest encoded document this store can hold. It is the
	// store's to declare rather than the caller's to assume: what bounds the
	// document is where it is being put.
	Budget() int
}

// ConfigMapProfiles keeps the usage document in its own ConfigMap.
type ConfigMapProfiles struct {
	Client    ConfigMapClient
	Namespace string
	Name      string
	// MaxBytes bounds the encoded document. Zero means [usage.DefaultBudget],
	// which is half of what the API server will accept — the margin exists
	// because the failure mode of discovering otherwise is a write that
	// starts being rejected months after it worked.
	MaxBytes int
}

// NewConfigMapProfiles returns a store using the default location.
func NewConfigMapProfiles(c ConfigMapClient) *ConfigMapProfiles {
	return &ConfigMapProfiles{Client: c, Namespace: DefaultCheckpointNamespace, Name: DefaultProfilesName}
}

func (s *ConfigMapProfiles) names() (string, string) {
	ns, name := s.Namespace, s.Name
	if ns == "" {
		ns = DefaultCheckpointNamespace
	}
	if name == "" {
		name = DefaultProfilesName
	}
	return ns, name
}

// Load reads the usage document.
func (s *ConfigMapProfiles) Load(ctx context.Context) (Profiles, bool, error) {
	ns, name := s.names()
	cm, err := s.Client.GetConfigMap(ctx, ns, name)
	if errors.Is(err, kube.ErrNotFound) {
		return Profiles{}, false, nil
	}
	if err != nil {
		return Profiles{}, false, fmt.Errorf("kernel: read the usage profiles: %w", err)
	}
	raw, ok := cm.Data[profilesKey]
	if !ok {
		return Profiles{}, false, fmt.Errorf("kernel: usage profiles %s/%s have no %q", ns, name, profilesKey)
	}
	var p Profiles
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return Profiles{}, false, fmt.Errorf("kernel: decode the usage profiles: %w", err)
	}
	if p.Version != ProfilesVersion {
		return Profiles{}, false, fmt.Errorf("kernel: unknown usage profile version %d (this build writes %d)",
			p.Version, ProfilesVersion)
	}
	return p, true, nil
}

// Save writes the usage document, trimming it to the budget first.
func (s *ConfigMapProfiles) Save(ctx context.Context, p Profiles) error {
	ns, name := s.names()
	p.Version = ProfilesVersion
	blob, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("kernel: encode the usage profiles: %w", err)
	}
	cm := kube.ConfigMap{
		Metadata: kube.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "technocore",
				"app.kubernetes.io/managed-by": "farcast",
			},
		},
		Data: map[string]string{profilesKey: string(blob)},
	}
	if existing, err := s.Client.GetConfigMap(ctx, ns, name); err == nil {
		cm.Metadata.ResourceVersion = existing.Metadata.ResourceVersion
	} else if !errors.Is(err, kube.ErrNotFound) {
		return fmt.Errorf("kernel: read the usage profiles before writing them: %w", err)
	}
	if err := s.Client.SaveConfigMap(ctx, ns, cm); err != nil {
		return fmt.Errorf("kernel: write the usage profiles: %w", err)
	}
	return nil
}

// Budget is the byte budget this store can hold.
func (s *ConfigMapProfiles) Budget() int {
	if s.MaxBytes > 0 {
		return s.MaxBytes
	}
	return usage.DefaultBudget
}

// RestoreUsage seeds the profiles from a stored document.
//
// The second return is not a failure to propagate: a usage document that
// cannot be read is DISCARDED and collection starts again from nothing, and
// the caller's job is to say so rather than to stop. That is the opposite of
// the ledger, where an unreadable checkpoint is fatal — carrying on from zero
// there would silently reset the meter and the limit would never trip. Here,
// carrying on from zero costs a day of advisory history and nothing else.
func (r *Reconciler) RestoreUsage(ctx context.Context, store ProfileStore) (bool, error) {
	if r.Usage == nil || store == nil {
		return false, nil
	}
	doc, ok, err := store.Load(ctx)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	restored, err := usage.Restore(doc.Store)
	if err != nil {
		return false, err
	}
	r.Usage = restored
	return true, nil
}

// SaveUsage writes the profiles, having first forgotten what has aged out of
// the window and trimmed whatever is left to the budget.
func (r *Reconciler) SaveUsage(ctx context.Context, store ProfileStore, now time.Time) error {
	if r.Usage == nil || store == nil {
		return nil
	}
	configured := r.Usage.Hours()
	r.Usage.Forget(now.Add(-time.Duration(configured) * time.Hour))

	trimmed, err := r.Usage.Trim(store.Budget())
	if err != nil {
		return err
	}
	doc := Profiles{
		Version:     ProfilesVersion,
		At:          now,
		Store:       r.Usage.Snapshot(),
		Unavailable: r.usageUnavailable,
		Dropped:     trimmed.Dropped,
		Advice:      r.lastAdvice,
		Adapting:    r.Adapting,
	}
	if trimmed.Shortened(configured) {
		doc.TrimmedTo = trimmed.Hours
	}
	return store.Save(ctx, doc)
}
