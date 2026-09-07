package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kube"
)

// CheckpointVersion is the shape of the persisted kernel state.
const CheckpointVersion = 1

// Defaults for where the checkpoint lives.
const (
	DefaultCheckpointNamespace = "farcast-system"
	DefaultCheckpointName      = "technocore-ledger"
	checkpointKey              = "checkpoint.json"
)

// Checkpoint is everything a restarted kernel needs to carry on accounting.
//
// It is the one piece of cloud-resident state TechnoCore keeps, and [ADR 0009]
// decision 2 is explicit about why that is acceptable where a keyring is not:
// the provider computed every number in it before TechnoCore did. The test is
// whether cloud-resident state tells the cloud something it does not already
// have, and a bill does not.
//
// [ADR 0009]: ../../docs/adr/0009-technocore-kernel-and-cost-metering.md
type Checkpoint struct {
	Version int           `json:"version"`
	Ledger  cost.Snapshot `json:"ledger"`

	// Last is when the kernel last accrued. Without it a restart cannot tell
	// an outage from an instant, and the spend during the outage is
	// invisible — an instance that forgot a day of spending would
	// under-report, in the flattering direction.
	Last time.Time `json:"last_reconcile"`

	// Observed is what the kernel saw the last time it looked, published so
	// an operator's machine can report spending without modelling it a second
	// time.
	//
	// The rate lives here rather than being recomputed by whatever asks,
	// because two implementations of the same arithmetic eventually quote
	// two different numbers — and the one an operator would act on is not
	// necessarily the one enforcement uses. It is written on the checkpoint's
	// own schedule, so it is as old as the last checkpoint and says when it
	// was taken.
	Observed Observation `json:"observed,omitzero"`
}

// Observation is one reconcile's view of the cluster, as the kernel saw it.
type Observation struct {
	At            time.Time `json:"at,omitzero"`
	Pods          int       `json:"pods,omitempty"`
	Unclassified  int       `json:"unclassified,omitempty"`
	RateHourlyUSD float64   `json:"rate_per_hour,omitempty"`

	// Level is the assessment the kernel is acting on, and Limit the figure it
	// is acting against. Both are the KERNEL's, not local state's: when a
	// limit has been changed locally and not redeployed, this is the one still
	// being enforced.
	Level string  `json:"level,omitempty"`
	Limit float64 `json:"limit,omitempty"`

	// Incomplete records that at least one metered namespace could not be
	// read. A report built on a partial picture must say so — the missing
	// namespace may hold the most expensive thing running.
	Incomplete  bool     `json:"incomplete,omitempty"`
	Unreachable []string `json:"unreachable,omitempty"`
}

// CheckpointKey is where the checkpoint lives inside its ConfigMap, exported
// so a reader outside this package cannot disagree with the writer about it.
func CheckpointKey() string { return checkpointKey }

// CheckpointStore persists a Checkpoint.
type CheckpointStore interface {
	// Load returns the stored checkpoint. The bool is false when there is
	// none — a first run, which is not an error.
	Load(ctx context.Context) (Checkpoint, bool, error)
	Save(ctx context.Context, cp Checkpoint) error
}

// ConfigMapClient is the slice of the Kubernetes client the store needs.
type ConfigMapClient interface {
	GetConfigMap(ctx context.Context, namespace, name string) (*kube.ConfigMap, error)
	SaveConfigMap(ctx context.Context, namespace string, cm kube.ConfigMap) error
}

// ConfigMapStore keeps the checkpoint in a ConfigMap.
type ConfigMapStore struct {
	Client    ConfigMapClient
	Namespace string
	Name      string
}

// NewConfigMapStore returns a store using the default location.
func NewConfigMapStore(c ConfigMapClient) *ConfigMapStore {
	return &ConfigMapStore{Client: c, Namespace: DefaultCheckpointNamespace, Name: DefaultCheckpointName}
}

func (s *ConfigMapStore) names() (string, string) {
	ns, name := s.Namespace, s.Name
	if ns == "" {
		ns = DefaultCheckpointNamespace
	}
	if name == "" {
		name = DefaultCheckpointName
	}
	return ns, name
}

// Load reads the checkpoint. A missing ConfigMap is a first run, not a
// failure; a present but unreadable one IS a failure, because carrying on
// from zero would silently reset the meter and the limit would never trip.
func (s *ConfigMapStore) Load(ctx context.Context) (Checkpoint, bool, error) {
	ns, name := s.names()
	cm, err := s.Client.GetConfigMap(ctx, ns, name)
	if errors.Is(err, kube.ErrNotFound) {
		return Checkpoint{}, false, nil
	}
	if err != nil {
		return Checkpoint{}, false, fmt.Errorf("kernel: read the checkpoint: %w", err)
	}
	raw, ok := cm.Data[checkpointKey]
	if !ok {
		return Checkpoint{}, false, fmt.Errorf("kernel: checkpoint %s/%s has no %q", ns, name, checkpointKey)
	}
	var cp Checkpoint
	if err := json.Unmarshal([]byte(raw), &cp); err != nil {
		return Checkpoint{}, false, fmt.Errorf("kernel: decode the checkpoint: %w", err)
	}
	if cp.Version != CheckpointVersion {
		return Checkpoint{}, false, fmt.Errorf("kernel: unknown checkpoint version %d (this build writes %d)",
			cp.Version, CheckpointVersion)
	}
	return cp, true, nil
}

// Save writes the checkpoint, carrying the ResourceVersion it just read so a
// concurrent writer produces a conflict rather than silently winning.
func (s *ConfigMapStore) Save(ctx context.Context, cp Checkpoint) error {
	ns, name := s.names()
	cp.Version = CheckpointVersion
	blob, err := json.Marshal(cp)
	if err != nil {
		return fmt.Errorf("kernel: encode the checkpoint: %w", err)
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
		Data: map[string]string{checkpointKey: string(blob)},
	}
	if existing, err := s.Client.GetConfigMap(ctx, ns, name); err == nil {
		cm.Metadata.ResourceVersion = existing.Metadata.ResourceVersion
	} else if !errors.Is(err, kube.ErrNotFound) {
		return fmt.Errorf("kernel: read the checkpoint before writing it: %w", err)
	}
	if err := s.Client.SaveConfigMap(ctx, ns, cm); err != nil {
		return fmt.Errorf("kernel: write the checkpoint: %w", err)
	}
	return nil
}

// Restore seeds the reconciler from a stored checkpoint.
//
// A first run — no checkpoint — leaves the reconciler as configured and
// reports false. A checkpoint for a DIFFERENT period is ignored rather than
// merged: a monthly limit applies to a month, and folding last month's spend
// into this one would trip the limit on money already accounted for.
func (r *Reconciler) Restore(ctx context.Context, store CheckpointStore) (bool, error) {
	cp, ok, err := store.Load(ctx)
	if err != nil || !ok {
		return false, err
	}
	start, end := r.Ledger.Period()
	if !cp.Ledger.PeriodStart.Equal(start) || !cp.Ledger.PeriodEnd.Equal(end) {
		return false, nil
	}
	ledger, err := cost.Restore(cp.Ledger)
	if err != nil {
		return false, fmt.Errorf("kernel: restore the ledger: %w", err)
	}
	r.Ledger = ledger
	r.Last = cp.Last
	// Carried across the restart so a report asked in the gap before the first
	// reconcile shows the last thing that was true, timestamped, rather than
	// an instance that appears to be running nothing.
	r.Observed = cp.Observed
	return true, nil
}

// Save writes the reconciler's current state.
func (r *Reconciler) Save(ctx context.Context, store CheckpointStore) error {
	return store.Save(ctx, Checkpoint{
		Version:  CheckpointVersion,
		Ledger:   r.Ledger.Snapshot(),
		Last:     r.Last,
		Observed: r.Observed,
	})
}
