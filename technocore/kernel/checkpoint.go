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
//
// Version 2 (2026-11-12) keys per-application spending by AppKey —
// "<namespace>/<app>" rather than the bare name — and adds Stops and Floor.
// A kernel still reads version 1: its bare keys are kept exactly as they
// were, every figure with them, and read as "accrued before namespaces were
// recorded". It writes only version 2.
//
// The upgrade is one way. A kernel built before version 2 refuses a version
// 2 checkpoint (it reads its own version only), so rolling the kernel's image
// back past this change leaves it failing to start — restore the ledger —
// and the instance with no cost enforcement until a kernel that reads
// version 2 is deployed again. Roll forward, not back.
const CheckpointVersion = 2

// OldestCheckpointVersion is the oldest checkpoint this build still reads.
const OldestCheckpointVersion = 1

// ErrCheckpointVersion marks a checkpoint of a version this build does not
// read. Refused rather than best-guessed: a meter that misread its own
// history would under-report in the flattering direction.
var ErrCheckpointVersion = errors.New("kernel: unknown checkpoint version")

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
// The stop and floor records pass the same test, on the provider's own
// records rather than its bill. Every stop is a patch to a Deployment's scale
// subresource, and the audit policy logs writes to the built-in API groups
// with their full bodies in Admin Activity, kept 400 days and undeletable
// ([ADR 0019]): the namespace, the Deployment, the time, the caller — the
// kernel's own service account, which scales nothing to zero for any reason
// but cost — and the zero. The saving is the price of requests the provider
// holds in the same Deployment's body and bills itself. The floor is that
// set of stops plus the limit, which is an argument in the kernel's own
// Deployment body, and the provider's bill; its levers are fixed text. Two
// limits on that claim. ADR 0019 calls the scale-down's full body "very
// likely", inferred from the documented policy and not yet seen in a walk.
// And the checkpoint is saved at once after a stop, or when the floor is
// first reached, rather than only on its schedule: one off-schedule
// Metadata-level write of this ConfigMap — this one alone; the usage
// profiles wait for the schedule — beside each such event. Beside a stop it
// dates the stop a second time. The floor first reached has no scale-down
// of its own beside it, but its time is derivable from what the provider
// already holds: the scale-downs, the limit in the kernel's Deployment
// arguments, and its own bill crossing that limit. Nothing here is written
// to the workload itself.
//
// [ADR 0009]: ../../docs/adr/0009-technocore-kernel-and-cost-metering.md
// [ADR 0019]: ../../docs/adr/0019-what-the-cluster-tells-its-provider.md
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

	// Stops are the workloads a cost shutdown scaled to zero that the kernel
	// has not since seen running or gone, in a namespace it still meters
	// (Stop). Kept across a period boundary: a stopped application stays
	// stopped when the month turns.
	Stops []Stop `json:"stops,omitempty"`

	// Floor is set while the kernel is at the instance floor (ADR 0009
	// decision 8). Not carried into another period, where the limit starts
	// again.
	Floor *Floor `json:"floor,omitempty"`
}

// RecordsStops reports whether the kernel that wrote this checkpoint records
// its stops and the floor. A version 1 kernel did neither, so its silence
// says nothing — an empty list from it is not "nothing was stopped".
func (cp Checkpoint) RecordsStops() bool { return cp.Version >= 2 }

// DecodeCheckpoint reads a stored checkpoint of any version this build reads,
// in this build's shape. Version is left as written, so a reader can tell
// what the writer recorded (RecordsStops). A version outside the range
// returns the decoded checkpoint and an error wrapping ErrCheckpointVersion;
// a document that is not JSON returns the decoder's error.
//
// It is the one decoder both sides use — the kernel restoring itself, and
// 'farcast costs' and 'world' reading what it wrote — so the two cannot
// disagree about which versions exist.
func DecodeCheckpoint(raw []byte) (Checkpoint, error) {
	var cp Checkpoint
	if err := json.Unmarshal(raw, &cp); err != nil {
		return Checkpoint{}, err
	}
	if cp.Version < OldestCheckpointVersion || cp.Version > CheckpointVersion {
		return cp, fmt.Errorf("%w %d (this build writes %d and reads %d to %d)",
			ErrCheckpointVersion, cp.Version, CheckpointVersion, OldestCheckpointVersion, CheckpointVersion)
	}
	if !cp.RecordsStops() {
		// A version 1 kernel wrote neither; a field claiming otherwise did
		// not come from one.
		cp.Stops, cp.Floor = nil, nil
	}
	return cp, nil
}

// Observation is one reconcile's view of the cluster, as the kernel saw it.
type Observation struct {
	At           time.Time `json:"at,omitzero"`
	Pods         int       `json:"pods,omitempty"`
	Unclassified int       `json:"unclassified,omitempty"`
	// RateHourlyUSD includes Overhead, the instance-level charges — today the
	// load-balancer carrier — that belong to no application.
	RateHourlyUSD float64 `json:"rate_per_hour,omitempty"`
	Overhead      float64 `json:"overhead_per_hour,omitempty"`
	Carrier       string  `json:"carrier,omitempty"`

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
	cp, err := DecodeCheckpoint([]byte(raw))
	if errors.Is(err, ErrCheckpointVersion) {
		return Checkpoint{}, false, err
	}
	if err != nil {
		return Checkpoint{}, false, fmt.Errorf("kernel: decode the checkpoint: %w", err)
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
// into this one would trip the limit on money already accounted for. Its
// stop records are kept all the same, because they are about workloads
// rather than money: an application stopped last month is still stopped,
// and still for the same reason.
//
// A version 1 checkpoint restores exactly: the ledger snapshot is the same
// shape in both versions, so every figure — totals, confirmed, expected,
// overhead, calibration — comes back as it was written. Its per-application
// figures keep their bare keys. They are not re-keyed to a namespace, even
// where only one namespace now runs that name: which namespace accrued them
// was never recorded, and a guess written into the ledger would outlive the
// evidence for it. They stay as written until the period ends, read as
// "accrued before namespaces were recorded", while new spending accrues
// under AppKey beside them.
func (r *Reconciler) Restore(ctx context.Context, store CheckpointStore) (bool, error) {
	cp, ok, err := store.Load(ctx)
	if err != nil || !ok {
		return false, err
	}
	r.Stops = nil
	for _, s := range cp.Stops {
		if s.Namespace != "" && s.Deployment != "" {
			r.Stops = append(r.Stops, s)
		}
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
	r.Floor = cp.Floor
	return true, nil
}

// Save writes the reconciler's current state.
func (r *Reconciler) Save(ctx context.Context, store CheckpointStore) error {
	return store.Save(ctx, Checkpoint{
		Version:  CheckpointVersion,
		Ledger:   r.Ledger.Snapshot(),
		Last:     r.Last,
		Observed: r.Observed,
		Stops:    r.Stops,
		Floor:    r.Floor,
	})
}
