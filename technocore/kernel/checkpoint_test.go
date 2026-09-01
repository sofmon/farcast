package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kube"
	"github.com/sofmon/farcast/technocore/tier"
)

type fakeConfigMaps struct {
	cm      *kube.ConfigMap
	getErr  error
	saveErr error
	saves   []kube.ConfigMap
}

func (f *fakeConfigMaps) GetConfigMap(_ context.Context, _, name string) (*kube.ConfigMap, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.cm == nil {
		return nil, &kube.APIError{Status: kube.Status{Code: 404}}
	}
	return f.cm, nil
}

func (f *fakeConfigMaps) SaveConfigMap(_ context.Context, ns string, cm kube.ConfigMap) error {
	f.saves = append(f.saves, cm)
	if f.saveErr != nil {
		return f.saveErr
	}
	cm.Metadata.Namespace = ns
	cm.Metadata.ResourceVersion = "next"
	f.cm = &cm
	return nil
}

func runningApp() *fakeCluster {
	return &fakeCluster{
		byNS: map[string][]kube.Pod{
			"farcast-apps": {pod("web-1", "farcast-apps", "web", tier.App, kube.PodRunning, "100m", "128Mi")},
		},
		depsNS: map[string][]kube.Deployment{
			"farcast-apps": {deployment("web", "farcast-apps", "web", tier.App, 1)},
		},
	}
}

// The reason the checkpoint exists: a meter that resets to zero on restart
// never trips the limit, so an instance could burn through it indefinitely as
// long as the kernel restarted often enough.
func TestARestartedKernelRemembersWhatWasSpent(t *testing.T) {
	store := &ConfigMapStore{Client: &fakeConfigMaps{}, Namespace: "farcast-system", Name: "ledger"}
	f := runningApp()

	first := reconciler(t, f, "farcast-apps")
	if _, err := first.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Reconcile(context.Background(), start.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	spent := first.Ledger.Accrued().Total
	if spent <= 0 {
		t.Fatal("test setup: nothing was spent")
	}
	if err := first.Save(context.Background(), store); err != nil {
		t.Fatal(err)
	}

	// A new process, with a fresh empty ledger.
	second := reconciler(t, f, "farcast-apps")
	restored, err := second.Restore(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if !restored {
		t.Fatal("the checkpoint was not restored")
	}
	if got := second.Ledger.Accrued().Total; got != spent {
		t.Errorf("restored total = %.4f, want %.4f", got, spent)
	}
	if !second.Last.Equal(start.Add(3 * time.Hour)) {
		t.Errorf("Last = %v, want the checkpointed time", second.Last)
	}
}

// Without Last, a restart cannot tell an outage from an instant, and the
// spend during the outage is invisible.
func TestARestoredKernelBillsTheOutageItSleptThrough(t *testing.T) {
	store := &ConfigMapStore{Client: &fakeConfigMaps{}}
	f := runningApp()

	first := reconciler(t, f, "farcast-apps")
	if _, err := first.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	if err := first.Save(context.Background(), store); err != nil {
		t.Fatal(err)
	}

	second := reconciler(t, f, "farcast-apps")
	if _, err := second.Restore(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	// Six hours of downtime, during which the application kept running.
	rep, err := second.Reconcile(context.Background(), start.Add(6*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Billed != 6*time.Hour {
		t.Errorf("billed %v after a restart, want the whole 6h gap", rep.Billed)
	}
	if !rep.Reconstructed {
		t.Error("the reconstructed gap must be flagged, not passed off as measured")
	}
}

// A first run is not an error.
func TestNoCheckpointIsAFirstRunNotAFailure(t *testing.T) {
	store := &ConfigMapStore{Client: &fakeConfigMaps{}}
	r := reconciler(t, runningApp(), "farcast-apps")
	restored, err := r.Restore(context.Background(), store)
	if err != nil {
		t.Fatalf("a missing checkpoint must not be an error: %v", err)
	}
	if restored {
		t.Error("nothing should have been restored")
	}
}

// A monthly limit applies to a month. Folding last period's spend into this
// one would trip the limit on money already accounted for.
func TestACheckpointFromAnotherPeriodIsIgnored(t *testing.T) {
	backing := &fakeConfigMaps{}
	store := &ConfigMapStore{Client: backing}

	old, err := cost.NewLedger(start.AddDate(0, -1, 0), start)
	if err != nil {
		t.Fatal(err)
	}
	old.Accrue(start.AddDate(0, -1, 0), "web", 10, time.Hour)
	if err := store.Save(context.Background(), Checkpoint{Ledger: old.Snapshot(), Last: start}); err != nil {
		t.Fatal(err)
	}

	r := reconciler(t, runningApp(), "farcast-apps")
	restored, err := r.Restore(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	if restored {
		t.Error("a checkpoint for a different period must not be restored")
	}
	if got := r.Ledger.Accrued().Total; got != 0 {
		t.Errorf("last period's %.2f leaked into this one", got)
	}
}

// Carrying on from zero would silently reset the meter, so an unreadable
// checkpoint is a failure rather than a fresh start.
func TestAnUnreadableCheckpointIsAFailureNotAFreshStart(t *testing.T) {
	cases := map[string]*kube.ConfigMap{
		"no data key":  {Data: map[string]string{"other": "{}"}},
		"not json":     {Data: map[string]string{checkpointKey: "{{{"}},
		"wrong versio": {Data: map[string]string{checkpointKey: `{"version":99}`}},
	}
	for name, cm := range cases {
		store := &ConfigMapStore{Client: &fakeConfigMaps{cm: cm}}
		r := reconciler(t, runningApp(), "farcast-apps")
		if _, err := r.Restore(context.Background(), store); err == nil {
			t.Errorf("%s: expected an error rather than a silent reset to zero", name)
		}
	}
}

func TestALoadFailureIsNotMistakenForAFirstRun(t *testing.T) {
	store := &ConfigMapStore{Client: &fakeConfigMaps{getErr: errors.New("api server unreachable")}}
	r := reconciler(t, runningApp(), "farcast-apps")
	if _, err := r.Restore(context.Background(), store); err == nil {
		t.Fatal("an unreachable API server must not read as a first run")
	}
}

// TechnoCore runs one replica so the ledger has one writer. Carrying the
// ResourceVersion is what makes a second one conflict rather than silently
// overwrite the ledger with a stale copy.
func TestSaveCarriesTheResourceVersionItRead(t *testing.T) {
	backing := &fakeConfigMaps{cm: &kube.ConfigMap{
		Metadata: kube.ObjectMeta{Name: "technocore-ledger", ResourceVersion: "77"},
		Data:     map[string]string{checkpointKey: `{"version":1}`},
	}}
	store := &ConfigMapStore{Client: backing}
	r := reconciler(t, runningApp(), "farcast-apps")
	if err := r.Save(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	if len(backing.saves) != 1 {
		t.Fatalf("saves = %d, want 1", len(backing.saves))
	}
	if backing.saves[0].Metadata.ResourceVersion != "77" {
		t.Errorf("ResourceVersion = %q, want the one just read",
			backing.saves[0].Metadata.ResourceVersion)
	}
}

func TestSaveWritesAVersionedPayloadUnderTheDefaultName(t *testing.T) {
	backing := &fakeConfigMaps{}
	store := NewConfigMapStore(backing)
	r := reconciler(t, runningApp(), "farcast-apps")
	if err := r.Save(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	cm := backing.saves[0]
	if cm.Metadata.Name != DefaultCheckpointName || cm.Metadata.Namespace != DefaultCheckpointNamespace {
		t.Errorf("wrote to %s/%s, want the defaults", cm.Metadata.Namespace, cm.Metadata.Name)
	}
	var cp Checkpoint
	if err := json.Unmarshal([]byte(cm.Data[checkpointKey]), &cp); err != nil {
		t.Fatal(err)
	}
	if cp.Version != CheckpointVersion {
		t.Errorf("version = %d, want %d", cp.Version, CheckpointVersion)
	}
	if !strings.Contains(cm.Data[checkpointKey], `"ledger"`) {
		t.Error("the payload does not carry the ledger")
	}
	if cm.Metadata.Labels["app.kubernetes.io/managed-by"] != "farcast" {
		t.Error("the checkpoint should be recognisable as FarCast's in a console")
	}
}

func TestSaveSurfacesAWriteFailure(t *testing.T) {
	store := &ConfigMapStore{Client: &fakeConfigMaps{saveErr: errors.New("nope")}}
	r := reconciler(t, runningApp(), "farcast-apps")
	if err := r.Save(context.Background(), store); err == nil {
		t.Fatal("a failed checkpoint write must surface")
	}
}
