package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kube"
)

func confirmationsCM(t *testing.T, cs ...cost.Confirmation) *fakeConfigMaps {
	t.Helper()
	blob, err := Marshal(cs)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeConfigMaps{cm: &kube.ConfigMap{
		Metadata: kube.ObjectMeta{Name: DefaultConfirmationsName},
		Data:     map[string]string{ConfirmationsKey(): string(blob)},
	}}
}

// The path the operator's machine writes and the kernel reads. It is the whole
// point of the two-signal model: expected enforces, confirmed corrects.
func TestAPushedConfirmationCorrectsTheEstimate(t *testing.T) {
	f := runningApp()
	r := reconciler(t, f, "farcast-apps")
	if _, err := r.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), start.Add(10*time.Hour)); err != nil {
		t.Fatal(err)
	}
	before := r.Ledger.Accrued()
	if before.HasConfirmation {
		t.Fatal("test setup: nothing should be confirmed yet")
	}

	// The provider says the first five hours cost 20% more than modelled.
	window := r.Ledger.Accrued().Total / 2
	r.Confirmations = &ConfigMapConfirmations{Client: confirmationsCM(t, cost.Confirmation{
		Start: start, End: start.Add(5 * time.Hour), USD: window * 1.2,
	})}

	rep, err := r.Reconcile(context.Background(), start.Add(11*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rep.ConfirmationsApplied != 1 {
		t.Fatalf("applied %d confirmations, want 1", rep.ConfirmationsApplied)
	}
	if !rep.Accrual.HasConfirmation {
		t.Error("the report does not know it has been confirmed")
	}
	if rep.Accrual.Calibration <= 1 {
		t.Errorf("calibration = %.3f, want the model raised toward the provider's figure", rep.Accrual.Calibration)
	}
	if rep.ConfirmationsRefused != 0 {
		t.Errorf("an in-clamp confirmation was refused")
	}
}

// The same document is read every tick, so re-applying must be a no-op rather
// than an error or a double count.
func TestConfirmationsAreIdempotentAcrossTicks(t *testing.T) {
	f := runningApp()
	r := reconciler(t, f, "farcast-apps")
	r.Confirmations = &ConfigMapConfirmations{Client: confirmationsCM(t, cost.Confirmation{
		Start: start, End: start.Add(2 * time.Hour), USD: 1,
	})}

	for i := range 4 {
		rep, err := r.Reconcile(context.Background(), start.Add(time.Duration(i+1)*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 && rep.ConfirmationsApplied != 1 {
			t.Fatalf("first tick applied %d, want 1", rep.ConfirmationsApplied)
		}
		if i > 0 && rep.ConfirmationsApplied != 0 {
			t.Fatalf("tick %d re-applied a confirmation it already had", i)
		}
	}
	a := r.Ledger.Accrued()
	if a.Confirmed != 1 {
		t.Errorf("confirmed = %.4f, want 1 — the same window was counted more than once", a.Confirmed)
	}
}

// A confirmation for a period that has rolled away is expected, not a fault:
// the operator's document keeps last month's figures and the kernel is
// accounting for this month.
func TestConfirmationsForAnotherPeriodAreSkippedQuietly(t *testing.T) {
	f := runningApp()
	r := reconciler(t, f, "farcast-apps")
	r.Confirmations = &ConfigMapConfirmations{Client: confirmationsCM(t, cost.Confirmation{
		Start: start.AddDate(0, -1, 0), End: start.AddDate(0, -1, 0).Add(time.Hour), USD: 5,
	})}
	rep, err := r.Reconcile(context.Background(), start)
	if err != nil {
		t.Fatalf("a stale confirmation must not fail the tick: %v", err)
	}
	if rep.ConfirmationsApplied != 0 {
		t.Error("a confirmation outside the period was applied")
	}
	if rep.Accrual.HasConfirmation {
		t.Error("a skipped confirmation must not count as one")
	}
}

// The security property, end to end through the push path: a confirmation the
// operator's machine did not write correctly — or that someone edited in the
// cluster — cannot switch the guard off.
func TestASpoofedConfirmationCannotLoosenTheGuard(t *testing.T) {
	f := runningApp()
	r := reconciler(t, f, "farcast-apps")
	if _, err := r.Reconcile(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), start.Add(10*time.Hour)); err != nil {
		t.Fatal(err)
	}
	honest := r.Ledger.Accrued().Total

	r.Confirmations = &ConfigMapConfirmations{Client: confirmationsCM(t, cost.Confirmation{
		Start: start, End: start.Add(10 * time.Hour), USD: 0,
	})}
	rep, err := r.Reconcile(context.Background(), start.Add(11*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rep.ConfirmationsRefused != 1 {
		t.Fatalf("refused %d confirmations, want 1", rep.ConfirmationsRefused)
	}
	if rep.Accrual.Total < honest {
		t.Errorf("total fell from %.4f to %.4f on a zero confirmation", honest, rep.Accrual.Total)
	}
	if len(rep.Accrual.Discrepancies) != 1 {
		t.Error("the refusal was not surfaced as a discrepancy")
	}
}

// An instance whose operator has confirmed nothing runs on expected alone —
// correctly, and visibly.
func TestAnAbsentConfirmationsDocumentIsNotAFailure(t *testing.T) {
	r := reconciler(t, runningApp(), "farcast-apps")
	r.Confirmations = &ConfigMapConfirmations{Client: &fakeConfigMaps{}}
	rep, err := r.Reconcile(context.Background(), start)
	if err != nil {
		t.Fatalf("a missing confirmations document must not fail the tick: %v", err)
	}
	if rep.Accrual.HasConfirmation {
		t.Error("nothing was confirmed")
	}
}

// A document that is present but unreadable is a different thing entirely:
// the operator pushed something and the kernel could not use it, which they
// need to be told.
func TestAnUnreadableConfirmationsDocumentFailsTheTick(t *testing.T) {
	cases := map[string]string{
		"not json":      "{{{",
		"wrong version": `{"version":99,"confirmations":[]}`,
	}
	for name, body := range cases {
		r := reconciler(t, runningApp(), "farcast-apps")
		r.Confirmations = &ConfigMapConfirmations{Client: &fakeConfigMaps{cm: &kube.ConfigMap{
			Data: map[string]string{ConfirmationsKey(): body},
		}}}
		if _, err := r.Reconcile(context.Background(), start); err == nil {
			t.Errorf("%s: expected the tick to fail", name)
		}
	}
}

func TestAReadFailureFailsTheTick(t *testing.T) {
	r := reconciler(t, runningApp(), "farcast-apps")
	r.Confirmations = &ConfigMapConfirmations{Client: &fakeConfigMaps{getErr: errors.New("unreachable")}}
	if _, err := r.Reconcile(context.Background(), start); err == nil {
		t.Fatal("an unreachable API server must not read as no confirmations")
	}
}

// The operator side writes the document the kernel reads. Two spellings of one
// key is a bug that only shows up in production.
func TestTheDocumentRoundTrips(t *testing.T) {
	cs := []cost.Confirmation{
		{Start: start, End: start.Add(time.Hour), USD: 1.25, AsOf: start.Add(48 * time.Hour)},
		{Start: start.Add(time.Hour), End: start.Add(2 * time.Hour), USD: 2.5},
	}
	blob, err := Marshal(cs)
	if err != nil {
		t.Fatal(err)
	}
	var doc Confirmations
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != ConfirmationsVersion {
		t.Errorf("version = %d, want %d", doc.Version, ConfirmationsVersion)
	}
	if len(doc.Confirmations) != 2 || doc.Confirmations[0].USD != 1.25 {
		t.Fatalf("round trip lost data: %+v", doc.Confirmations)
	}
	if !doc.Confirmations[0].AsOf.Equal(cs[0].AsOf) {
		t.Error("the provider's own as-of timestamp did not survive")
	}
}

// A confirmation the kernel cannot make sense of is the operator's data being
// wrong, and the kernel should say so rather than skip it in silence.
func TestAMalformedConfirmationIsReported(t *testing.T) {
	r := reconciler(t, runningApp(), "farcast-apps")
	r.Confirmations = &ConfigMapConfirmations{Client: confirmationsCM(t, cost.Confirmation{
		Start: start, End: start.Add(time.Hour), USD: -5,
	})}
	if _, err := r.Reconcile(context.Background(), start); err == nil {
		t.Fatal("a negative confirmed amount must be reported, not skipped")
	}
}

// The writer and the reader must agree exactly. This is the one failure mode
// that survives every unit test on either side: the CLI writes a document the
// kernel silently cannot see, and the instance runs on `expected` alone while
// the operator believes it is calibrated.
func TestWhatTheOperatorWritesIsWhatTheKernelReads(t *testing.T) {
	want := []cost.Confirmation{
		{Start: start, End: start.Add(24 * time.Hour), USD: 12.34, AsOf: start.Add(48 * time.Hour)},
		{Start: start.Add(24 * time.Hour), End: start.Add(48 * time.Hour), USD: 11.5},
	}
	manifest, err := RenderConfigMap("farcast-system", DefaultConfirmationsName, want)
	if err != nil {
		t.Fatal(err)
	}

	// Parse the rendered YAML the way the API server would, then feed the
	// resulting object to the reader.
	var cm struct {
		Metadata struct {
			Name, Namespace string
		}
		Data map[string]string
	}
	if err := yaml.Unmarshal(manifest, &cm); err != nil {
		t.Fatalf("the rendered ConfigMap is not valid YAML: %v\n%s", err, manifest)
	}
	if cm.Metadata.Name != DefaultConfirmationsName || cm.Metadata.Namespace != "farcast-system" {
		t.Fatalf("rendered %s/%s", cm.Metadata.Namespace, cm.Metadata.Name)
	}

	src := &ConfigMapConfirmations{Client: &fakeConfigMaps{cm: &kube.ConfigMap{Data: cm.Data}}}
	got, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("the kernel cannot read what the operator wrote: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("read %d confirmations, wrote %d", len(got), len(want))
	}
	for i := range want {
		if !got[i].Start.Equal(want[i].Start) || !got[i].End.Equal(want[i].End) || got[i].USD != want[i].USD {
			t.Errorf("confirmation %d round-tripped as %+v, wrote %+v", i, got[i], want[i])
		}
	}
}

func TestRenderedConfirmationsUseTheDefaultLocation(t *testing.T) {
	manifest, err := RenderConfigMap("", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(manifest)
	if !strings.Contains(s, "name: "+DefaultConfirmationsName) ||
		!strings.Contains(s, "namespace: "+DefaultCheckpointNamespace) {
		t.Errorf("blank names did not default:\n%s", s)
	}
}
