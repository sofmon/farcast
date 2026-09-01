package cli

import (
	"context"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kernel"
)

func kernelInstance(t *testing.T, dir config.Dir, name string) *config.InstanceMetadata {
	t.Helper()
	meta := connectedInstance(t, dir, name)
	meta.Kernel = &config.Kernel{Deployed: true, Image: "img@sha256:x", Replicas: 1, Limit: 50}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
	return meta
}

func confirmCmd(fc *fakeCluster) *kernelConfirmCommand {
	c := &kernelConfirmCommand{}
	c.deployer.newCluster = func(string) clusterApplier { return fc }
	return c
}

func thisMonth(day int) string {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), day, 0, 0, 0, 0, time.UTC).Format(time.DateOnly)
}

func TestConfirmPushesTheDocumentTheKernelReads(t *testing.T) {
	dir := config.Dir(t.TempDir())
	kernelInstance(t, dir, "p41")
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}

	c := confirmCmd(fc)
	c.amount, c.amountSet = 12.34, true
	c.from, c.to = thisMonth(1), thisMonth(2)
	if err := c.Run(context.Background(), env, []string{"p41"}); err != nil {
		t.Fatal(err)
	}
	if len(fc.applied) != 1 {
		t.Fatalf("applied %d manifests, want 1", len(fc.applied))
	}
	manifest := string(fc.applied[0])
	if !strings.Contains(manifest, "name: "+kernel.DefaultConfirmationsName) {
		t.Errorf("pushed to the wrong object:\n%s", manifest)
	}
	if !strings.Contains(manifest, "12.34") {
		t.Errorf("the amount did not reach the document:\n%s", manifest)
	}

	meta, err := dir.LoadInstanceMetadata("p41")
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Kernel.Confirmations) != 1 || meta.Kernel.Confirmations[0].USD != 12.34 {
		t.Errorf("the confirmation was not recorded locally: %+v", meta.Kernel.Confirmations)
	}
}

// Running daily must append one window per day with no bookkeeping by the
// operator: each push continues where the last ended.
func TestRepeatedConfirmsAppendNonOverlappingWindows(t *testing.T) {
	dir := config.Dir(t.TempDir())
	kernelInstance(t, dir, "p41")
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}

	first := confirmCmd(fc)
	first.amountSet = true
	first.amount, first.from, first.to = 10, thisMonth(1), thisMonth(2)
	if err := first.Run(context.Background(), env, []string{"p41"}); err != nil {
		t.Fatal(err)
	}
	// No --from: continues from where the last one ended.
	second := confirmCmd(fc)
	second.amountSet = true
	second.amount, second.to = 11, thisMonth(3)
	if err := second.Run(context.Background(), env, []string{"p41"}); err != nil {
		t.Fatal(err)
	}

	meta, err := dir.LoadInstanceMetadata("p41")
	if err != nil {
		t.Fatal(err)
	}
	ks := meta.Kernel.Confirmations
	if len(ks) != 2 {
		t.Fatalf("recorded %d windows, want 2: %+v", len(ks), ks)
	}
	if !ks[0].End.Equal(ks[1].Start) {
		t.Errorf("the second window starts at %v, not where the first ended (%v)", ks[1].Start, ks[0].End)
	}
	// And every window this machine knows about is pushed, not just the newest.
	if !strings.Contains(string(fc.applied[1]), "10") || !strings.Contains(string(fc.applied[1]), "11") {
		t.Error("the second push dropped the first window")
	}
}

// The kernel's only recourse for an overlap is to skip the window silently.
// Refusing at the point of entry means the operator finds out while they still
// have the invoice open.
func TestConfirmRefusesAnOverlappingWindow(t *testing.T) {
	dir := config.Dir(t.TempDir())
	kernelInstance(t, dir, "p41")
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}

	first := confirmCmd(fc)
	first.amountSet = true
	first.amount, first.from, first.to = 10, thisMonth(1), thisMonth(5)
	if err := first.Run(context.Background(), env, []string{"p41"}); err != nil {
		t.Fatal(err)
	}
	second := confirmCmd(fc)
	second.amountSet = true
	second.amount, second.from, second.to = 5, thisMonth(3), thisMonth(7)
	err := second.Run(context.Background(), env, []string{"p41"})
	if err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("err = %v, want an overlap refusal", err)
	}
	if len(fc.applied) != 1 {
		t.Error("a refused confirmation still touched the cluster")
	}
}

// A daily push that runs twice has nothing new to confirm. Failing would make
// a cron job noisy for doing exactly the right thing.
func TestAnEmptyWindowIsNotAnError(t *testing.T) {
	dir := config.Dir(t.TempDir())
	kernelInstance(t, dir, "p41")
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}

	c := confirmCmd(fc)
	c.amountSet = true
	c.amount, c.from, c.to = 1, thisMonth(3), thisMonth(3)
	if err := c.Run(context.Background(), env, []string{"p41"}); err != nil {
		t.Fatalf("an empty window must not fail: %v", err)
	}
	if len(fc.applied) != 0 {
		t.Error("an empty window was pushed")
	}
}

// A confirmation the cluster never received would be skipped by the next push,
// and the window would go unconfirmed forever.
func TestAFailedPushRollsBackLocalState(t *testing.T) {
	dir := config.Dir(t.TempDir())
	kernelInstance(t, dir, "p41")
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{applyErr: errors.New("apiserver said no")}

	c := confirmCmd(fc)
	c.amountSet = true
	c.amount, c.from, c.to = 9, thisMonth(1), thisMonth(2)
	if err := c.Run(context.Background(), env, []string{"p41"}); err == nil {
		t.Fatal("expected the push failure to surface")
	}
	meta, err := dir.LoadInstanceMetadata("p41")
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Kernel.Confirmations) != 0 {
		t.Errorf("local state kept a confirmation the cluster never got: %+v", meta.Kernel.Confirmations)
	}
}

func TestConfirmRefusesWithoutAKernel(t *testing.T) {
	dir := config.Dir(t.TempDir())
	connectedInstance(t, dir, "p41") // no kernel deployed
	env, _ := testEnv(dir, output.ModeHuman)
	c := confirmCmd(&fakeCluster{})
	c.amount, c.amountSet = 1, true
	err := c.Run(context.Background(), env, []string{"p41"})
	if err == nil || !strings.Contains(err.Error(), "no kernel") {
		t.Fatalf("err = %v, want a refusal naming the missing kernel", err)
	}
}

func TestConfirmRequiresAnAmount(t *testing.T) {
	dir := config.Dir(t.TempDir())
	kernelInstance(t, dir, "p41")
	env, _ := testEnv(dir, output.ModeHuman)
	c := confirmCmd(&fakeCluster{}) // --amount never given
	if err := c.Run(context.Background(), env, []string{"p41"}); err == nil {
		t.Fatal("expected a usage error without --amount")
	}
}

// Zero is a real answer — an idle window genuinely cost nothing — and must not
// be mistaken for a missing flag.
func TestZeroIsAValidConfirmedAmount(t *testing.T) {
	dir := config.Dir(t.TempDir())
	kernelInstance(t, dir, "p41")
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}
	c := confirmCmd(fc)
	c.amountSet = true
	c.amount, c.from, c.to = 0, thisMonth(1), thisMonth(2)
	if err := c.Run(context.Background(), env, []string{"p41"}); err != nil {
		t.Fatalf("zero must be confirmable: %v", err)
	}
	if len(fc.applied) != 1 {
		t.Error("a zero confirmation was not pushed")
	}
}

// The kernel accounts for one period. A window outside it would be pushed and
// silently skipped, which looks exactly like a confirmation that worked.
func TestConfirmRefusesAWindowOutsideThePeriod(t *testing.T) {
	dir := config.Dir(t.TempDir())
	kernelInstance(t, dir, "p41")
	env, _ := testEnv(dir, output.ModeHuman)
	fc := &fakeCluster{}
	c := confirmCmd(fc)
	last := time.Now().UTC().AddDate(0, -1, 0)
	c.amount, c.amountSet = 5, true
	c.from = time.Date(last.Year(), last.Month(), 1, 0, 0, 0, 0, time.UTC).Format(time.DateOnly)
	c.to = time.Date(last.Year(), last.Month(), 2, 0, 0, 0, 0, time.UTC).Format(time.DateOnly)
	err := c.Run(context.Background(), env, []string{"p41"})
	if err == nil || !strings.Contains(err.Error(), "outside the current") {
		t.Fatalf("err = %v, want a refusal naming the period", err)
	}
	if len(fc.applied) != 0 {
		t.Error("a window outside the period was pushed")
	}
}

func TestConfirmRejectsUnparseableDates(t *testing.T) {
	dir := config.Dir(t.TempDir())
	kernelInstance(t, dir, "p41")
	env, _ := testEnv(dir, output.ModeHuman)
	for _, bad := range []string{"01/09/2026", "2026-9-1", "yesterday"} {
		c := confirmCmd(&fakeCluster{})
		c.amount, c.amountSet, c.from = 1, true, bad
		if err := c.Run(context.Background(), env, []string{"p41"}); err == nil {
			t.Errorf("--from %q was accepted", bad)
		}
	}
}

// mergeConfirmations drops previous periods rather than carrying them forever:
// the kernel would skip them anyway, and an unbounded document is one that
// eventually will not fit in a ConfigMap.
func TestMergeDropsAnEarlierPeriodsWindows(t *testing.T) {
	periodStart := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 1, 0)
	old := config.KernelConfirmation{
		Start: periodStart.AddDate(0, -1, 0), End: periodStart.AddDate(0, -1, 1), USD: 1,
	}
	next := config.KernelConfirmation{Start: periodStart, End: periodStart.AddDate(0, 0, 1), USD: 2}

	got, err := mergeConfirmations([]config.KernelConfirmation{old}, next, periodStart, periodEnd)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].USD != 2 {
		t.Errorf("merged = %+v, want only the current period's window", got)
	}
}

func TestToCostConfirmationsPreservesEveryField(t *testing.T) {
	at := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	got := toCostConfirmations([]config.KernelConfirmation{
		{Start: at, End: at.Add(time.Hour), USD: 3.5, AsOf: at.Add(48 * time.Hour)},
	})
	want := cost.Confirmation{Start: at, End: at.Add(time.Hour), USD: 3.5, AsOf: at.Add(48 * time.Hour)}
	if got[0] != want {
		t.Errorf("converted to %+v, want %+v", got[0], want)
	}
}

// Zero is a real answer and "unspecified" must not look like it. A sentinel
// that only exists once SetFlags has run would make a directly-constructed
// command confirm zero for a window nobody measured.
func TestUnspecifiedIsDistinctFromConfirmedZeroAtTheFlag(t *testing.T) {
	c := &kernelConfirmCommand{}
	fs := flag.NewFlagSet("confirm", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	c.SetFlags(fs)
	if c.amountSet {
		t.Fatal("amount reads as given before any flag was parsed")
	}
	if err := fs.Parse([]string{"--amount", "0"}); err != nil {
		t.Fatal(err)
	}
	if !c.amountSet || c.amount != 0 {
		t.Errorf("--amount 0 parsed as set=%v value=%v, want set=true value=0", c.amountSet, c.amount)
	}
	if err := fs.Parse([]string{"--amount", "banana"}); err == nil {
		t.Error("a non-numeric amount was accepted")
	}
}

func TestConfirmRejectsANegativeAmount(t *testing.T) {
	dir := config.Dir(t.TempDir())
	kernelInstance(t, dir, "p41")
	env, _ := testEnv(dir, output.ModeHuman)
	c := confirmCmd(&fakeCluster{})
	c.amount, c.amountSet = -1, true
	if err := c.Run(context.Background(), env, []string{"p41"}); err == nil {
		t.Fatal("a negative confirmed amount must be refused")
	}
}
