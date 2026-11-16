package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
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
	c.deployer.newCluster = func(clusterRef) (clusterApplier, error) { return fc, nil }
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

// confirmAt is kernel confirm with flags, its writer fc, and its clock fixed
// at now.
func confirmAt(t *testing.T, fc *fakeCluster, now time.Time, flags ...string) *kernelConfirmCommand {
	t.Helper()
	c := withFlags(t, confirmCmd(fc), flags...)
	c.deployer.now = func() time.Time { return now }
	return c
}

// ADR 0023 M2.6 (A23-40, mutation 90a): a kernel confirm plan does not
// outlive its UTC day: the window's default end and the confirmation's date
// are that day. Confirmed the next day, it has changed; confirmed across the
// end of a month, the recomputed window is empty, and still it has changed,
// refused before the empty window says anything. Confirmed later the same
// day, it is the same plan.
func TestKernelConfirmPlanChangesAcrossUTCMidnight(t *testing.T) {
	for _, row := range []struct {
		name          string
		plan, confirm time.Time
		changed       bool
	}{
		{"later the same day", time.Date(2026, 11, 16, 0, 0, 1, 0, time.UTC), time.Date(2026, 11, 16, 23, 59, 59, 0, time.UTC), false},
		{"a day boundary", time.Date(2026, 11, 16, 23, 59, 59, 0, time.UTC), time.Date(2026, 11, 17, 0, 0, 1, 0, time.UTC), true},
		{"a month boundary, the window now empty", time.Date(2026, 11, 30, 23, 59, 59, 0, time.UTC), time.Date(2026, 12, 1, 0, 0, 1, 0, time.UTC), true},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			kernelInstance(t, dir, "p41")
			env, out := testEnv(dir, output.ModeJSON)
			if err := confirmAt(t, &fakeCluster{}, row.plan, "--amount", "4", "--plan").Run(t.Context(), env, []string{"p41"}); err != nil {
				t.Fatal(err)
			}
			digest := printedDocument(t, out.Bytes()).Digest
			record := filepath.Join(dir.InstancePath("p41"), "metadata.yaml")
			before, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}

			fc := &fakeCluster{}
			env, out, errb := testEnvBoth(dir, output.ModeHuman)
			err = confirmAt(t, fc, row.confirm, "--amount", "4", "--confirm", digest).Run(t.Context(), env, []string{"p41"})
			if !row.changed {
				if err != nil || len(fc.applied) != 1 {
					t.Fatalf("--confirm later the same day = %v, applying %d streams; want the plan done", err, len(fc.applied))
				}
				return
			}
			if kindOf(classified(err)) != kindPlanChanged || exitCodeOf(err) != 1 {
				t.Fatalf("--confirm across midnight = %v; want plan_changed", err)
			}
			if errb.Len() != 0 || out.Len() != 0 {
				t.Errorf("a plan that changed printed %q %q before its comparison refused it", out, errb)
			}
			after, err := os.ReadFile(record)
			if err != nil {
				t.Fatal(err)
			}
			if len(fc.applied) != 0 || !bytes.Equal(before, after) {
				t.Errorf("a plan that changed applied %d streams, or changed the record", len(fc.applied))
			}
		})
	}
}

// ADR 0023 M2.6 (A23-40, mutation 79a): a confirmation is dated the UTC day
// it is made, in the record and in the ConfigMap the kernel reads, on every
// path: interactive, and --confirm.
func TestKernelConfirmAsOfIsTheUTCDay(t *testing.T) {
	// 01:30 on the 17th east of Greenwich, 20:30 on the 16th in UTC.
	now := time.Date(2026, 11, 17, 1, 30, 45, 123, time.FixedZone("east", 5*3600))
	wantDay := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	for _, path := range []string{"interactive", "--confirm"} {
		t.Run(path, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			kernelInstance(t, dir, "p41")
			flags := []string{"--amount", "6.5", "--from", "2026-11-01", "--to", "2026-11-03"}
			if path == "--confirm" {
				env, out := testEnv(dir, output.ModeJSON)
				if err := confirmAt(t, &fakeCluster{}, now, append(flags, "--plan")...).Run(t.Context(), env, []string{"p41"}); err != nil {
					t.Fatal(err)
				}
				b := decodedBound(t, printedDocument(t, out.Bytes()))
				if c, ok := b.Facts[0].(plan.ConfirmationFact); !ok || c.AsOfDay != "2026-11-16" {
					t.Errorf("the plan's confirmation is %+v; want as_of_day 2026-11-16", b.Facts[0])
				}
				flags = append(flags, "--confirm", printedDocument(t, out.Bytes()).Digest)
			}
			fc := &fakeCluster{}
			env, _ := testEnv(dir, output.ModeHuman)
			if err := confirmAt(t, fc, now, flags...).Run(t.Context(), env, []string{"p41"}); err != nil {
				t.Fatal(err)
			}
			meta, err := dir.LoadInstanceMetadata("p41")
			if err != nil {
				t.Fatal(err)
			}
			if len(meta.Kernel.Confirmations) != 1 || !meta.Kernel.Confirmations[0].AsOf.Equal(wantDay) {
				t.Errorf("recorded %+v; want AsOf %s", meta.Kernel.Confirmations, wantDay)
			}
			if len(fc.applied) != 1 || !strings.Contains(string(fc.applied[0]), `"AsOf":"2026-11-16T00:00:00Z"`) {
				t.Errorf("the ConfigMap does not date the confirmation 2026-11-16:\n%s", bytes.Join(fc.applied, nil))
			}
		})
	}
}

// ADR 0023 M2.6 (A23-40, mutation 90b): --amount must be a number a bill can
// hold. NaN and ±Inf are a usage error, under --plan too, before anything is
// rendered, opened or recorded.
func TestKernelConfirmRefusesANonFiniteAmount(t *testing.T) {
	dir := config.Dir(t.TempDir())
	kernelInstance(t, dir, "p41")
	record := filepath.Join(dir.InstancePath("p41"), "metadata.yaml")
	before, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	for amount, shown := range map[string]string{"NaN": "NaN", "+Inf": "+Inf", "-Inf": "-Inf", "infinity": "+Inf"} {
		for _, extra := range [][]string{nil, {"--plan"}} {
			fc := &fakeCluster{}
			c := confirmAt(t, fc, time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC), append([]string{"--amount", amount}, extra...)...)
			env, out := testEnv(dir, output.ModeJSON)
			err := c.Run(t.Context(), env, []string{"p41"})
			var ue *usageError
			if want := "--amount must be a finite number, got " + shown; !errors.As(err, &ue) || err.Error() != want {
				t.Errorf("--amount %s %q = %v; want the usage error %q", amount, extra, err, want)
			}
			if len(fc.applied) != 0 || out.Len() != 0 {
				t.Errorf("--amount %s %q applied %d streams and printed %q", amount, extra, len(fc.applied), out)
			}
		}
	}
	after, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("a non-finite amount changed the record:\n%s", after)
	}
}

// S-R5-3: an amount a plan cannot state to the cent is refused. From
// maxAmount up, --amount is a usage error, under --plan too, before anything
// is rendered, opened or recorded: far above it cents() wraps, and the plan
// would state one amount and push another. A recorded window at such an
// amount is refused the same way, as the record's fault, whether the new
// window is empty or not. The largest amount below the bound is stated
// exactly.
func TestKernelConfirmRefusesAnAmountItCannotState(t *testing.T) {
	dir := config.Dir(t.TempDir())
	kernelInstance(t, dir, "p41")
	record := filepath.Join(dir.InstancePath("p41"), "metadata.yaml")
	before, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	window := []string{"--from", "2026-11-01", "--to", "2026-11-02"}
	for _, amount := range []string{"10000000000000", "1e17", "92233720368547758.07", "1e300"} {
		for _, extra := range [][]string{nil, {"--plan"}} {
			fc := &fakeCluster{}
			c := confirmAt(t, fc, planNow, append(append([]string{"--amount", amount}, window...), extra...)...)
			env, out := testEnv(dir, output.ModeJSON)
			err := c.Run(t.Context(), env, []string{"p41"})
			f, perr := strconv.ParseFloat(amount, 64)
			if perr != nil {
				t.Fatal(perr)
			}
			var ue *usageError
			if want := fmt.Sprintf(msgAmountTooLarge, f); !errors.As(err, &ue) || err.Error() != want {
				t.Errorf("--amount %s %q = %v; want the usage error %q", amount, extra, err, want)
			}
			if len(fc.applied) != 0 || out.Len() != 0 {
				t.Errorf("--amount %s %q applied %d streams and printed %q", amount, extra, len(fc.applied), out)
			}
		}
	}
	after, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("an amount a plan cannot state changed the record:\n%s", after)
	}

	env, out := testEnv(dir, output.ModeHuman)
	if err := confirmAt(t, &fakeCluster{}, planNow, append([]string{"--amount", "9999999999999.99", "--plan"}, window...)...).
		Run(t.Context(), env, []string{"p41"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--amount=9999999999999.99,", "the provider charged 9999999999999.99 for 2026-11-01..2026-11-02,"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the largest amount below the bound is not stated as %q:\n%s", want, out)
		}
	}

	for _, usd := range []float64{1e17, -1e300} {
		for _, to := range []string{"2026-11-03", "2026-11-02"} {
			dir := config.Dir(t.TempDir())
			kernelInstance(t, dir, "p41")
			if _, err := dir.UpdateInstanceMetadata("p41", func(m *config.InstanceMetadata) error {
				m.Kernel.Confirmations = []config.KernelConfirmation{{Start: day("2026-11-01"), End: day("2026-11-02"), USD: usd}}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf(msgWindowNotStated, "p41", "2026-11-01", "2026-11-02", usd)
			for _, extra := range [][]string{nil, {"--plan"}} {
				fc := &fakeCluster{}
				c := confirmAt(t, fc, planNow, append([]string{"--amount", "1", "--to", to}, extra...)...)
				env, out := testEnv(dir, output.ModeJSON)
				err := c.Run(t.Context(), env, []string{"p41"})
				if err == nil || err.Error() != want || kindOf(classified(err)) != kindInternal {
					t.Errorf("a recorded window at %v, --to %s %q = %v; want %q", usd, to, extra, err, want)
				}
				if len(fc.applied) != 0 || out.Len() != 0 {
					t.Errorf("a recorded window at %v, --to %s %q applied %d streams and printed %q", usd, to, extra, len(fc.applied), out)
				}
			}
		}
	}
}

// ADR 0023 M2.6 (A23-27, A23-28): the plan states the amount pushed. --amount
// binds the number given exactly (FormatFloat's shortest form, never two
// decimals), and the confirmation binds its cents rounded, never cut, so a
// bill's sub-cent amount and an amount that is not exact in binary both
// show as given and as pushed.
func TestKernelConfirmPlanStatesTheAmountItPushes(t *testing.T) {
	for _, row := range []struct {
		amount string
		cents  int64
		shown  string
	}{
		{"2.715", 272, "2.72"},
		{"1.15", 115, "1.15"},
		{"0.29", 29, "0.29"},
		{"9999999999999.99", 999999999999999, "9999999999999.99"},
	} {
		t.Run(row.amount, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			kernelInstance(t, dir, "p41")
			flags := []string{"--amount", row.amount, "--from", "2026-11-01", "--to", "2026-11-02", "--plan"}
			env, out := testEnv(dir, output.ModeJSON)
			if err := confirmAt(t, &fakeCluster{}, planNow, flags...).Run(t.Context(), env, []string{"p41"}); err != nil {
				t.Fatal(err)
			}
			b := decodedBound(t, printedDocument(t, out.Bytes()))
			if len(b.Options) == 0 || b.Options[0] != (plan.Option{Flag: "amount", Value: row.amount}) {
				t.Errorf("the plan binds the options %+v; want --amount as given, %s", b.Options, row.amount)
			}
			if c, ok := b.Facts[0].(plan.ConfirmationFact); !ok || c.AmountCents != row.cents {
				t.Errorf("the confirmation is %+v; want %d cents", b.Facts[0], row.cents)
			}
			env, out = testEnv(dir, output.ModeHuman)
			if err := confirmAt(t, &fakeCluster{}, planNow, flags...).Run(t.Context(), env, []string{"p41"}); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"--amount=" + row.amount + ",", "the provider charged " + row.shown + " for 2026-11-01..2026-11-02,"} {
				if !strings.Contains(out.String(), want) {
					t.Errorf("the rendering does not say %q:\n%s", want, out)
				}
			}
		})
	}
}

// ADR 0023 M2.6 (A23-8, A23-33): an empty window's plan writes nothing and
// still binds the windows the record keeps, which stay confirmed: a daily
// push run twice on one day says what is confirmed, never "none".
func TestKernelConfirmEmptyWindowBindsTheRecordedWindows(t *testing.T) {
	dir := config.Dir(t.TempDir())
	kernelInstance(t, dir, "p41")
	if _, err := dir.UpdateInstanceMetadata("p41", func(m *config.InstanceMetadata) error {
		m.Kernel.Confirmations = []config.KernelConfirmation{{Start: day("2026-11-01"), End: day("2026-11-02"), USD: 1.5}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// No --from: the window continues from the recorded one's end, and ends
	// the same day, so it is empty.
	flags := []string{"--amount", "0", "--to", "2026-11-02", "--plan"}
	env, out := testEnv(dir, output.ModeJSON)
	if err := confirmAt(t, &fakeCluster{}, planNow, flags...).Run(t.Context(), env, []string{"p41"}); err != nil {
		t.Fatal(err)
	}
	b := decodedBound(t, printedDocument(t, out.Bytes()))
	want := []plan.ConfirmationWindow{{From: "2026-11-01", To: "2026-11-02", AmountCents: 150}}
	if c, ok := b.Facts[0].(plan.ConfirmationFact); !ok || !slices.Equal(c.WindowsAfter, want) {
		t.Errorf("the empty window's confirmation is %+v; want the record's window, %+v", b.Facts[0], want)
	}
	if len(writeTargets(b)) != 0 {
		t.Errorf("the empty window's plan writes %q", writeTargets(b))
	}
	env, out = testEnv(dir, output.ModeHuman)
	if err := confirmAt(t, &fakeCluster{}, planNow, flags...).Run(t.Context(), env, []string{"p41"}); err != nil {
		t.Fatal(err)
	}
	if line := "  confirmed windows afterwards: 2026-11-01..2026-11-02 1.50\n"; !strings.Contains(out.String(), line) {
		t.Errorf("the rendering does not say %q:\n%s", line, out)
	}
}
