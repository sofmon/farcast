package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/datasphere"
	dskeyholder "github.com/sofmon/farcast/datasphere/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/manifest/parser"
	pfetch "github.com/sofmon/farcast/planck/fetch"
	"github.com/sofmon/farcast/technocore/cost"
)

// run's two stages (ADR 0023 M2.6d; design §9.4, A23-47, A23-48, A28-1,
// A28-8, A28-10): --plan prints the fetch plan; --confirm <fetch digest>
// runs the manifest read and prints the deploy plan, computed as the
// instance's reader; --confirm <deploy digest> computes it again, compares,
// and deploys exactly it, checking every write after the builds against it.
// These run on fakes: one cluster, which the writer and the reader each see,
// and the instance's in-memory pin. kubetest serves the identity, RBAC and
// cross-cutting rows, through runFixture (runfixture_test.go, A28-11).

const (
	stageName = "p43"
	stageRepo = "https://github.com/example/my-platform"
	// stageUID is farcast-system's uid in the stage rig's cluster.
	stageUID = "00000000-0000-4000-8000-0000000000c3"
	// stageJobUID is the fetch Job's uid.
	stageJobUID = "00000000-0000-4000-8000-0000000000f1"
)

var stageArgs = []string{stageName, "github.com/example/my-platform"}

// stageFetchJob is the fetch Job a run of stageRepo at its default ref
// reads.
func stageFetchJob() string { return pfetch.Config{Repo: stageRepo}.Job() }

// stageRig is run against a fake cluster that its writer and its reader each
// reach: what each identity was opened as, in order, and how many egress
// credentials were minted.
type stageRig struct {
	t      *testing.T
	dir    config.Dir
	f      *fakeRunCluster
	ps     *fakePinStore
	kh     keyholderOpener
	opened []kube.Identity
	minted int
}

// newStageRig is a runnable instance whose reader 'reader grant' verified,
// edited by edit, and a cluster that reads twoAppManifest at stageJobUID
// and holds no namespace of the manifest's yet.
func newStageRig(t *testing.T, edit func(meta *config.InstanceMetadata)) *stageRig {
	t.Helper()
	dir := config.Dir(t.TempDir())
	meta := runnableInstance(t, dir, stageName)
	meta.Project = "proj-test1"
	meta.Reader = &config.Reader{Email: readerEmail(stageName, "proj-test1"), KeyID: readerTestKeyID, GrantedAt: readerGrantedAt}
	if edit != nil {
		edit(meta)
	}
	if err := dir.SaveInstanceMetadata(stageName, meta); err != nil {
		t.Fatal(err)
	}
	if err := dir.SaveReaderKey(stageName, []byte("not read"), []byte("not read")); err != nil {
		t.Fatal(err)
	}
	f := newFakeRun(twoAppManifest)
	f.uid = stageUID
	f.jobUIDs = map[string]string{stageFetchJob(): stageJobUID}
	f.namespaces = []string{"farcast-system", "kube-system"}
	return &stageRig{t: t, dir: dir, f: f, ps: testPinStoreFor(dir, stageName)}
}

// withStorage is an instance whose keyholder is deployed: its applications
// are wired to storage.
func withStorage(meta *config.InstanceMetadata) {
	meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 1}
}

// metering is an instance whose kernel meters the manifest's namespace.
func metering(meta *config.InstanceMetadata) {
	meta.Kernel.Namespaces = append(meta.Kernel.Namespaces, "my-platform")
}

// cmd is run with its toolchain images named and flags parsed, its writer and
// its reader each the rig's cluster, opened only as that identity.
func (r *stageRig) cmd(flags ...string) *runCommand {
	c := withFlags(r.t, &runCommand{}, append([]string{"--fetcher-image", fetcherDigest, "--builder-image", builderDigest}, flags...)...)
	c.newCluster = func(ref clusterRef) (runCluster, error) {
		r.opened = append(r.opened, ref.Identity)
		if ref.Identity != kube.Writer {
			return nil, fmt.Errorf("test: run's writer was opened as %q", ref.Identity)
		}
		return runWriterWithPin{r.f, r.ps}, nil
	}
	c.newPlanReader = func(ref clusterRef) (runPlanReader, error) {
		r.opened = append(r.opened, ref.Identity)
		if ref.Identity != kube.Reader {
			return nil, fmt.Errorf("test: run's plan reader was opened as %q", ref.Identity)
		}
		return runWriterWithPin{r.f, r.ps}, nil
	}
	c.newBuilder = func(func(string)) imageBuilder { return &fakeBuilder{} }
	c.newKeyholder = noKeyholder
	if r.kh != nil {
		c.newKeyholder = r.kh
	}
	c.mintCredential = func(string, string) (string, error) {
		r.minted++
		return policy.NewCredential()
	}
	c.now = func() time.Time { return runClock }
	return c
}

// run runs the command line flags in mode, and returns what it printed.
func (r *stageRig) run(mode output.Mode, flags ...string) (stdout, stderr string, err error) {
	r.t.Helper()
	env, out, errb := testEnvBoth(r.dir, mode)
	err = r.cmd(flags...).Run(r.t.Context(), env, stageArgs)
	return out.String(), errb.String(), err
}

// fetchPlan is the document run --plan prints.
func (r *stageRig) fetchPlan(flags ...string) plan.Document {
	r.t.Helper()
	out, errb, err := r.run(output.ModeJSON, append(slices.Clone(flags), "--plan")...)
	if err != nil {
		r.t.Fatalf("run --plan = %v\n%s", err, errb)
	}
	return printedDocument(r.t, []byte(out))
}

// deployPlan is the document run --confirm <fetch digest> prints: the
// deploy plan. It runs the manifest read.
func (r *stageRig) deployPlan(flags ...string) plan.Document {
	r.t.Helper()
	fetch := r.fetchPlan(flags...)
	out, errb, err := r.run(output.ModeJSON, append(slices.Clone(flags), "--confirm", fetch.Digest)...)
	if err != nil {
		r.t.Fatalf("run --confirm <fetch digest> = %v\n%s", err, errb)
	}
	return printedDocument(r.t, []byte(out))
}

// confirm runs --confirm with the deploy plan's digest, the rig's record of
// what was applied and opened cleared first.
func (r *stageRig) confirm(d plan.Document, flags ...string) (stdout, stderr string, err error) {
	r.t.Helper()
	r.f.applied, r.opened, r.minted = nil, nil, 0
	return r.run(output.ModeJSON, append(slices.Clone(flags), "--confirm", d.Digest)...)
}

// once is a build hook that acts at the first build alone: another writer,
// once, while the builds run.
func once(act func()) func(string) {
	done := false
	return func(string) {
		if !done {
			done = true
			act()
		}
	}
}

// factsOf is b's facts of type T, in order.
func factsOf[T plan.Fact](b plan.Bound) []T {
	var out []T
	for _, f := range b.Facts {
		if v, ok := f.(T); ok {
			out = append(out, v)
		}
	}
	return out
}

// runFactOf is b's one run fact.
func runFactOf(t *testing.T, b plan.Bound) plan.RunFact {
	t.Helper()
	runs := factsOf[plan.RunFact](b)
	if len(runs) != 1 {
		t.Fatalf("the deploy plan carries %d run facts, want 1", len(runs))
	}
	return runs[0]
}

// plannedChange is --confirm's refusal of what changed after its plan: msg,
// then msgPlanAgain, kind plan_changed, exit 1.
func plannedChange(t *testing.T, err error, msg string) {
	t.Helper()
	want := msg + "; " + msgPlanAgain
	if err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged || exitCodeOf(err) != 1 {
		t.Fatalf("--confirm = %v (kind %s, exit %d);\nwant plan_changed, %q", err, kindOf(classified(err)), exitCodeOf(err), want)
	}
}

// ADR 0023 M2.6d (A23-47, A28-8): run --plan is the fetch plan. It opens
// nothing and writes nothing; it binds every behaviour flag as given, the
// manifest read, its Job's cost, the fetcher image and the read's three
// documents, and reads no cluster.
func TestRunPlanIsTheFetchStage(t *testing.T) {
	r := newStageRig(t, nil)
	reads := observeConfigReads(t)
	b := decodedBound(t, r.fetchPlan("--ref", "refs/heads/next"))
	if b.Command != "run" || b.Stage != "fetch" || b.ClusterIdentity != "none" || b.Target.SystemNamespaceUID != "" || len(b.Blocked) != 0 {
		t.Fatalf("run --plan is %q stage %q as %q, uid %q, blocked %v; want run's fetch stage, reading no cluster",
			b.Command, b.Stage, b.ClusterIdentity, b.Target.SystemNamespaceUID, b.Blocked)
	}
	want := []plan.Option{{Flag: "builder-image", Value: builderDigest}, {Flag: "fetcher-image", Value: fetcherDigest},
		{Flag: "git-secret", Value: ""}, {Flag: "manifest", Value: ""}, {Flag: "namespace", Value: ""},
		{Flag: "ref", Value: "refs/heads/next"}, {Flag: "replace-repository", Value: "false"}}
	if !slices.Equal(b.Options, want) {
		t.Errorf("options %v, want %v", b.Options, want)
	}
	var types []string
	for _, f := range b.Facts {
		types = append(types, f.FactType())
	}
	if !slices.Equal(types, []string{"fetch", "cost", "image", "write", "write", "write"}) {
		t.Errorf("facts %q; want the fetch, its cost, the fetcher and three writes", types)
	}
	fetch := factsOf[plan.FetchFact](b)[0]
	if fetch.Repository != stageRepo || fetch.Ref != "refs/heads/next" || fetch.Fetcher != fetcherDigest ||
		fetch.Job != (pfetch.Config{Repo: stageRepo, Ref: "refs/heads/next"}).Job() {
		t.Errorf("fetch fact %+v", fetch)
	}
	if c := factsOf[plan.CostFact](b)[0]; len(c.OneOff) != 1 || c.OneOff[0].What != costWhatFetch || len(c.Standing) != 0 {
		t.Errorf("cost fact %+v; want the manifest read alone", c)
	}
	if img := factsOf[plan.ImageFact](b)[0]; img.Component != "fetcher" || img.Action != plan.ImageNamed || img.Target != fetcherDigest {
		t.Errorf("image fact %+v; want the fetcher, named", img)
	}
	if len(r.opened) != 0 || len(r.f.applied) != 0 || len(r.f.waited) != 0 {
		t.Errorf("run --plan opened %v, applied %d streams and waited on %v", r.opened, len(r.f.applied), r.f.waited)
	}
	for _, p := range reads() {
		if base := filepath.Base(p); base == "credentials.yaml" || base == "reader.key" {
			t.Errorf("run --plan read %s", p)
		}
	}
}

// ADR 0023 M2.6d (A23-47, rows 82 and 82a): the deploy plan never writes
// the fetch again. --confirm <fetch digest> applies the read once, as the
// writer, after the reader is opened, and prints a deploy plan that lists
// none of the fetch plan's writes and names the plan and Job it read.
// --confirm <deploy digest> reads that Job, never applies it again, and
// deploys; with the Job gone it refuses, plan_changed, writing nothing.
func TestRunDeployConfirmNeverWritesTheFetchAgain(t *testing.T) {
	r := newStageRig(t, nil)
	fetch := r.fetchPlan()
	fb := decodedBound(t, fetch)
	out, errb, err := r.run(output.ModeJSON, "--confirm", fetch.Digest)
	if err != nil {
		t.Fatalf("run --confirm <fetch digest> = %v\n%s", err, errb)
	}
	if !slices.Equal(r.opened, []kube.Identity{kube.Reader, kube.Writer}) {
		t.Errorf("opened %v; want the reader, then the writer for the read", r.opened)
	}
	if len(r.f.applied) != 1 || docsIn(t, r.f.applied[0])["Job/"+stageFetchJob()] == "" {
		t.Fatalf("--confirm <fetch digest> applied %d streams; want the read alone", len(r.f.applied))
	}
	d := printedDocument(t, []byte(out))
	db := decodedBound(t, d)
	if db.Stage != "deploy" || db.ClusterIdentity != "reader" || db.Target.SystemNamespaceUID != stageUID || len(db.Blocked) != 0 {
		t.Fatalf("the deploy plan is stage %q as %q, uid %q, blocked %v", db.Stage, db.ClusterIdentity, db.Target.SystemNamespaceUID, db.Blocked)
	}
	if run := runFactOf(t, db); run.FetchPlanDigest != fetch.Digest || run.JobUID != stageJobUID {
		t.Errorf("the run fact binds the plan %q and Job %q; want %q and %q", run.FetchPlanDigest, run.JobUID, fetch.Digest, stageJobUID)
	}
	fetchWrites := writeTargets(fb)
	for _, w := range writeTargets(db) {
		if slices.Contains(fetchWrites, w) {
			t.Errorf("the deploy plan writes the fetch's %s again", w)
		}
	}
	if fetches := factsOf[plan.FetchFact](db); len(fetches) != 1 || fetches[0] != factsOf[plan.FetchFact](fb)[0] {
		t.Errorf("the deploy plan's fetch facts are %+v; want the fetch plan's", fetches)
	}
	human, _, err := r.run(output.ModeHuman, "--confirm", fetch.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if want := "fetched by the plan " + fetch.Digest + " (Job uid " + stageJobUID + ")"; !strings.Contains(human, want) {
		t.Errorf("the deploy plan does not say %q:\n%s", want, human)
	}
	if strings.Contains(human, "Job farcast-system/"+stageFetchJob()) {
		t.Errorf("the deploy plan's rendering lists the fetch Job's write:\n%s", human)
	}

	stdout, errb, err := r.confirm(d)
	if err != nil {
		t.Fatalf("run --confirm <deploy digest> = %v\n%s", err, errb)
	}
	for _, s := range r.f.applied {
		if docsIn(t, s)["Job/"+stageFetchJob()] != "" {
			t.Error("--confirm <deploy digest> applied the fetch Job again")
		}
	}
	if got := builds(t, r.f); len(got) != 2 || !strings.Contains(stdout, `"deployment":"my-platform"`) {
		t.Errorf("--confirm <deploy digest> built %q and printed %s; want both applications deployed", got, stdout)
	}
	if !slices.Equal(r.opened, []kube.Identity{kube.Reader, kube.Writer}) {
		t.Errorf("opened %v; want the reader, then the writer after the comparison", r.opened)
	}

	t.Run("the Job is gone", func(t *testing.T) {
		r := newStageRig(t, nil)
		d := r.deployPlan()
		r.f.gone = map[string]bool{stageFetchJob(): true}
		_, _, err := r.confirm(d)
		if len(r.f.applied) != 0 || !slices.Equal(r.opened, []kube.Identity{kube.Reader}) {
			t.Errorf("--confirm with the fetch Job gone applied %d streams, opening %v; want the reader alone, and nothing applied", len(r.f.applied), r.opened)
		}
		plannedChange(t, err, fmt.Sprintf(msgFetchJobGone, 15))
	})
}

// ADR 0023 M2.6d (A23-47, row 82b): a deploy digest confirmed with another
// fetch stage — here another ref, whose Job the instance never ran — is not
// called gone: it says the fetch stage changed, or the Job went, kind
// plan_changed, with nothing written.
func TestRunConfirmOfAChangedFetchPlanSaysSo(t *testing.T) {
	r := newStageRig(t, nil)
	d := r.deployPlan()
	_, _, err := r.confirm(d, "--ref", "refs/heads/other")
	plannedChange(t, err, "the plan's fetch stage changed, or the fetch Job its deploy plan read is gone "+
		"(a fetch Job is kept 15 minutes after it finishes)")
	if len(r.f.applied) != 0 || !slices.Equal(r.opened, []kube.Identity{kube.Reader}) {
		t.Errorf("applied %d streams, opening %v; want the reader alone", len(r.f.applied), r.opened)
	}
}

// A28-8 (the F-blocked path): a fetch plan that is blocked has no deploy
// plan, so a digest that is not its own is plan_changed, naming the fetch
// plan's, before any reader is checked or anything is opened; its own is
// refused with its block's kind.
func TestRunConfirmOfABlockedFetchPlanNamesItsDigest(t *testing.T) {
	r := newStageRig(t, func(meta *config.InstanceMetadata) {
		meta.Kernel, meta.Reader = nil, nil
	})
	fetch := r.fetchPlan()
	fb := decodedBound(t, fetch)
	if len(fb.Blocked) != 1 || len(fb.Facts) != 0 {
		t.Fatalf("the fetch plan of an instance with no kernel: blocked %v, facts %d", fb.Blocked, len(fb.Facts))
	}
	_, _, err := r.run(output.ModeJSON, "--confirm", sampleDigest)
	if want := planChanged(fetch.Digest, sampleDigest).Error(); err == nil || err.Error() != want || kindOf(classified(err)) != kindPlanChanged {
		t.Errorf("--confirm <another digest> of a blocked fetch plan = %v; want %q", err, want)
	}
	_, _, err = r.run(output.ModeJSON, "--confirm", fetch.Digest)
	if err == nil || err.Error() != fb.Blocked[0].Message || kindOf(classified(err)) != kindInternal {
		t.Errorf("--confirm <its digest> = %v; want its block, %q", err, fb.Blocked[0].Message)
	}
	if len(r.opened) != 0 || len(r.f.applied) != 0 {
		t.Errorf("opened %v and applied %d streams", r.opened, len(r.f.applied))
	}
}

// ADR 0023 M2.6d (A23-47, A28-9): with storage wired, a machine with no CA
// key, or an empty one, gets a deploy plan blocked with translate's words,
// kind internal; it reads ca.key by its size alone. Its --confirm refuses
// with the block, and builds nothing.
func TestRunPlanBlocksWithoutTheCAKey(t *testing.T) {
	for _, row := range []struct {
		name   string
		remove func(t *testing.T, dir config.Dir)
	}{
		{"an empty ca.key", func(t *testing.T, dir config.Dir) {
			if err := os.WriteFile(filepath.Join(dir.InstancePath(stageName), "fatline", "ca.key"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"no ca.key", func(t *testing.T, dir config.Dir) {
			if err := os.Remove(filepath.Join(dir.InstancePath(stageName), "fatline", "ca.key")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := newStageRig(t, withStorage)
			mintKeyring(t, r.dir, stageName)
			row.remove(t, r.dir)
			d := r.deployPlan()
			db := decodedBound(t, d)
			want := noCAKey(stageName).Error()
			if len(db.Blocked) != 1 || db.Blocked[0].Kind != kindInternal || db.Blocked[0].Message != want || len(db.Facts) != 0 {
				t.Fatalf("the deploy plan without a CA key: blocked %v, %d facts; want %q alone", db.Blocked, len(db.Facts), want)
			}
			_, _, err := r.confirm(d)
			if err == nil || err.Error() != want || kindOf(classified(err)) != kindInternal || exitCodeOf(err) != 1 {
				t.Errorf("its --confirm = %v; want the block", err)
			}
			if got := builds(t, r.f); len(got) != 0 || slices.Contains(r.opened, kube.Writer) {
				t.Errorf("a blocked deploy built %q, opening %v", got, r.opened)
			}
		})
	}
}

// ADR 0023 M2.6d (A23-18, A23-19): a ca.key that cannot be checked — a
// stat that fails other than for a missing file, here under a fatline
// directory this process may not search — is an error met while the plan is
// computed, never the "no CA key" block. --confirm <fetch digest> returns it,
// exit 1, and prints no plan; --confirm <deploy digest> of a plan made while
// the key could be checked returns it as it is, before the comparison, and
// not as plan_changed. Neither builds nor opens the writer to deploy.
func TestACAKeyThatCannotBeCheckedIsAnErrorNotABlock(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may search a directory at mode 000, so no stat fails here")
	}
	unsearchable := func(t *testing.T, r *stageRig) {
		t.Helper()
		fatline := filepath.Join(r.dir.InstancePath(stageName), "fatline")
		if err := os.Chmod(fatline, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(fatline, 0o700) })
		if _, err := r.dir.InstanceCAKeyExists(stageName); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("guard: InstanceCAKeyExists = %v; want the permission error", err)
		}
	}
	isTheStatError := func(t *testing.T, err error) {
		t.Helper()
		want := fmt.Sprintf("check for this machine's CA key for %q: ", stageName)
		if err == nil || !strings.HasPrefix(err.Error(), want) || !errors.Is(err, fs.ErrPermission) ||
			kindOf(classified(err)) != kindInternal || exitCodeOf(err) != 1 {
			t.Fatalf("= %v (kind %s, exit %d); want %q…, internal, exit 1", err, kindOf(classified(err)), exitCodeOf(err), want)
		}
	}

	t.Run("--confirm <fetch digest>", func(t *testing.T) {
		r := newStageRig(t, withStorage)
		mintKeyring(t, r.dir, stageName)
		fetch := r.fetchPlan()
		unsearchable(t, r)
		for _, mode := range []output.Mode{output.ModeHuman, output.ModeJSON} {
			out, _, err := r.run(mode, "--confirm", fetch.Digest)
			isTheStatError(t, err)
			if out != "" {
				t.Errorf("--confirm <fetch digest> printed a plan:\n%s", out)
			}
		}
		if got := builds(t, r.f); len(got) != 0 {
			t.Errorf("built %q", got)
		}
	})
	t.Run("--confirm <deploy digest>", func(t *testing.T) {
		r := newStageRig(t, withStorage)
		mintKeyring(t, r.dir, stageName)
		d := r.deployPlan()
		unsearchable(t, r)
		out, _, err := r.confirm(d)
		isTheStatError(t, err)
		if out != "" || len(r.f.applied) != 0 || slices.Contains(r.opened, kube.Writer) {
			t.Errorf("printed %q, applied %d documents, opened %v", out, len(r.f.applied), r.opened)
		}
	})
}

// ADR 0023 M2.6d (design §9.4's run-deploy row, A28-8): a keyring behind the
// key pin is not a block. The deploy plan writes no pin and still states
// the hand-over, beside the warning that a replica which has loaded the pin
// refuses it; --confirm then does what it stated: the pin is left as it is,
// and the replicas that serve, none of which loaded it, take the new scopes.
func TestADeployPlanBehindThePinStatesTheHandOver(t *testing.T) {
	r := newStageRig(t, withStorage)
	mintKeyring(t, r.dir, stageName)
	r.ps.set(dskeyholder.Pin{Require: []datasphere.KeyID{foreignID(t)}}.Marshal())
	d := r.deployPlan()
	db := decodedBound(t, d)
	if w := pinWriteFact(db); w != nil || len(factsOf[plan.PinFact](db)) != 0 {
		t.Errorf("a plan behind the pin writes it: %+v", w)
	}
	notices := noticesOf(db)
	warning := "warning: this keyring is behind the instance's key pin: it lacks 1 key the instance's key pin requires (" +
		foreignKeyID + "); if any keyholder replica has loaded this pin, the hand-over is refused."
	if !slices.Contains(notices, msgRunHandOver) || !slices.Contains(notices, warning) {
		t.Fatalf("a plan behind the pin carries the notices %q; want the hand-over's and %q", notices, warning)
	}
	kh := &fakeStateKeyholder{phase: "unsealed"}
	r.kh = openerFor(kh)
	version := r.ps.version
	_, errb, err := r.confirm(d)
	if err != nil {
		t.Fatalf("--confirm of a plan behind the pin = %v\n%s", err, errb)
	}
	if kh.pushes == 0 || r.ps.version != version {
		t.Errorf("--confirm pushed %d times and moved the pin from version %d to %d; want the hand-over and the pin left", kh.pushes, version, r.ps.version)
	}
	if !strings.Contains(errb, warning) {
		t.Errorf("--confirm did not warn at the hand-over:\n%s", errb)
	}
}

// ADR 0023 M2.6d (§5.4, P3): into a namespace that does not exist yet the
// deploy plan reads nothing there — no Deployment, no workload list — and
// every application is new: no reset, no other workload kept. A Deployment
// found there by --confirm's re-read is a change (A28-10).
func TestRunPlanIntoANewNamespaceReadsNothingThere(t *testing.T) {
	r := newStageRig(t, nil)
	d := r.deployPlan()
	db := decodedBound(t, d)
	if resets := factsOf[plan.ApplicationResetFact](db); len(resets) != 0 {
		t.Errorf("a plan into a new namespace resets %+v", resets)
	}
	if run := runFactOf(t, db); run.OtherDeploymentsKept == nil || len(run.OtherDeploymentsKept) != 0 || !run.MeteringAdded {
		t.Errorf("the run fact keeps %v and adds metering %v; want none kept, and the namespace metered", run.OtherDeploymentsKept, run.MeteringAdded)
	}
	if len(r.f.stateReads) != 0 || len(r.f.workloadReads) != 0 {
		t.Errorf("the plan read %v and listed %v in a namespace that does not exist", r.f.stateReads, r.f.workloadReads)
	}
	if _, errb, err := r.confirm(d); err != nil {
		t.Fatalf("its --confirm = %v\n%s", err, errb)
	}

	t.Run("a Deployment found there after the plan", func(t *testing.T) {
		r := newStageRig(t, nil)
		d := r.deployPlan()
		r.f.onBuild = func(string) {
			deployed(r.f, map[string]cluster.DeploymentState{"api": liveApp("api", 1, 100, 128)})
		}
		_, _, err := r.confirm(d)
		plannedChange(t, err, fmt.Sprintf(msgAppsChanged, "my-platform/api"))
		if got := appliedAfterTheBuilds(t, r.f); len(got) != 0 {
			t.Errorf("applied %q after the builds", got)
		}
	})
}

// ADR 0023 M2.6d (§5.4, P3, A28-8): into a namespace that exists and the
// kernel does not meter, the deploy plan is blocked, kind forbidden, with
// nothing read there: the reader is bound only where the kernel meters.
func TestRunPlanIntoAnUnmeteredNamespaceIsBlocked(t *testing.T) {
	r := newStageRig(t, nil)
	deployed(r.f, map[string]cluster.DeploymentState{"api": liveApp("api", 1, 100, 128)})
	d := r.deployPlan()
	db := decodedBound(t, d)
	want := `namespace "my-platform" exists and is not metered, so its reader cannot read it; run 'farcast kernel meter p43 my-platform' first`
	if len(db.Blocked) != 1 || db.Blocked[0].Kind != kindForbidden || db.Blocked[0].Message != want || len(db.Facts) != 0 {
		t.Fatalf("the plan into an unmetered namespace: blocked %v, %d facts; want %q, forbidden", db.Blocked, len(db.Facts), want)
	}
	if len(r.f.stateReads) != 0 || len(r.f.workloadReads) != 0 {
		t.Errorf("the plan read %v and listed %v in a namespace its reader may not read", r.f.stateReads, r.f.workloadReads)
	}
	_, _, err := r.confirm(d)
	if err == nil || err.Error() != want || kindOf(classified(err)) != kindForbidden || exitCodeOf(err) != 1 {
		t.Errorf("its --confirm = %v; want the block, forbidden", err)
	}
	if got := builds(t, r.f); len(got) != 0 {
		t.Errorf("a blocked deploy built %q", got)
	}
}

// A28-8: an interactive or --yes run reads as the writer, which may read
// every namespace, so one into an existing namespace the kernel does not
// meter still deploys, reads its applications, and meters it.
func TestAnInteractiveOrYesRunIntoAnUnmeteredNamespaceDeploys(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		t.Run(fmt.Sprintf("interactive=%v", interactive), func(t *testing.T) {
			f := newFakeRun(twoAppManifest)
			deployed(f, map[string]cluster.DeploymentState{"api": liveApp("api", 1, 100, 128)})
			c := p1Cmd(f)
			in := ""
			if interactive {
				c, in = interactively(c), "y\n"
			}
			if stderr, err := p1Run(t, c, in); err != nil {
				t.Fatalf("run into an unmetered namespace = %v\n%s", err, stderr)
			}
			if !slices.Contains(f.stateReads, "my-platform/api") {
				t.Errorf("the run did not read the application it resets: %v", f.stateReads)
			}
			if got := appliedAfterTheBuilds(t, f); len(got) == 0 {
				t.Error("the run deployed nothing")
			}
			if !strings.Contains(appliedWith(t, f, "technocore-namespaces"), "my-platform") {
				t.Error("the run did not meter the namespace")
			}
		})
	}
}

// A28-6: the deploy plan never reads a namespace list that failed as "the
// namespace is absent", which would read every application as new: it is
// the plan's read error, and no plan is printed.
func TestTheDeployPlanNeverReadsAFailedNamespaceListAsAbsent(t *testing.T) {
	r := newStageRig(t, nil)
	fetch := r.fetchPlan()
	r.f.nsErr = errors.New("the API server is unavailable")
	stdout, _, err := r.run(output.ModeJSON, "--confirm", fetch.Digest)
	want := "list the cluster's namespaces: the API server is unavailable; " + msgNothingDeployed
	if err == nil || err.Error() != want || stdout != "" {
		t.Errorf("a failed namespace list = %v, printing %q; want %q and no plan", err, stdout, want)
	}
	var reader *readerPhaseError
	if !errors.As(err, &reader) {
		t.Errorf("the plan's read error %v is not marked the reader's", err)
	}
	if len(r.f.stateReads) != 0 {
		t.Errorf("read %v after the namespace list failed", r.f.stateReads)
	}
}

// A28-8: a manifest named like a system namespace is a block in the deploy
// plan, kind internal, and stays a usage error, exit 2, for an interactive
// or --yes run (TestRunRefusesAManifestNamedLikeASystemNamespace).
func TestTheDeployPlanBlocksAManifestNamedLikeASystemNamespace(t *testing.T) {
	r := newStageRig(t, nil)
	r.f.manifest = strings.Replace(twoAppManifest, "name: my-platform", "name: farcast-system", 1)
	r.f.report = reportFor(r.f.manifest)
	db := decodedBound(t, r.deployPlan())
	if len(db.Blocked) != 1 || db.Blocked[0].Kind != kindInternal || !strings.Contains(db.Blocked[0].Message, "the manifest's name: refusing to deploy applications into \"farcast-system\"") {
		t.Errorf("blocked %v", db.Blocked)
	}
	f := newFakeRun(r.f.manifest)
	_, err := p1Run(t, p1Cmd(f), "")
	if exitCodeOf(err) != 2 {
		t.Errorf("--yes into a system namespace = %v (exit %d); want a usage error", err, exitCodeOf(err))
	}
}

// ADR 0023 M2.6d (A23-2, A23-48, rows 87 and 87a): under --confirm the
// applications are read again after the builds and before the egress
// policy. One the kernel stopped during the builds is plan_changed; and one
// stopped when the plan was made, while the spending was below the limit, is
// refused once the ledger reads the limit reached (A28-1). Either way the
// builds alone were written: no egress policy, no workload, no credential.
func TestConfirmRefusesAnAppStoppedAfterTheCompare(t *testing.T) {
	t.Run("stopped during the builds", func(t *testing.T) {
		r := newStageRig(t, metering)
		withLedger(r.f, savedCheckpoint(t, cost.LevelWarn90.String(), freshAt))
		deployed(r.f, map[string]cluster.DeploymentState{"api": liveApp("api", 1, 100, 128), "web": liveApp("web", 1, 100, 128)})
		d := r.deployPlan()
		r.f.onBuild = func(string) { r.f.deployments["my-platform/api"] = liveApp("api", 0, 100, 128) }
		_, _, err := r.confirm(d)
		plannedChange(t, err, "my-platform/api changed since the plan was made (the kernel stopped or resized it); "+
			"the builds were written, and nothing after them was")
		if got := appliedAfterTheBuilds(t, r.f); len(got) != 0 || r.minted != 0 || len(builds(t, r.f)) != 2 {
			t.Errorf("applied %q after the builds, minting %d credentials; want the builds alone", got, r.minted)
		}
	})
	t.Run("stopped at the plan, the limit reached during the builds", func(t *testing.T) {
		r := newStageRig(t, metering)
		withLedger(r.f, savedCheckpoint(t, cost.LevelWarn90.String(), freshAt))
		deployed(r.f, map[string]cluster.DeploymentState{"api": liveApp("api", 0, 100, 128), "web": liveApp("web", 1, 100, 128)})
		d := r.deployPlan()
		if resets := factsOf[plan.ApplicationResetFact](decodedBound(t, d)); len(resets) != 1 || resets[0].State != plan.ResetStopped || resets[0].LimitReached {
			t.Fatalf("resets %+v; want api stopped, below the limit", resets)
		}
		r.f.onBuild = func(string) { withLedger(r.f, savedCheckpoint(t, cost.LevelReached.String(), freshAt)) }
		_, _, err := r.confirm(d)
		plannedChange(t, err, msgLimitReachedSince)
		if got := appliedAfterTheBuilds(t, r.f); len(got) != 0 || r.minted != 0 {
			t.Errorf("applied %q after the builds, minting %d credentials", got, r.minted)
		}
	})
}

// ADR 0023 M2.6d (§9.5, A28-10, row 88): under --confirm the egress policy
// is read again, and its resourceVersion compared with the one its plan
// bound, before any credential is minted: one another run wrote meanwhile is
// plan_changed, with nothing minted and the policy not written.
//
// ADR 0023 M2.7 (A30-40 as A31-2 amends it, row 88b): the policy is then
// written at the resourceVersion just read, which its document carries. One
// another run writes between that read and the apply is the API server's
// 409, which is plan_changed too, with one attempt, at the version read, and
// no workload applied; an interactive or --yes run, which consented to no
// digest, refuses with the same words, and no kind. The API server's other
// refusals of the apply are not a changed plan. A policy deleted between the
// read and the apply is recreated from this run's merge, which the
// precondition cannot tell from one never there: the deploy goes on.
func TestConfirmRefusesAPolicyChangedAfterTheCompare(t *testing.T) {
	const policyKey = fldeploy.DefaultNamespace + "/" + fldeploy.PolicyConfigMap
	// writeOther is another run's write of the policy, at resourceVersion
	// rv: its own deployment's application alone.
	writeOther := func(t *testing.T, f *fakeRunCluster, rv string) {
		t.Helper()
		other := &policy.Document{Version: policy.Version, Apps: []policy.App{{Name: "worker", Namespace: "other", CredentialSHA256: policy.HashCredential("theirs")}}}
		body, err := other.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if f.configMaps == nil {
			f.configMaps = map[string]string{}
		}
		f.configMaps[policyKey+"/"+fldeploy.PolicyKey] = string(body)
		f.rvs = map[string]string{policyKey: rv}
	}
	// policyAt is a rig whose cluster holds another run's policy at
	// resourceVersion 5, and the deploy plan it reads at that version.
	policyAt := func(t *testing.T) (*stageRig, plan.Document) {
		t.Helper()
		r := newStageRig(t, nil)
		writeOther(t, r.f, "5")
		d := r.deployPlan()
		if w := policyWriteOf(t, decodedBound(t, d)); w.ResourceVersion != "5" {
			t.Fatalf("the policy's write binds resourceVersion %q; want the 5 it was read at", w.ResourceVersion)
		}
		return r, d
	}
	// nothingAfterTheBuilds checks that a refused policy left the builds
	// alone written, its apply tried once, at version 5.
	nothingAfterTheBuilds := func(t *testing.T, f *fakeRunCluster) {
		t.Helper()
		if got := appliedAfterTheBuilds(t, f); len(got) != 0 || len(builds(t, f)) != 2 {
			t.Errorf("applied %q after the builds %q; want the builds alone", got, builds(t, f))
		}
		if !slices.Equal(f.appliedAt, []string{"5"}) {
			t.Errorf("the policy's applies were at %q; want one, at the 5 it was read at", f.appliedAt)
		}
	}

	t.Run("during the builds", func(t *testing.T) {
		r := newStageRig(t, nil)
		d := r.deployPlan()
		if w := policyWriteOf(t, decodedBound(t, d)); w.ResourceVersion != "" {
			t.Fatalf("the policy's write binds resourceVersion %q; want the absent policy's", w.ResourceVersion)
		}
		r.f.onBuild = func(string) { writeOther(t, r.f, "7") }
		_, _, err := r.confirm(d)
		plannedChange(t, err, "the instance's egress policy changed since the plan was made; the builds were written, and nothing after them was")
		if got := appliedAfterTheBuilds(t, r.f); len(got) != 0 || r.minted != 0 || len(r.f.appliedAt) != 0 {
			t.Errorf("applied %q, minting %d credentials, after the policy changed; its applies were at %q", got, r.minted, r.f.appliedAt)
		}
	})
	t.Run("between the re-read and the apply", func(t *testing.T) {
		r, d := policyAt(t)
		r.f.onApplyAt = func() { r.f.rvs[policyKey] = "6" }
		_, _, err := r.confirm(d)
		plannedChange(t, err, "the instance's egress policy changed since the plan was made; the builds were written, and nothing after them was")
		nothingAfterTheBuilds(t, r.f)
	})
	for _, mode := range []struct {
		name string
		cmd  func(*runCommand) *runCommand
		in   string
	}{
		{"--yes, between the re-read and the apply", func(c *runCommand) *runCommand { return c }, ""},
		{"interactively, between the re-read and the apply", interactively, "y\n"},
	} {
		t.Run(mode.name, func(t *testing.T) {
			f := newFakeRun(twoAppManifest)
			writeOther(t, f, "5")
			f.onApplyAt = func() { f.rvs[policyKey] = "6" }
			stderr, err := p1Run(t, mode.cmd(p1Cmd(f)), mode.in)
			if err == nil || err.Error() != msgPolicyChangedSince || kindOf(classified(err)) != kindInternal || exitCodeOf(err) != 1 {
				t.Fatalf("%s = %v (kind %s, exit %d)\n%s\nwant %q, kind internal", mode.name, err, kindOf(classified(err)), exitCodeOf(err), stderr, msgPolicyChangedSince)
			}
			nothingAfterTheBuilds(t, f)
		})
	}
	t.Run("another refusal of the apply", func(t *testing.T) {
		r, d := policyAt(t)
		r.f.applyErrOn = "name: " + fldeploy.PolicyConfigMap
		_, _, err := r.confirm(d)
		if want := "write the egress policy: the API server said no"; err == nil || err.Error() != want || kindOf(classified(err)) == kindPlanChanged {
			t.Fatalf("--confirm = %v (kind %s); want %q, no plan change", err, kindOf(classified(err)), want)
		}
		if got := appliedAfterTheBuilds(t, r.f); !slices.Equal(got, []string{"ConfigMap/" + fldeploy.PolicyConfigMap}) {
			t.Errorf("applied %q after the builds; want the refused policy alone", got)
		}
	})
	t.Run("deleted between the re-read and the apply", func(t *testing.T) {
		r, d := policyAt(t)
		r.f.onApplyAt = func() { r.f.configMaps, r.f.rvs = nil, nil }
		if _, errb, err := r.confirm(d); err != nil {
			t.Fatalf("--confirm over a policy deleted after its re-read = %v\n%s", err, errb)
		}
		policyApplied := appliedWith(t, r.f, "name: "+fldeploy.PolicyConfigMap)
		if !strings.Contains(policyApplied, `resourceVersion: "5"`) || !strings.Contains(policyApplied, `"name": "worker"`) {
			t.Errorf("the policy recreated is not this run's merge at the version it read:\n%s", policyApplied)
		}
		if got := appliedAfterTheBuilds(t, r.f); !slices.ContainsFunc(got, func(k string) bool { return strings.HasPrefix(k, "Deployment/") }) {
			t.Errorf("applied %q after the builds; want the workloads too", got)
		}
	})
}

// policyWriteOf is b's write of the egress policy.
func policyWriteOf(t *testing.T, b plan.Bound) plan.WriteFact {
	t.Helper()
	for _, w := range factsOf[plan.WriteFact](b) {
		if w.Kind == "ConfigMap" && w.Name == fldeploy.PolicyConfigMap {
			return w
		}
	}
	t.Fatal("the plan writes no egress policy")
	return plan.WriteFact{}
}

// ADR 0023 M2.6d (A23-48, A28-10, row 88a): under --confirm the key pin's
// resourceVersion is read again with the applications and the ledger, after
// the builds and before the egress policy: a pin another writer wrote
// meanwhile is plan_changed, with no scope minted and the policy not written.
func TestConfirmRefusesAPinChangedAfterTheCompare(t *testing.T) {
	r := newStageRig(t, withStorage)
	mintKeyring(t, r.dir, stageName)
	d := r.deployPlan()
	db := decodedBound(t, d)
	if w := pinWriteFact(db); w == nil || w.Method != plan.WriteCreate {
		t.Fatalf("the plan writes the pin %+v; want it created", w)
	}
	other := dskeyholder.Pin{Retired: []datasphere.KeyID{foreignID(t)}}.Marshal()
	r.f.onBuild = once(func() { r.ps.set(other) })
	_, _, err := r.confirm(d)
	plannedChange(t, err, "the instance's key pin changed since the plan was made; the builds were written, and nothing after them was")
	if got := appliedAfterTheBuilds(t, r.f); len(got) != 0 || r.minted != 0 {
		t.Errorf("applied %q, minting %d credentials, after the pin changed", got, r.minted)
	}
	if k := liveKeyring(t, r.dir, stageName); len(k.Scopes()) != 0 {
		t.Errorf("minted %d scopes after the pin changed", len(k.Scopes()))
	}
	if r.ps.value != other || r.ps.version != 1 {
		t.Errorf("the pin is %s at version %d; want the other writer's", r.ps.value, r.ps.version)
	}
}

// A28-10 (the scope-set check): under --confirm the scopes the deploy would
// mint must be the ones its plan listed. One another command minted
// meanwhile is plan_changed, before keys.yaml is saved: nothing is minted,
// and the error says what was written.
func TestConfirmRefusesAScopeSetChangedAfterThePlan(t *testing.T) {
	r := newStageRig(t, withStorage)
	mintKeyring(t, r.dir, stageName)
	d := r.deployPlan()
	r.f.onBuild = once(func() {
		s, err := datasphere.NewAppScope("my-platform", "web")
		if err != nil {
			t.Fatal(err)
		}
		k, err := liveKeyring(t, r.dir, stageName).AddScope(s)
		if err != nil {
			t.Fatal(err)
		}
		saveKeyring(t, r.dir, stageName, k)
	})
	_, _, err := r.confirm(d)
	plannedChange(t, err, fmt.Sprintf(msgScopesChangedSince, "my-platform/api", "my-platform/api, my-platform/web"))
	if k := liveKeyring(t, r.dir, stageName); len(k.Scopes()) != 1 {
		t.Errorf("keys.yaml holds %d scopes; want only the other command's", len(k.Scopes()))
	}
	for kind := range appliedKinds(t, r.f) {
		if strings.HasPrefix(kind, "Deployment/") {
			t.Errorf("applied %s after the scopes changed", kind)
		}
	}
}

// ADR 0023 M2.6d (A28-1, row 89f): a deploy plan made below the limit binds
// limit_reached false; --confirm reads the ledger again after the builds,
// and one that now reads the limit reached is plan_changed, even when every
// application is new, with only the builds written.
func TestConfirmRefusesALimitReachedAfterThePlan(t *testing.T) {
	r := newStageRig(t, nil)
	withLedger(r.f, savedCheckpoint(t, cost.LevelOK.String(), freshAt))
	d := r.deployPlan()
	if run := runFactOf(t, decodedBound(t, d)); run.LimitReached || run.LimitReason != "" {
		t.Fatalf("the run fact reads the limit %v (%q); want not reached", run.LimitReached, run.LimitReason)
	}
	r.f.onBuild = func(string) { withLedger(r.f, savedCheckpoint(t, cost.LevelReached.String(), freshAt)) }
	_, _, err := r.confirm(d)
	plannedChange(t, err, "the instance's spending reached its limit, or its kernel's ledger became unreadable or stale, since the plan was made; "+
		"the builds were written, and nothing after them was")
	if got := appliedAfterTheBuilds(t, r.f); len(got) != 0 || r.minted != 0 {
		t.Errorf("applied %q, minting %d credentials, at the limit", got, r.minted)
	}
}

// ADR 0023 M2.6d (A23-48, A28-5, mutants O27, O11c and O28): under
// --confirm each application is compared with the plan's after the builds,
// its replicas and its requests, and a failed re-read counts as a change.
// One the kernel resized during the builds; one the plan found absent that
// the re-read cannot read; and one the plan could not read that is found
// stopped: each is plan_changed, with only the builds written and nothing
// minted.
func TestConfirmRefusesAnAppTheReReadCannotMatch(t *testing.T) {
	refused := func(t *testing.T, r *stageRig, d plan.Document) {
		t.Helper()
		_, _, err := r.confirm(d)
		plannedChange(t, err, fmt.Sprintf(msgAppsChanged, "my-platform/api"))
		if got := appliedAfterTheBuilds(t, r.f); len(got) != 0 || r.minted != 0 {
			t.Errorf("applied %q after the builds, minting %d credentials", got, r.minted)
		}
	}
	unreachable := map[string]error{"my-platform/api": fmt.Errorf("deployment my-platform/api: %w", kube.ErrUnreachable)}

	t.Run("resized during the builds", func(t *testing.T) {
		r := newStageRig(t, metering)
		withLedger(r.f, savedCheckpoint(t, cost.LevelWarn90.String(), freshAt))
		deployed(r.f, map[string]cluster.DeploymentState{"api": liveApp("api", 1, 100, 128), "web": liveApp("web", 1, 100, 128)})
		d := r.deployPlan()
		r.f.onBuild = func(string) {
			resized := liveApp("api", 1, 250, 512)
			resized.AdaptedAt = runClock
			r.f.deployments["my-platform/api"] = resized
		}
		refused(t, r, d)
	})
	t.Run("absent at the plan, unreadable after the builds", func(t *testing.T) {
		r := newStageRig(t, nil)
		d := r.deployPlan()
		r.f.onBuild = func(string) {
			deployed(r.f, map[string]cluster.DeploymentState{})
			r.f.deployErrs = unreachable
		}
		refused(t, r, d)
	})
	t.Run("unreadable at the plan, stopped after the builds", func(t *testing.T) {
		r := newStageRig(t, metering)
		withLedger(r.f, savedCheckpoint(t, cost.LevelWarn90.String(), freshAt))
		deployed(r.f, map[string]cluster.DeploymentState{"api": liveApp("api", 1, 100, 128), "web": liveApp("web", 1, 100, 128)})
		r.f.deployErrs = unreachable
		d := r.deployPlan()
		if resets := factsOf[plan.ApplicationResetFact](decodedBound(t, d)); len(resets) != 1 || resets[0].State != plan.ResetUnknown {
			t.Fatalf("resets %+v; want api unknown", resets)
		}
		r.f.onBuild = func(string) {
			r.f.deployErrs = nil
			r.f.deployments["my-platform/api"] = liveApp("api", 0, 100, 128)
		}
		refused(t, r, d)
	})
}

// A28-10 (the scope-set check, mutant O17): under --confirm the scopes the
// deploy mints must be the plan's own, not only as many. keys.yaml rewritten
// during the builds so that another application's scope is the one missing
// is plan_changed, nothing minted.
func TestConfirmRefusesAnotherScopeSetOfTheSameSize(t *testing.T) {
	r := newStageRig(t, withStorage)
	base := mintKeyring(t, r.dir, stageName)
	api, err := datasphere.NewAppScope("my-platform", "api")
	if err != nil {
		t.Fatal(err)
	}
	withAPI, err := base.AddScope(api)
	if err != nil {
		t.Fatal(err)
	}
	saveKeyring(t, r.dir, stageName, withAPI)
	d := r.deployPlan()
	r.f.onBuild = once(func() {
		web, err := datasphere.NewAppScope("my-platform", "web")
		if err != nil {
			t.Fatal(err)
		}
		k, err := base.AddScope(web)
		if err != nil {
			t.Fatal(err)
		}
		saveKeyring(t, r.dir, stageName, k)
	})
	_, _, err = r.confirm(d)
	plannedChange(t, err, fmt.Sprintf(msgScopesChangedSince, "my-platform/api", "my-platform/web"))
	if k := liveKeyring(t, r.dir, stageName); len(k.Scopes()) != 1 {
		t.Errorf("keys.yaml holds %d scopes; want only the other command's", len(k.Scopes()))
	}
}

// ADR 0023 M2.6d (A28-1, mutant O12): a deploy plan made at the limit is the
// consent, and --confirm deploys it when the ledger reads below the limit
// after the builds too: only a limit newly reached is a change.
func TestConfirmAtTheLimitDeploysWhenTheLimitIsNoLongerReached(t *testing.T) {
	r := newStageRig(t, metering)
	withLedger(r.f, savedCheckpoint(t, cost.LevelReached.String(), freshAt))
	deployed(r.f, map[string]cluster.DeploymentState{"api": liveApp("api", 1, 100, 128), "web": liveApp("web", 1, 100, 128)})
	d := r.deployPlan()
	if run := runFactOf(t, decodedBound(t, d)); !run.LimitReached {
		t.Fatalf("the run fact reads the limit not reached")
	}
	r.f.onBuild = func(string) { withLedger(r.f, savedCheckpoint(t, cost.LevelWarn90.String(), freshAt)) }
	if _, errb, err := r.confirm(d); err != nil {
		t.Fatalf("--confirm of a plan made at the limit, below it after the builds = %v\n%s", err, errb)
	}
	if got := appliedAfterTheBuilds(t, r.f); len(got) == 0 {
		t.Error("deployed nothing")
	}
}

// ADR 0023 M2.6d (A28-1): a deploy plan made at the limit says so — on its
// run fact, on each reset, and in its rendering — and confirming it is the
// consent: --confirm deploys what it stated, restarting the application the
// cost guard stopped, where --yes would deploy nothing.
func TestConfirmAtTheLimitDeploysWhatItsPlanStated(t *testing.T) {
	r := newStageRig(t, metering)
	withLedger(r.f, savedCheckpoint(t, cost.LevelReached.String(), freshAt, guardStop("my-platform", "api")))
	deployed(r.f, map[string]cluster.DeploymentState{"api": liveApp("api", 0, 100, 128), "web": liveApp("web", 1, 100, 128)})
	d := r.deployPlan()
	db := decodedBound(t, d)
	if run := runFactOf(t, db); !run.LimitReached || run.LimitReason != limitReasonReached {
		t.Fatalf("the run fact reads the limit %v (%q); want reached", run.LimitReached, run.LimitReason)
	}
	resets := factsOf[plan.ApplicationResetFact](db)
	if len(resets) != 1 || resets[0].App != "api" || resets[0].State != plan.ResetStopped || !resets[0].StoppedByCostGuard || !resets[0].LimitReached {
		t.Fatalf("resets %+v; want api, stopped by the cost guard, at the limit", resets)
	}
	fetch := r.fetchPlan()
	human, _, err := r.run(output.ModeHuman, "--confirm", fetch.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if want := limitLine(limitReasonReached); !strings.Contains(human, want) {
		t.Errorf("the deploy plan does not say %q:\n%s", want, human)
	}
	if _, errb, err := r.confirm(d); err != nil {
		t.Fatalf("--confirm of a plan made at the limit = %v\n%s", err, errb)
	}
	if !strings.Contains(appliedWith(t, r.f, "name: api\n"), "replicas: 1") {
		t.Error("the confirmed deploy did not set api back to one replica")
	}
}

// A23-26, A28-8: the deploy plan's notices — here that the hosts it
// declares are unreachable with no FatLine — are facts in the plan
// --confirm <fetch digest> prints, and are printed by nothing else there;
// --confirm <deploy digest> prints each once, right after the comparison,
// and no review.
func TestConfirmPrintsTheDeployPlansNoticesOnce(t *testing.T) {
	r := newStageRig(t, func(meta *config.InstanceMetadata) { meta.FatLineDeployed = false })
	fetch := r.fetchPlan()
	out, errb, err := r.run(output.ModeJSON, "--confirm", fetch.Digest)
	if err != nil {
		t.Fatal(err)
	}
	notice := noWayOutWarning(stageName, mustManifest(t, twoAppManifest), false)
	if got := noticesOf(decodedBound(t, printedDocument(t, []byte(out)))); !slices.Contains(got, notice) {
		t.Errorf("the deploy plan's notices are %q; want %q among them", got, notice)
	}
	if strings.Contains(errb, "FatLine is not deployed") {
		t.Errorf("--confirm <fetch digest> printed a notice:\n%s", errb)
	}
	d := printedDocument(t, []byte(out))
	_, errb, err = r.confirm(d)
	if err != nil {
		t.Fatalf("--confirm <deploy digest> = %v\n%s", err, errb)
	}
	if n := strings.Count(errb, notice); n != 1 {
		t.Errorf("--confirm <deploy digest> printed the notice %d times:\n%s", n, errb)
	}
	if strings.Contains(errb, "This machine did not clone the repository") {
		t.Errorf("--confirm <deploy digest> printed the review:\n%s", errb)
	}
}

// mustManifest is s parsed.
func mustManifest(t *testing.T, s string) parser.Manifest {
	t.Helper()
	m, err := parseTestManifest(s)
	if err != nil {
		t.Fatal(err)
	}
	return *m
}
