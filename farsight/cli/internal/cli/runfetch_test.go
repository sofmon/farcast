package cli

import (
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/farsight/cli/internal/plan"
	pfetch "github.com/sofmon/farcast/planck/fetch"
)

// ADR 0023 M2.6d (A23-47): the manifest read is two steps. applyFetch renders
// the fetch Job, applies it and waits for nothing. readFetch reads a Job it
// did not apply, as 'run --confirm' reads as the reader the one the writer
// applied, and returns the manifest with the Job it read: its name, and the
// uid the wait ended on.
func TestTheManifestReadIsAppliedAndReadApart(t *testing.T) {
	cfg := pfetch.Config{
		Instance: "p43", Fetcher: fetcherDigest, Repo: "https://github.com/example/my-platform",
		EgressHosts: []string{"github.com"},
	}
	env, _, errb := testEnvBoth(config.Dir(t.TempDir()), output.ModeHuman)
	env.Verbose = true

	writer := newFakeRun(twoAppManifest)
	if err := applyFetch(t.Context(), env, writer, cfg); err != nil {
		t.Fatal(err)
	}
	want, err := pfetch.Render(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(writer.applied) != 1 || writer.applied[0] != string(want) {
		t.Fatalf("applyFetch applied %d streams; want exactly the rendered fetch Job:\n%s", len(writer.applied), strings.Join(writer.applied, "\n=====\n"))
	}
	if len(writer.waited) != 0 || len(writer.tails) != 0 {
		t.Errorf("applyFetch waited on %v and read logs %v; it only applies", writer.waited, writer.tails)
	}
	if line := "Reading " + cfg.Repo + " inside \"p43\""; !strings.Contains(errb.String(), line) {
		t.Errorf("applyFetch did not say %q:\n%s", line, errb)
	}

	// The reader is a cluster that applied nothing: the Job is there
	// because the writer applied it.
	errb.Reset()
	reader := newFakeRun(twoAppManifest)
	reader.jobs = map[string]bool{cfg.Job(): true}
	reader.jobUIDs = map[string]string{cfg.Job(): "uid-of-the-fetch"}
	got, err := readFetch(t.Context(), env, reader, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(reader.applied) != 0 {
		t.Errorf("readFetch applied %d streams; it only reads", len(reader.applied))
	}
	if got.Job != cfg.Job() || got.UID != "uid-of-the-fetch" || string(got.Manifest) != twoAppManifest || got.Report.Commit != testCommit {
		t.Errorf("readFetch = job %q, uid %q, commit %q, manifest %q; want %q, uid-of-the-fetch, %s and the manifest the Job printed",
			got.Job, got.UID, got.Report.Commit, got.Manifest, cfg.Job(), testCommit)
	}
	if len(reader.waited) != 1 || reader.waited[0] != cfg.Job() || len(reader.tails) != 1 || reader.tails[0] != 0 {
		t.Errorf("readFetch waited on %v and read tails %v; want one wait on %s and the whole log", reader.waited, reader.tails, cfg.Job())
	}
	if errb.Len() != 0 {
		t.Errorf("readFetch printed on a read that succeeded:\n%s", errb)
	}
}

// A fetch fact binds --ref and --manifest as given, "" when they were not
// (A28-8), and its rendering says what the fetch reads in their place: the
// defaults planck/fetch applies, which fetchDefaultRef and DefaultManifest
// name, so the human plan never reads "the manifest  from <repo> at ,".
func TestTheFetchDefaultsAreTheFetchsOwn(t *testing.T) {
	const repo = "https://github.com/example/my-platform"
	if got, want := (pfetch.Config{Repo: repo}).Job(), pfetch.JobName(repo, fetchDefaultRef, pfetch.DefaultManifest); got != want {
		t.Fatalf("the fetch defaults to the Job %s; fetchDefaultRef and DefaultManifest name %s", got, want)
	}
	fact := plan.FetchFact{Type: plan.TypeFetch, Repository: repo, Job: "fetch-x", Fetcher: fetcherDigest}
	text := renderPlan(t, sampleBound(fact))
	want := "fetch: the manifest farcast (the default) from " + repo + " at refs/heads/main (the default), read by the Job fetch-x with "
	if !strings.Contains(text, want) {
		t.Errorf("a fetch fact with neither flag given renders as\n%s\nwant it to hold %q", text, want)
	}
}
