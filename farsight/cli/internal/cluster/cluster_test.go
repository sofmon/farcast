package cluster

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"testing"
	"time"
)

type fakeRunner struct {
	calls  [][]string
	stdins [][]byte
	out    map[string][]byte // keyed by args[0]
	err    error
}

func (f *fakeRunner) Run(_ context.Context, stdin []byte, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	f.stdins = append(f.stdins, stdin)
	if f.err != nil {
		return nil, f.err
	}
	if f.out != nil {
		return f.out[args[0]], nil
	}
	return nil, nil
}

func TestApplyPipesManifestToStdin(t *testing.T) {
	fr := &fakeRunner{}
	c := NewWithRunner(fr)
	if err := c.Apply(context.Background(), []byte("MANIFEST")); err != nil {
		t.Fatal(err)
	}
	if len(fr.calls) != 1 || !slices.Equal(fr.calls[0], []string{"apply", "-f", "-"}) {
		t.Fatalf("calls=%v, want one [apply -f -]", fr.calls)
	}
	if string(fr.stdins[0]) != "MANIFEST" {
		t.Fatalf("stdin=%q, want MANIFEST", fr.stdins[0])
	}
}

func TestRolloutStatusArgs(t *testing.T) {
	fr := &fakeRunner{}
	c := NewWithRunner(fr)
	if err := c.RolloutStatus(context.Background(), "farcast-system", "fatline", 90*time.Second); err != nil {
		t.Fatal(err)
	}
	want := []string{"rollout", "status", "deployment/fatline", "-n", "farcast-system", "--timeout", "90s"}
	if len(fr.calls) != 1 || !slices.Equal(fr.calls[0], want) {
		t.Fatalf("calls=%v, want %v", fr.calls, want)
	}
}

func TestWaitExternalIPReturnsIP(t *testing.T) {
	fr := &fakeRunner{out: map[string][]byte{"get": []byte("34.0.0.5\n")}}
	c := NewWithRunner(fr)
	ip, err := c.WaitExternalIP(context.Background(), "farcast-system", "fatline", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "34.0.0.5" {
		t.Fatalf("ip=%q, want 34.0.0.5 (trimmed)", ip)
	}
}

func TestWaitExternalIPTimesOut(t *testing.T) {
	fr := &fakeRunner{out: map[string][]byte{"get": []byte("")}} // never assigned
	c := NewWithRunner(fr)
	// Zero timeout: the first empty read is already past the deadline.
	if _, err := c.WaitExternalIP(context.Background(), "farcast-system", "fatline", 0); err == nil {
		t.Fatal("expected a timeout error when no external IP is assigned")
	}
}

func TestRunnerErrorPropagates(t *testing.T) {
	fr := &fakeRunner{err: errors.New("boom")}
	c := NewWithRunner(fr)
	if err := c.Apply(context.Background(), []byte("x")); err == nil {
		t.Fatal("expected the runner error to propagate")
	}
}

// A manifest read's whole output is the document, so asking for "the logs"
// must mean all of them. kubectl's own default is a tail, which is why this is
// a behaviour rather than an omission.
func TestJobLogsAsksForEverythingUnlessGivenALimit(t *testing.T) {
	for name, tc := range map[string]struct {
		lines int
		want  string
	}{
		"no limit":       {0, "--tail=-1"},
		"negative limit": {-1, "--tail=-1"},
		"a limit":        {40, "--tail=40"},
		"one line":       {1, "--tail=1"},
	} {
		t.Run(name, func(t *testing.T) {
			fr := &fakeRunner{}
			c := NewWithRunner(fr)
			if _, err := c.JobLogs(context.Background(), "ns", "job", tc.lines); err != nil {
				t.Fatal(err)
			}
			if len(fr.calls) != 1 {
				t.Fatalf("calls=%v, want one", fr.calls)
			}
			if !slices.Contains(fr.calls[0], tc.want) {
				t.Errorf("calls[0]=%v, want it to contain %q", fr.calls[0], tc.want)
			}
		})
	}
}

// A Deployment with no explicit replicas runs one. Decoding that as zero would
// show every healthy application as stopped — and stopped is exactly what a
// protective cost shutdown leaves behind, so the two must not be confused.
func TestWorkloadsWithoutExplicitReplicasRunOne(t *testing.T) {
	const body = `{"items":[
	  {"metadata":{"name":"api","namespace":"apps","creationTimestamp":"2026-09-01T10:00:00Z",
	    "labels":{"farcast.sofmon.com/tier":"app"}},
	   "spec":{"template":{"spec":{"containers":[{"image":"reg.example/api@sha256:abc"}]}}},
	   "status":{"readyReplicas":1}},
	  {"metadata":{"name":"web","namespace":"apps"},
	   "spec":{"replicas":0,"template":{"spec":{"containers":[{"image":"reg.example/web@sha256:def"}]}}},
	   "status":{}}
	]}`
	fr := &fakeRunner{out: map[string][]byte{"get": []byte(body)}}
	got, err := NewWithRunner(fr).Workloads(context.Background(), "apps")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d deployments, want 2", len(got))
	}
	if got[0].Desired != 1 || got[0].Ready != 1 {
		t.Errorf("api = %d/%d, want 1/1 — an absent replicas field means one", got[0].Ready, got[0].Desired)
	}
	if got[1].Desired != 0 {
		t.Errorf("web desired = %d, want 0 — an explicit zero is a stopped application", got[1].Desired)
	}
	if got[0].Labels["farcast.sofmon.com/tier"] != "app" {
		t.Errorf("labels were dropped: %v", got[0].Labels)
	}
	if len(got[0].Images) != 1 || got[0].Images[0] != "reg.example/api@sha256:abc" {
		t.Errorf("images = %v", got[0].Images)
	}
	if got[0].CreatedAt.IsZero() {
		t.Error("the creation timestamp was dropped, so ps can show no age")
	}
}

// An empty answer is a namespace with no deployments, not a parse failure.
func TestWorkloadsHandlesAnEmptyAnswer(t *testing.T) {
	fr := &fakeRunner{}
	got, err := NewWithRunner(fr).Workloads(context.Background(), "apps")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want nothing", got)
	}
}

// The keys FarCast stores contain dots, and jsonpath reads a dot as a path
// separator — which is why this reads JSON. A jsonpath asking for
// {.data.checkpoint.json} returns empty rather than failing, and empty reads
// as "the kernel has never checkpointed".
func TestConfigMapValueReadsADottedKey(t *testing.T) {
	const body = `{"data":{"checkpoint.json":"{\"version\":1}"}}`
	fr := &fakeRunner{out: map[string][]byte{"get": []byte(body)}}
	got, found, err := NewWithRunner(fr).ConfigMapValue(context.Background(), "farcast-system", "technocore-ledger", "checkpoint.json")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("found = false for a ConfigMap that exists")
	}
	if got != `{"version":1}` {
		t.Errorf("got %q", got)
	}
}

func TestConfigMapValueDistinguishesMissingFromEmpty(t *testing.T) {
	fr := &fakeRunner{}
	_, found, err := NewWithRunner(fr).ConfigMapValue(context.Background(), "ns", "name", "key")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Error("found = true for a ConfigMap kubectl returned nothing for")
	}

	fr = &fakeRunner{out: map[string][]byte{"get": []byte(`{"data":{"other":"x"}}`)}}
	_, found, err = NewWithRunner(fr).ConfigMapValue(context.Background(), "ns", "name", "key")
	if !found {
		t.Error("found = false for a ConfigMap that exists but lacks the key")
	}
	if err == nil {
		t.Error("a present ConfigMap missing its key was not reported")
	}
}

// streamingRunner is a fakeRunner that can also follow, so the streaming path
// is exercised rather than only the buffered one.
type streamingRunner struct {
	fakeRunner
	streamed []string
	body     string
}

func (s *streamingRunner) Stream(_ context.Context, out io.Writer, args ...string) error {
	s.streamed = args
	_, err := io.WriteString(out, s.body)
	return err
}

func TestLogsBuildsTheRightCall(t *testing.T) {
	for name, tc := range map[string]struct {
		follow, previous bool
		lines            int
		want, absent     []string
	}{
		"a plain read": {
			lines:  200,
			want:   []string{"logs", "-n", "apps", "deployment/api", "--tail=200", "--all-containers=true"},
			absent: []string{"--follow", "--previous"},
		},
		"after a crash": {
			lines: 50, previous: true,
			want:   []string{"--tail=50", "--previous"},
			absent: []string{"--follow"},
		},
		"following": {
			lines: 10, follow: true,
			want:   []string{"--follow", "--tail=10"},
			absent: []string{"--previous"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			sr := &streamingRunner{body: "log line\n"}
			sr.out = map[string][]byte{"logs": []byte("log line\n")}
			var buf bytes.Buffer
			if err := NewWithRunner(sr).Logs(context.Background(), &buf, "apps", "deployment/api", tc.lines, tc.follow, tc.previous); err != nil {
				t.Fatal(err)
			}
			got := sr.streamed
			if !tc.follow {
				if len(sr.calls) != 1 {
					t.Fatalf("calls=%v, want one", sr.calls)
				}
				got = sr.calls[0]
				if sr.streamed != nil {
					t.Error("a plain read went through the streaming path")
				}
			} else if got == nil {
				t.Fatal("--follow did not go through the streaming path")
			}
			for _, want := range tc.want {
				if !slices.Contains(got, want) {
					t.Errorf("args=%v, want it to contain %q", got, want)
				}
			}
			for _, absent := range tc.absent {
				if slices.Contains(got, absent) {
					t.Errorf("args=%v, want it NOT to contain %q", got, absent)
				}
			}
			if buf.String() != "log line\n" {
				t.Errorf("output = %q, want the log unchanged", buf.String())
			}
		})
	}
}

// A Runner that cannot stream must say so rather than silently reading a
// snapshot: an operator who asked to follow would sit watching output that has
// already stopped arriving.
func TestFollowingNeedsAStreamer(t *testing.T) {
	var buf bytes.Buffer
	err := NewWithRunner(&fakeRunner{}).Logs(context.Background(), &buf, "apps", "deployment/api", 10, true, false)
	if err == nil {
		t.Fatal("following succeeded on a Runner that cannot stream")
	}
}

// FarCast runs Deployments and StatefulSets — the key holder is the latter —
// so a listing must ask for both, and must carry back which is which. The
// Phase 4.3 walk found `farcast ps --all` silently omitting storage.
func TestWorkloadsAsksForBothKindsAndKeepsThem(t *testing.T) {
	const body = `{"items":[
	  {"kind":"Deployment","metadata":{"name":"fatline","namespace":"farcast-system"},
	   "spec":{"replicas":2,"template":{"spec":{"containers":[{"image":"reg/fatline@sha256:a"}]}}},
	   "status":{"readyReplicas":2}},
	  {"kind":"StatefulSet","metadata":{"name":"datasphered","namespace":"farcast-system"},
	   "spec":{"replicas":2,"template":{"spec":{"containers":[{"image":"reg/ds@sha256:b"}]}}},
	   "status":{"readyReplicas":2}}
	]}`
	fr := &fakeRunner{out: map[string][]byte{"get": []byte(body)}}
	got, err := NewWithRunner(fr).Workloads(context.Background(), "farcast-system")
	if err != nil {
		t.Fatal(err)
	}

	// The request itself: asking only for deployments is how storage vanished.
	if len(fr.calls) != 1 {
		t.Fatalf("calls=%v, want one", fr.calls)
	}
	if !slices.Contains(fr.calls[0], "deployments,statefulsets") {
		t.Errorf("args=%v, want them to ask for both kinds", fr.calls[0])
	}

	kinds := map[string]string{}
	for _, w := range got {
		kinds[w.Name] = w.Kind
	}
	if kinds["datasphered"] != "StatefulSet" {
		t.Errorf("datasphered came back as %q; reading its logs would target the wrong kind", kinds["datasphered"])
	}
	if kinds["fatline"] != "Deployment" {
		t.Errorf("fatline came back as %q", kinds["fatline"])
	}
}
