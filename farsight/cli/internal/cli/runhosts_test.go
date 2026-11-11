package cli

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/manifest/parser"
	pfetch "github.com/sofmon/farcast/planck/fetch"
)

// orderedManifest declares its applications and its hosts out of alphabetical
// order, so an implementation that sorts either — or walks a map — prints them
// in an order the manifest never gave.
const orderedManifest = `name: ordered
apps:
  - name: worker
    containerfile: worker/Containerfile
    external:
      - host: zeta.example
        reason: z reason
      - host: alpha.example
        reason: a reason
  - name: api
    containerfile: api/Containerfile
`

// declarationLines is every line of out that states what an application may
// reach, in order.
func declarationLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "→") || strings.Contains(l, "reaches nothing") {
			lines = append(lines, l)
		}
	}
	return lines
}

// The walk's finding 5: an operator approving with -y was shown "1 declared host
// across 2 applications" and never the host. The result is the record of what
// was allowed, so it names every host, what it is for, and which application
// may reach it — in the manifest's order.
func TestTheResultNamesEveryDeclaredHostAndWhy(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, out, _ := testEnvBoth(dir, output.ModeHuman)

	f := newFakeRun(orderedManifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/ordered"}); err != nil {
		t.Fatal(err)
	}

	// The summary line is quoted verbatim by the phase-4-4 runbook, so it is
	// part of the golden block rather than merely "contained".
	want := "\nEgress: 2 declared hosts across 2 applications, enforced per application.\n" +
		"  worker\n" +
		"    → zeta.example                       z reason\n" +
		"    → alpha.example                      a reason\n" +
		"  api\n" +
		"    reaches nothing outside the instance\n"
	if !strings.Contains(out.String(), want) {
		t.Errorf("the result does not list the declared hosts as\n%s\ngot:\n%s", want, out.String())
	}
}

// What the result says was allowed is, line for line, what the review showed
// before it was approved. Two formats, or two sources, would be two records an
// operator has to reconcile.
func TestTheResultIsWhatTheReviewShowed(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, out, errb := testEnvBoth(dir, output.ModeHuman)

	f := newFakeRun(orderedManifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/ordered"}); err != nil {
		t.Fatal(err)
	}

	reviewed := declarationLines(errb.String())
	result := declarationLines(out.String())
	if len(reviewed) != 3 {
		t.Fatalf("the review showed %d declaration lines, want 3:\n%s", len(reviewed), errb.String())
	}
	if !reflect.DeepEqual(reviewed, result) {
		t.Errorf("the result is not what the review showed\nreview: %q\nresult: %q", reviewed, result)
	}

	// The same comparison without the command around it: the review and the
	// result rendered from one manifest and the policy written for it.
	m, err := parseTestManifest(orderedManifest)
	if err != nil {
		t.Fatal(err)
	}
	var rev, res strings.Builder
	review{Instance: "p43", Namespace: "ordered", Manifest: *m, FatLineDeployed: true,
		Limit: config.CostLimit{Amount: 500, Currency: "USD", Period: "monthly"}}.print(&rev)
	doc, _, err := egressPolicy(context.Background(), newFakeRun(orderedManifest), "ordered", *m)
	if err != nil {
		t.Fatal(err)
	}
	if err := (runResult{Apps: appResults(*m, nil, doc, "ordered"), Egress: summarise(doc, "ordered")}).Human(&res); err != nil {
		t.Fatal(err)
	}
	if a, b := declarationLines(rev.String()), declarationLines(res.String()); !reflect.DeepEqual(a, b) {
		t.Errorf("rendered directly, the result is not what the review showed\nreview: %q\nresult: %q", a, b)
	}
}

// The JSON result carries each declaration with its reason, in the shape the
// policy ConfigMap uses, taken from the policy that was written for THIS
// namespace — and an application that may reach nothing says so with [], not
// with a key that is not there.
func TestTheJSONResultIsThePolicyThatWasWritten(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, out, _ := testEnvBoth(dir, output.ModeJSON)

	// Another deployment already runs an "api" with different declarations;
	// reading its entry would report hosts this deployment never declared.
	f := newFakeRun(twoAppManifest)
	seedPolicy(t, f, "other-deployment", "api", []parser.External{{Host: "queue.example", Reason: "jobs"}})

	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}

	var typed struct {
		Apps []struct {
			Name     string            `json:"name"`
			External []parser.External `json:"external"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out.Bytes(), &typed); err != nil {
		t.Fatalf("stdout is not one JSON result: %v\n%s", err, out.String())
	}
	written := map[string][]parser.External{}
	for _, app := range policyIn(t, f).Apps {
		if app.Namespace == "my-platform" {
			written[app.Name] = app.External
		}
	}
	if len(typed.Apps) != 2 {
		t.Fatalf("the result lists %d applications, want 2: %s", len(typed.Apps), out.String())
	}
	for _, a := range typed.Apps {
		want := written[a.Name]
		if want == nil {
			want = []parser.External{}
		}
		if !reflect.DeepEqual(a.External, want) {
			t.Errorf("the result says %s may reach %+v; the policy written says %+v", a.Name, a.External, want)
		}
	}
	if got := typed.Apps[0].External; len(got) != 2 || got[0].Reason != "payment processing" {
		t.Errorf("api's declarations lost their reasons: %+v", got)
	}

	var loose struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(out.Bytes(), &loose); err != nil {
		t.Fatal(err)
	}
	for _, a := range loose.Apps {
		if a["name"] != "web" {
			continue
		}
		ext, present := a["external"]
		if !present {
			t.Fatalf("web, which may reach nothing, has no external key: %v", a)
		}
		if list, ok := ext.([]any); !ok || len(list) != 0 {
			t.Errorf("web's external is %#v, want []", ext)
		}
	}
}

// -y waives the question, not the review. The declarations — and the warnings
// an unattended run most needs on record — are still printed, to stderr.
func TestRunWithYesStillShowsTheReview(t *testing.T) {
	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, out, errb := testEnvBoth(dir, output.ModeHuman)

	f := newFakeRun(twoAppManifest)
	if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"api.stripe.com", "payment processing", "sentry.io", "error reporting",
		"reaches nothing outside the instance", "Approved with --yes",
	} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("a -y run did not show %q on stderr:\n%s", want, errb.String())
		}
	}
	if strings.Contains(out.String(), "Approved with --yes") || strings.Contains(out.String(), "read inside") {
		t.Errorf("the review reached stdout, which carries only the result:\n%s", out.String())
	}

	// The warning that the declared hosts are unreachable is the one a -y run
	// would otherwise discover only when its applications fail.
	t.Run("FatLine not deployed", func(t *testing.T) {
		dir := config.Dir(t.TempDir())
		meta := runnableInstance(t, dir, "p43")
		meta.FatLineDeployed = false
		if err := dir.SaveInstanceMetadata("p43", meta); err != nil {
			t.Fatal(err)
		}
		env, _, errb := testEnvBoth(dir, output.ModeHuman)
		if err := runCmd(newFakeRun(twoAppManifest)).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(errb.String(), "FatLine is not deployed") {
			t.Errorf("a -y run did not warn that FatLine is not deployed:\n%s", errb.String())
		}
	})
}

// hostileManifest's reason erases the line it is on, returns the cursor to the
// start of it, and forges a declaration on a line of its own; the second one
// reverses the text after it; the Containerfile path does the first again.
// The parser accepts all of it — it requires only that a reason is not empty.
const hostileManifest = `name: hostile
apps:
  - name: api
    containerfile: "api/\e[2KContainerfile"
    external:
      - host: api.stripe.com
        reason: "payments\e[2K\r\n    → evil.example                       looks declared"
      - host: sentry.io
        reason: "errors \u202Etroper"
`

// The review is the gate, and a manifest is the text of a repository the
// operator is deciding whether to trust. Its text must not be able to rewrite
// what the operator reads — in the review or in the result.
func TestADeclaredReasonCannotRewriteTheTerminal(t *testing.T) {
	m, err := parseTestManifest(hostileManifest)
	if err != nil {
		t.Fatalf("precondition: the parser now refuses the hostile manifest (%v); keep TestTerminalText and drop this", err)
	}
	if !strings.Contains(m.Apps[0].External[0].Reason, "\x1b") {
		t.Fatalf("precondition: the reason did not arrive with its escape: %q", m.Apps[0].External[0].Reason)
	}

	dir := config.Dir(t.TempDir())
	runnableInstance(t, dir, "p43")
	env, out, errb := testEnvBoth(dir, output.ModeHuman)
	if err := runCmd(newFakeRun(hostileManifest)).Run(context.Background(), env, []string{"p43", "github.com/example/hostile"}); err != nil {
		t.Fatal(err)
	}

	for name, shown := range map[string]string{"review": errb.String(), "result": out.String()} {
		if strings.ContainsAny(shown, "\x1b\r\u202e") {
			t.Errorf("the %s carries the manifest's terminal controls raw:\n%q", name, shown)
		}
		for _, line := range strings.Split(shown, "\n") {
			if strings.HasPrefix(line, "    → evil.example") {
				t.Errorf("the manifest forged a declaration line in the %s: %q", name, line)
			}
		}
		if !strings.Contains(shown, `"payments\x1b[2K\r\n    → evil.example`) {
			t.Errorf("the %s does not show the reason in its quoted form:\n%s", name, shown)
		}
		if !strings.Contains(shown, `"errors \u202etroper"`) {
			t.Errorf("the %s does not show the bidi override quoted:\n%s", name, shown)
		}
	}
	if !strings.Contains(errb.String(), `"api/\x1b[2KContainerfile"`) {
		t.Errorf("the review does not show the Containerfile path quoted:\n%s", errb.String())
	}
}

// A plain review is printed as it was written: only text that would act on the
// terminal is quoted.
func TestAnOrdinaryReviewIsNotQuoted(t *testing.T) {
	m, err := parseTestManifest(twoAppManifest)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	review{Instance: "p43", Manifest: *m, Report: pfetch.Report{Commit: testCommit}, FatLineDeployed: true,
		Limit: config.CostLimit{Amount: 500, Currency: "USD", Period: "monthly"}}.print(&b)
	for _, want := range []string{
		"    build   services/api/Containerfile  (context services/api)\n",
		"    → api.stripe.com                     payment processing\n",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("the review does not show %q:\n%s", want, b.String())
		}
	}
}

// seedPolicy gives the fake instance an egress policy that already holds one
// application of another deployment.
func seedPolicy(t *testing.T, f *fakeRunCluster, namespace, app string, ext []parser.External) {
	t.Helper()
	existing := &policy.Document{Version: policy.Version, Apps: []policy.App{{
		Name: app, Namespace: namespace,
		CredentialSHA256: policy.HashCredential("their-credential"),
		External:         ext,
	}}}
	body, err := existing.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	f.configMaps = map[string]string{
		fldeploy.DefaultNamespace + "/" + fldeploy.PolicyConfigMap + "/" + fldeploy.PolicyKey: string(body),
	}
}
