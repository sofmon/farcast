package rehearsal_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/cli"
	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/rehearsal"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kernel"
)

// The test binary is the fake tools too: linked as kubectl,
// gke-gcloud-auth-plugin or gcloud, it runs as that tool, exactly as the
// harness binary does.
func TestMain(m *testing.M) {
	if code, ok := rehearsal.ToolMain(os.Args[0], os.Args[1:], os.Environ(), os.Stdout, os.Stderr); ok {
		os.Exit(code)
	}
	// A race-built binary that exits 0 sleeps a second first, for late race
	// reports. Every read runs this binary as kubectl, the plugin and gcloud,
	// a dozen and more times; the children inherit this. It changes nothing
	// a test asserts: GORACE is no variable the fake kubectl refuses, and
	// race reports still print.
	if os.Getenv("GORACE") == "" {
		if err := os.Setenv("GORACE", raceQuiet); err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
}

const raceQuiet = "atexit_sleep_ms=0"

const instance = rehearsal.DefaultInstance

func testBinary(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// startRig starts a rehearsal in a new directory under a fake home, linked to
// this test binary, and stops it when the test ends.
func startRig(t *testing.T, o rehearsal.Options) *rehearsal.Rig {
	t.Helper()
	if o.Dir == "" {
		o.Dir = filepath.Join(t.TempDir(), "r")
	}
	if o.Home == "" {
		o.Home = t.TempDir()
	}
	if o.Tools == "" {
		o.Tools = testBinary(t)
	}
	rig, err := rehearsal.Start(t.Context(), o)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := rig.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return rig
}

// shellNoise are variables a developer's shell may export that 'farcast
// world' passes on to kubectl (its kubectlEnv drops only KUBECONFIG,
// GOOGLE_APPLICATION_CREDENTIALS and CLOUDSDK_*), and that the fake kubectl
// refuses on sight. cli.Main runs in process, with this test's environment.
var shellNoise = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "no_proxy",
	"FARCAST_CONFIG_HOME",
}

// asTheApp gives this process the environment the FarCast app gives farcast
// for these settings — PATH, HOME and CLOUDSDK_CONFIG — after removing what
// a developer's shell may export. Every test that runs cli.Main calls it.
// The variables must be absent, not empty.
func asTheApp(t *testing.T, rig *rehearsal.Rig) {
	t.Helper()
	for _, k := range shellNoise {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", rig.Path())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLOUDSDK_CONFIG", rig.GCloudDir)
}

// appArgv is the FarCast app's own argv, from I1's vector: the CLI's
// testdata/app/argv.json.
type appArgv struct {
	Version   []string `json:"version"`
	Instances []string `json:"instances"`
	World     []string `json:"world"`
}

func loadArgv(t *testing.T) appArgv {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "cli", "testdata", "app", "argv.json"))
	if err != nil {
		t.Fatalf("the app's argv vector: %v", err)
	}
	var a appArgv
	if err := json.Unmarshal(data, &a); err != nil {
		t.Fatal(err)
	}
	if len(a.Version) == 0 || len(a.Instances) == 0 || len(a.World) == 0 {
		t.Fatalf("argv.json lacks a command: %+v", a)
	}
	return a
}

func substitute(argv []string, configDir, inst string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		switch a {
		case "<config>":
			out[i] = configDir
		case "<instance>":
			out[i] = inst
		default:
			out[i] = a
		}
	}
	return out
}

// farcast runs the CLI in process with one of the app's three argvs.
func farcast(t *testing.T, rig *rehearsal.Rig, argv []string) (int, []byte, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := cli.Main(append([]string{"farcast"}, substitute(argv, rig.ConfigDir, instance)...), nil, &out, &errb)
	return code, out.Bytes(), errb.String()
}

// worldDoc is as much of a world document as these tests read.
type worldDoc struct {
	Instance struct {
		Spend struct {
			Read            bool   `json:"read"`
			HasConfirmation bool   `json:"has_confirmation"`
			ConfirmedCents  *int64 `json:"confirmed_cents"`
			ExpectedCents   int64  `json:"expected_cents"`
			TotalCents      int64  `json:"total_cents"`
			LimitCents      *int64 `json:"limit_cents"`
			CheckpointStale bool   `json:"checkpoint_stale"`
			Level           string `json:"level"`
			AtFloor         *bool  `json:"at_floor"`
			Floor           *struct {
				Levers []string `json:"levers"`
			} `json:"floor"`
		} `json:"spend"`
		Network struct {
			Read            bool    `json:"read"`
			Replica         *string `json:"replica"`
			FatLineReplicas *int    `json:"fatline_replicas"`
		} `json:"network"`
		Caveats []string `json:"caveats"`
	} `json:"instance"`
	Groups []struct {
		Namespace string `json:"namespace"`
		Apps      []struct {
			Name      string  `json:"name"`
			State     string  `json:"state"`
			StoppedBy *string `json:"stopped_by"`
		} `json:"apps"`
	} `json:"groups"`
	Lines []struct {
		Kind     string            `json:"kind"`
		From     map[string]string `json:"from"`
		To       map[string]string `json:"to"`
		Evidence string            `json:"evidence"`
	} `json:"lines"`
	Devices []struct {
		ID     string `json:"id"`
		Role   string `json:"role"`
		Health string `json:"health"`
	} `json:"devices"`
	Alerts   []alert            `json:"alerts"`
	Sections map[string]section `json:"sections"`
}

type alert struct {
	Kind     string         `json:"kind"`
	Severity string         `json:"severity"`
	Subject  map[string]any `json:"subject"`
	Title    string         `json:"title"`
}

type section struct {
	Read    bool   `json:"read"`
	Skipped string `json:"skipped"`
	Error   *struct {
		Kind    string `json:"kind"`
		Message string `json:"message"`
	} `json:"error"`
}

// world runs the app's world argv and decodes the document.
func world(t *testing.T, rig *rehearsal.Rig, argv appArgv) worldDoc {
	t.Helper()
	code, out, errOut := farcast(t, rig, argv.World)
	if code != 0 {
		t.Fatalf("world exited %d: %s\nstderr: %s", code, out, errOut)
	}
	if errOut != "" {
		t.Errorf("world wrote to stderr: %s", errOut)
	}
	var doc worldDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("world printed no document: %v\n%s", err, out)
	}
	return doc
}

func (d worldDoc) sectionKind(name string) string {
	s, ok := d.Sections[name]
	switch {
	case !ok:
		return "absent"
	case s.Error != nil:
		return s.Error.Kind
	case s.Skipped != "":
		return "skipped"
	case s.Read:
		return "read"
	}
	return "not read"
}

func (d worldDoc) hasAlert(kind string) bool {
	return slices.ContainsFunc(d.Alerts, func(a alert) bool { return a.Kind == kind })
}

func (d worldDoc) hasLine(kind, fromKey, from, toKey, to, evidence string) bool {
	for _, l := range d.Lines {
		if l.Kind == kind && l.From[fromKey] == from && l.To[toKey] == to && (evidence == "" || l.Evidence == evidence) {
			return true
		}
	}
	return false
}

func calls(t *testing.T, rig *rehearsal.Rig) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(rig.Dir, "calls.log"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for line := range strings.SplitSeq(strings.TrimRight(string(data), "\n"), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func kubectlCalls(lines []string) int {
	n := 0
	for _, l := range lines {
		if f := strings.Fields(l); len(f) > 1 && f[1] == "kubectl" {
			n++
		}
	}
	return n
}

func checkHealthy(t *testing.T, doc worldDoc) {
	t.Helper()
	for _, s := range []string{"spend", "apps", "policy", "network", "seal"} {
		if got := doc.sectionKind(s); got != "read" {
			t.Errorf("section %s: %s, want read", s, got)
		}
	}
	if n := doc.Instance.Network; !n.Read || n.Replica == nil || *n.Replica != "fatline-rehearsal-0" ||
		n.FatLineReplicas == nil || *n.FatLineReplicas != 1 {
		t.Errorf("network: %+v, want replica fatline-rehearsal-0, 1 of 1", n)
	}
	if s := doc.Instance.Spend; !s.Read || !s.HasConfirmation || s.ConfirmedCents == nil || s.Level != "ok" || s.CheckpointStale {
		t.Errorf("spend: %+v, want read, split (confirmed and expected), level ok, fresh", s)
	}
	for _, l := range []struct{ kind, fk, from, tk, to, ev string }{
		{"tunnel", "device", "operator", "component", "boundary", "observed"},
		{"watch", "component", "monitor", "component", "boundary", "observed"},
		{"keeper", "device", instance + "/phone", "component", "storage", "observed"},
		{"storage", "app", "shop/api", "component", "storage", "declared"},
		{"storage", "app", "shop/web", "component", "storage", "declared"},
		{"egress", "app", "shop/api", "host", "api.payments.invalid", "observed"},
		{"egress", "app", "shop/api", "host", "telemetry.invalid", "declared"},
	} {
		if !doc.hasLine(l.kind, l.fk, l.from, l.tk, l.to, l.ev) {
			t.Errorf("no %s line %s → %s (%s)", l.kind, l.from, l.to, l.ev)
		}
	}
	keeper := false
	for _, d := range doc.Devices {
		if d.ID == instance+"/phone" {
			keeper = d.Health == "healthy"
		}
	}
	if !keeper {
		t.Errorf("devices %+v: the keeper %s/phone is not healthy", doc.Devices, instance)
	}
	if len(doc.Alerts) != 0 {
		t.Errorf("alerts %+v, want none", doc.Alerts)
	}
}

// planted are values the FarCast app's parent environment must never pass
// on, and farcast's own kubectl environment must drop or override. If one
// reached the fake kubectl it would refuse, and the read would fail.
func plant(t *testing.T) []string {
	t.Helper()
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	for k, v := range map[string]string{
		"CLOUDSDK_AUTH_ACCESS_TOKEN":     "planted-token",
		"CLOUDSDK_CORE_ACCOUNT":          "someone@work.invalid",
		"CLOUDSDK_ACTIVE_CONFIG_NAME":    "work",
		"KUBECONFIG":                     filepath.Join(elsewhere, "kubeconfig"),
		"GOOGLE_APPLICATION_CREDENTIALS": filepath.Join(elsewhere, "credentials.json"),
	} {
		t.Setenv(k, v)
	}
	return []string{"planted", "someone@work.invalid", "elsewhere", "CLOUDSDK_AUTH_ACCESS_TOKEN", "CLOUDSDK_CORE_ACCOUNT",
		"GOOGLE_APPLICATION_CREDENTIALS"}
}

// TestWorldReadsTheRehearsalWhole is the rehearsal end to end: the real
// 'farcast version', 'instances' and 'world', run with the app's own argv
// and the app's environment, planted variables included, read every section.
func TestWorldReadsTheRehearsalWhole(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	argv := loadArgv(t)
	asTheApp(t, rig)
	planted := plant(t)

	code, out, errOut := farcast(t, rig, argv.Version)
	if code != 0 || errOut != "" {
		t.Fatalf("version exited %d: %s %s", code, out, errOut)
	}
	var v struct{ Version, Commit string }
	if err := json.Unmarshal(out, &v); err != nil || v.Version == "" || v.Commit == "" {
		t.Fatalf("version: %s (%v)", out, err)
	}

	code, out, errOut = farcast(t, rig, argv.Instances)
	if code != 0 || errOut != "" {
		t.Fatalf("instances exited %d: %s %s", code, out, errOut)
	}
	var list struct {
		Schema    int `json:"schema"`
		Instances []struct {
			Name         string `json:"name"`
			GCloudPinned bool   `json:"gcloud_pinned"`
			Status       string `json:"status"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		t.Fatal(err)
	}
	if list.Schema != 1 || len(list.Instances) != 1 || list.Instances[0].Name != instance ||
		!list.Instances[0].GCloudPinned || list.Instances[0].Status != "running" {
		t.Fatalf("instances: %s", out)
	}
	if n := len(calls(t, rig)); n != 0 {
		t.Fatalf("version and instances read files only, yet calls.log has %d lines", n)
	}

	checkHealthy(t, world(t, rig, argv))

	lines := calls(t, rig)
	if kubectlCalls(lines) == 0 {
		t.Fatal("world ran no kubectl")
	}
	for _, l := range lines {
		if !strings.HasSuffix(l, " | ok") {
			t.Errorf("calls.log line not ok: %s", l)
		}
		f := strings.Fields(strings.TrimSuffix(l, " | ok"))
		switch {
		case len(f) < 2:
			t.Errorf("calls.log line has no tool: %s", l)
		case f[1] == "kubectl":
			if len(f) < 5 || f[2] != "--kubeconfig" || f[4] != "get" {
				t.Errorf("a kubectl call that is not a get: %s", l)
			}
		case f[1] == "gke-gcloud-auth-plugin":
			if len(f) != 2 {
				t.Errorf("the auth plugin was given arguments: %s", l)
			}
		case f[1] == "gcloud":
			if strings.Join(f[2:], " ") != "config config-helper --format=json" {
				t.Errorf("gcloud was asked something else: %s", l)
			}
		default:
			t.Errorf("an unexpected caller: %s", l)
		}
		for _, p := range planted {
			if strings.Contains(l, p) {
				t.Errorf("calls.log names %q: %s", p, l)
			}
		}
	}
}

// TestScenariosShowInWorld switches each scenario and reads the very next
// world, with no waiting.
func TestScenariosShowInWorld(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	argv := loadArgv(t)
	asTheApp(t, rig)

	set := func(name string) {
		t.Helper()
		if err := rehearsal.SetScenario(rig.Dir, name); err != nil {
			t.Fatal(err)
		}
	}

	set(rehearsal.ScenarioSealed)
	if doc := world(t, rig, argv); !doc.hasAlert("sealed") || doc.sectionKind("seal") != "read" {
		t.Errorf("sealed: alerts %+v, seal %s", doc.Alerts, doc.sectionKind("seal"))
	}

	set(rehearsal.ScenarioStaleCheckpoint)
	if doc := world(t, rig, argv); !doc.hasAlert("checkpoint_stale") || !doc.Instance.Spend.CheckpointStale {
		t.Errorf("stale-checkpoint: alerts %+v, spend %+v", doc.Alerts, doc.Instance.Spend)
	}

	set(rehearsal.ScenarioCostReached)
	doc := world(t, rig, argv)
	critical := false
	for _, a := range doc.Alerts {
		critical = critical || (a.Kind == "cost" && a.Severity == "critical")
	}
	stopped := false
	for _, g := range doc.Groups {
		for _, a := range g.Apps {
			if g.Namespace == "shop" && a.Name == "web" {
				stopped = a.State == "stopped" && a.StoppedBy == nil
			}
		}
	}
	if !critical || !stopped || doc.Instance.Spend.Level != "reached" {
		t.Errorf("cost-reached: alerts %+v, groups %+v", doc.Alerts, doc.Groups)
	}
	// A kernel at its limit is one whose spending is over it (phase 7, F6).
	if s := doc.Instance.Spend; s.LimitCents == nil || s.TotalCents < *s.LimitCents {
		t.Errorf("cost-reached: total %d cents against a limit of %v; a kernel at its limit is over it", s.TotalCents, s.LimitCents)
	}

	set(rehearsal.ScenarioSignedOut)
	doc = world(t, rig, argv)
	for _, s := range []string{"spend", "apps", "policy"} {
		if got := doc.sectionKind(s); got != "gcloud_signed_out" {
			t.Errorf("signed-out: section %s is %s", s, got)
		}
	}
	for _, s := range []string{"network", "seal"} {
		if got := doc.sectionKind(s); got != "read" {
			t.Errorf("signed-out: section %s is %s, want read", s, got)
		}
	}

	set(rehearsal.ScenarioIdentityMismatch)
	before := kubectlCalls(calls(t, rig))
	code, out, errOut := farcast(t, rig, argv.World)
	var env struct {
		Error struct {
			Kind string `json:"kind"`
		} `json:"error"`
	}
	if code != 1 || json.Unmarshal(out, &env) != nil || env.Error.Kind != "gcloud_mismatch" || errOut != "" {
		t.Errorf("identity-mismatch: exit %d, %s, stderr %q", code, out, errOut)
	}
	if after := kubectlCalls(calls(t, rig)); after != before {
		t.Errorf("identity-mismatch: kubectl ran %d times; it must not run at all", after-before)
	}

	// Every other scenario puts the project back, so this read is whole.
	set(rehearsal.ScenarioDenied)
	doc = world(t, rig, argv)
	denied := false
	for _, a := range doc.Alerts {
		denied = denied || (a.Kind == "denied" && a.Subject["app"] == "shop/web")
	}
	if !denied || !doc.hasLine("egress", "app", "shop/web", "host", "tracker.invalid", "denied") {
		t.Errorf("denied: alerts %+v, lines %+v", doc.Alerts, doc.Lines)
	}
	for _, s := range []string{"spend", "apps", "policy", "network", "seal"} {
		if got := doc.sectionKind(s); got != "read" {
			t.Errorf("denied: section %s is %s, want read", s, got)
		}
	}
}

// TestTheAtFloorScenarioShowsWhatTheKernelRecorded reads the scenario the
// map's cost-guard label, floor alert and levers are walked with: both
// applications stopped by the kernel and recorded, and the floor reached.
// cost-reached stays the kernel that recorded nothing, so the two read apart.
func TestTheAtFloorScenarioShowsWhatTheKernelRecorded(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	argv := loadArgv(t)
	asTheApp(t, rig)
	if err := rehearsal.SetScenario(rig.Dir, rehearsal.ScenarioAtFloor); err != nil {
		t.Fatal(err)
	}
	doc := world(t, rig, argv)

	for _, g := range doc.Groups {
		if g.Namespace != "shop" {
			continue
		}
		for _, a := range g.Apps {
			if a.State != "stopped" || a.StoppedBy == nil || *a.StoppedBy != "cost_guard" {
				t.Errorf("shop/%s: state %s, stopped_by %v; want stopped by the cost guard", a.Name, a.State, a.StoppedBy)
			}
		}
	}
	s := doc.Instance.Spend
	if s.Level != "reached" || s.AtFloor == nil || !*s.AtFloor || s.Floor == nil ||
		!slices.Equal(s.Floor.Levers, []string{"drop_carrier", "release_instance"}) {
		t.Errorf("spend: level %s, at_floor %v, floor %+v", s.Level, s.AtFloor, s.Floor)
	}
	if s.LimitCents == nil || s.TotalCents < *s.LimitCents {
		t.Errorf("spend: total %d cents against a limit of %v; at the floor, spending is still over the limit", s.TotalCents, s.LimitCents)
	}
	floor, costAlert := false, false
	for _, a := range doc.Alerts {
		switch a.Kind {
		case "at_floor":
			floor = a.Severity == "critical" && a.Subject["component"] == "kernel" &&
				strings.Contains(a.Title, "release the instance")
		case "cost":
			costAlert = a.Severity == "critical"
		}
	}
	if !floor || !costAlert {
		t.Errorf("alerts %+v; want the critical at_floor alert on the kernel naming its levers, beside the cost alert", doc.Alerts)
	}
	for _, sec := range []string{"spend", "apps", "policy", "network", "seal"} {
		if got := doc.sectionKind(sec); got != "read" {
			t.Errorf("section %s is %s, want read", sec, got)
		}
	}
}

// editSpec rewrites rehearsal.json, as a test seam.
func editSpec(t *testing.T, dir string, edit func(*rehearsal.Spec)) {
	t.Helper()
	s, err := rehearsal.LoadSpec(dir)
	if err != nil {
		t.Fatal(err)
	}
	edit(&s)
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rehearsal.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// kubectlEnv is the environment 'farcast world' gives kubectl for the rig:
// what the tool tests pass explicitly, never the test's own.
func kubectlEnv(t *testing.T, rig *rehearsal.Rig) []string {
	t.Helper()
	return []string{
		"PATH=" + rig.Path(),
		"HOME=" + t.TempDir(),
		"KUBECONFIG=" + instanceKubeconfig(rig),
		"CLOUDSDK_CONFIG=" + rig.GCloudDir,
		"CLOUDSDK_ACTIVE_CONFIG_NAME=rehearsal",
		"GORACE=" + os.Getenv("GORACE"), // see TestMain
	}
}

func instanceKubeconfig(rig *rehearsal.Rig) string {
	return filepath.Join(rig.ConfigDir, "instances", instance, "kubeconfig.yaml")
}

func kubectlArgs(rig *rehearsal.Rig, rest ...string) []string {
	return append([]string{"--kubeconfig", instanceKubeconfig(rig)}, rest...)
}

var namespaceRead = []string{"get", "namespace", "-l", "app.kubernetes.io/managed-by=farcast", "-o", "json"}

func runTool(argv0 string, args, environ []string) (int, string, string) {
	var out, errb bytes.Buffer
	code, ok := rehearsal.ToolMain(argv0, args, environ, &out, &errb)
	if !ok {
		return -1, "", "not a tool"
	}
	return code, out.String(), errb.String()
}

func without(env []string, key string) []string {
	return slices.DeleteFunc(slices.Clone(env), func(kv string) bool { return strings.HasPrefix(kv, key+"=") })
}

func with(env []string, kv ...string) []string { return append(slices.Clone(env), kv...) }

// TestSlowClusterSleeps proves slow-cluster makes kubectl wait before it
// answers, with the sleep cut to 50 ms in the spec.
func TestSlowClusterSleeps(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	editSpec(t, rig.Dir, func(s *rehearsal.Spec) { s.Scenario, s.SlowSeconds = rehearsal.ScenarioSlowCluster, 0.05 })
	start := time.Now()
	code, out, errOut := runTool(filepath.Join(rig.KubeBin, "kubectl"), kubectlArgs(rig, namespaceRead...), kubectlEnv(t, rig))
	if code != 0 || !strings.Contains(out, `"shop"`) {
		t.Fatalf("slow kubectl: exit %d, %s, %s", code, out, errOut)
	}
	if took := time.Since(start); took < 50*time.Millisecond {
		t.Errorf("slow-cluster answered in %s; it sleeps first", took)
	}
	if s, err := rehearsal.LoadSpec(rig.Dir); err != nil || s.SlowSeconds != 0.05 {
		t.Fatalf("the spec's slow_seconds: %v, %v", s.SlowSeconds, err)
	}
}

// TestFakeKubectlRefusesWhatMustNotReachIt runs the tools in process with an
// environment given explicitly, never the test runner's own.
func TestFakeKubectlRefusesWhatMustNotReachIt(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	// Nothing on the test runner's PATH can stand in: every lookup must
	// read the environment it is given.
	t.Setenv("PATH", "/nonexistent-rehearsal-path")
	kubectl := filepath.Join(rig.KubeBin, "kubectl")
	base := kubectlEnv(t, rig)
	args := kubectlArgs(rig, namespaceRead...)

	if code, out, errOut := runTool(kubectl, args, base); code != 0 || !strings.Contains(out, `"shop"`) {
		t.Fatalf("baseline: exit %d, %s, %s", code, out, errOut)
	}

	for _, c := range []struct {
		name, names, value string
		env                []string
	}{
		{"a planted access token", "CLOUDSDK_AUTH_ACCESS_TOKEN", "planted-token-value", with(base, "CLOUDSDK_AUTH_ACCESS_TOKEN=planted-token-value")},
		{"a planted account", "CLOUDSDK_CORE_ACCOUNT", "someone@work.invalid", with(base, "CLOUDSDK_CORE_ACCOUNT=someone@work.invalid")},
		{"a proxy", "HTTPS_PROXY", "127.0.0.1:9", with(base, "HTTPS_PROXY=http://127.0.0.1:9")},
		{"a lower-case proxy", "https_proxy", "127.0.0.1:9", with(base, "https_proxy=http://127.0.0.1:9")},
		{"FARCAST_CONFIG_HOME", "FARCAST_CONFIG_HOME", "/nonexistent-farcast-home", with(base, "FARCAST_CONFIG_HOME=/nonexistent-farcast-home")},
		{"credentials", "GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent-credentials", with(base, "GOOGLE_APPLICATION_CREDENTIALS=/nonexistent-credentials")},
		{"no active configuration named", "CLOUDSDK_ACTIVE_CONFIG_NAME", "", without(base, "CLOUDSDK_ACTIVE_CONFIG_NAME")},
		{"a relative PATH entry", "PATH", "", with(without(base, "PATH"), "PATH=bin:"+rig.Path())},
		{"another kubeconfig", "KUBECONFIG", "", with(without(base, "KUBECONFIG"), "KUBECONFIG="+filepath.Join(t.TempDir(), "kubeconfig"))},
		{"the decoy configuration", "another identity", "", with(without(base, "CLOUDSDK_ACTIVE_CONFIG_NAME"), "CLOUDSDK_ACTIVE_CONFIG_NAME=work")},
	} {
		code, out, errOut := runTool(kubectl, args, c.env)
		if code != 1 || out != "" || !strings.Contains(errOut, c.names) || (c.value != "" && strings.Contains(errOut, c.value)) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want exit 1 naming %s and not its value", c.name, code, out, errOut, c.names)
		}
	}
	for _, l := range calls(t, rig) {
		for _, v := range []string{"planted-token-value", "someone@work.invalid", "127.0.0.1:9", "/nonexistent"} {
			if strings.Contains(l, v) {
				t.Errorf("calls.log holds a value: %s", l)
			}
		}
	}

	// The plugin and gcloud never fall back to a default directory, and
	// never open one they were not given: the other directory is mode 000,
	// so reading it would fail with a different message.
	other := filepath.Join(t.TempDir(), "gcloud")
	if err := os.Mkdir(other, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(other, 0o700) })
	for _, c := range []struct {
		tool string
		args []string
	}{
		{filepath.Join(rig.SDKBin, "gke-gcloud-auth-plugin"), nil},
		{filepath.Join(rig.SDKBin, "gcloud"), []string{"config", "config-helper", "--format=json"}},
	} {
		for _, env := range [][]string{without(base, "CLOUDSDK_CONFIG"), with(without(base, "CLOUDSDK_CONFIG"), "CLOUDSDK_CONFIG="+other)} {
			code, out, errOut := runTool(c.tool, c.args, env)
			if code != 1 || out != "" || !strings.Contains(errOut, "CLOUDSDK_CONFIG") || strings.Contains(errOut, "permission") {
				t.Errorf("%s with %v: exit %d, %q, %q", filepath.Base(c.tool), env, code, out, errOut)
			}
		}
	}

	// A relative argv0, and a link outside the rehearsal's own bin.
	if code, _, errOut := runTool("kubectl", args, base); code != 1 || !strings.Contains(errOut, "relative") {
		t.Errorf("relative argv0: exit %d, %q", code, errOut)
	}
	elsewhere := filepath.Join(t.TempDir(), "copy")
	if err := os.MkdirAll(filepath.Join(elsewhere, "kube", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(testBinary(t), filepath.Join(elsewhere, "kube", "bin", "kubectl")); err != nil {
		t.Fatal(err)
	}
	spec, err := os.ReadFile(filepath.Join(rig.Dir, "rehearsal.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "rehearsal.json"), spec, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := runTool(filepath.Join(elsewhere, "kube", "bin", "kubectl"), args, base); code != 1 || out != "" ||
		!strings.Contains(errOut, "not this rehearsal's own") {
		t.Errorf("a copied link: exit %d, %q, %q", code, out, errOut)
	}
}

// TestFakeKubectlAnswersOnlyReads: nothing but the reads world sends.
func TestFakeKubectlAnswersOnlyReads(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	kubectl := filepath.Join(rig.KubeBin, "kubectl")
	env := kubectlEnv(t, rig)
	for _, cmd := range [][]string{
		{"apply", "-f", "-"},
		{"delete", "ns", "shop"},
		{"get", "secrets", "-A"},
		{"get", "configmap", "x", "-n", "shop", "--ignore-not-found", "-o", "json"},
		{"logs", "-n", "shop", "deployment/api"},
	} {
		code, out, errOut := runTool(kubectl, kubectlArgs(rig, cmd...), env)
		if code != 1 || out != "" || !strings.Contains(errOut, "reads only") {
			t.Errorf("%v: exit %d, %q, %q", cmd, code, out, errOut)
		}
		if _, ok := rehearsal.ClusterAnswer(spec(t), cmd, time.Now()); ok {
			t.Errorf("ClusterAnswer answered %v", cmd)
		}
	}
	refused := 0
	for _, l := range calls(t, rig) {
		if strings.Contains(l, " kubectl ") && strings.HasSuffix(l, "| refused: no answer to this command") {
			refused++
		}
	}
	if refused != 5 {
		t.Errorf("calls.log records %d refusals, want 5", refused)
	}
}

// spec is a rehearsal's record, made by hand for the pure tests.
func spec(t *testing.T) rehearsal.Spec {
	t.Helper()
	root := t.TempDir()
	return rehearsal.Spec{
		Instance: instance, Account: rehearsal.DefaultAccount, Project: rehearsal.DefaultProject,
		Scenario: rehearsal.ScenarioHealthy, Started: time.Now().UTC().Add(-time.Hour).Truncate(time.Second),
		Dirs: rehearsal.Dirs{
			Root: root, Config: filepath.Join(root, "config"), GCloud: filepath.Join(root, "gcloud"),
			KubeBin: filepath.Join(root, "kube", "bin"), SDKBin: filepath.Join(root, "sdk", "bin"),
		},
		Images: map[string]string{
			"fatline": "registry.rehearsal.invalid/farcast/fatline@sha256:" + strings.Repeat("1", 64),
			"shrike":  "registry.rehearsal.invalid/farcast/shrike@sha256:" + strings.Repeat("2", 64),
		},
		SlowSeconds: 25,
	}
}

type answerRunner struct {
	spec rehearsal.Spec
	now  time.Time
}

func (a answerRunner) Run(_ context.Context, _ []byte, args ...string) ([]byte, error) {
	out, ok := rehearsal.ClusterAnswer(a.spec, args, a.now)
	if !ok {
		return nil, fmt.Errorf("no answer to %v", args)
	}
	return out, nil
}

// TestClusterAnswersDecode reads the answers through farcast's own cluster
// client, as world does.
func TestClusterAnswersDecode(t *testing.T) {
	s := spec(t)
	now := time.Now().UTC()
	cl := cluster.NewWithRunner(answerRunner{s, now})
	ctx := t.Context()

	sys, err := cl.Workloads(ctx, fldeploy.DefaultNamespace)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]cluster.Workload{}
	for _, w := range sys {
		got[w.Name] = w
	}
	if f := got["fatline"]; f.Desired != 1 || f.Ready != 1 || len(f.Images) != 2 || f.Images[0] != s.Images["fatline"] {
		t.Errorf("fatline: %+v", f)
	}
	if k := got["datasphered"]; k.Kind != "StatefulSet" || k.Desired != 2 || k.Ready != 2 {
		t.Errorf("datasphered: %+v", k)
	}
	if k := got["technocore"]; k.Desired != 1 || k.Ready != 1 {
		t.Errorf("technocore: %+v", k)
	}
	shop, err := cl.Workloads(ctx, "shop")
	if err != nil || len(shop) != 2 || shop[0].Name != "api" || shop[0].Desired != 2 || shop[1].Name != "web" || shop[1].Desired != 1 {
		t.Errorf("shop: %+v, %v", shop, err)
	}
	if none, err := cl.Workloads(ctx, "elsewhere"); err != nil || len(none) != 0 {
		t.Errorf("another namespace: %+v, %v", none, err)
	}
	if ns, err := cl.NamespacesLabelled(ctx, "app.kubernetes.io/managed-by=farcast"); err != nil || !slices.Equal(ns, []string{"shop"}) {
		t.Errorf("namespaces: %v, %v", ns, err)
	}

	raw, found, err := cl.ConfigMapValue(ctx, fldeploy.DefaultNamespace, kernel.DefaultNamespacesName, kernel.NamespacesKey())
	var meter kernel.Namespaces
	if err != nil || !found || json.Unmarshal([]byte(raw), &meter) != nil || meter.Version != kernel.NamespacesVersion ||
		!slices.Equal(meter.Meter, []string{"farcast-system", "shop"}) {
		t.Errorf("metered namespaces: %q, %v, %v", raw, found, err)
	}

	raw, found, err = cl.ConfigMapValue(ctx, fldeploy.DefaultNamespace, kernel.DefaultCheckpointName, kernel.CheckpointKey())
	if err != nil || !found {
		t.Fatalf("checkpoint: %v, %v", found, err)
	}
	var cp kernel.Checkpoint
	if err := json.Unmarshal([]byte(raw), &cp); err != nil || cp.Version != kernel.CheckpointVersion {
		t.Fatalf("checkpoint: %v", err)
	}
	ledger, err := cost.Restore(cp.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	if a := ledger.Accrued(); !a.HasConfirmation || a.Calibration != 1 || a.Expected <= 0 || len(a.Discrepancies) != 0 {
		t.Errorf("accrual: %+v", a)
	}
	if cp.Observed.Level != cost.LevelOK.String() || cp.Observed.Limit != 50 || now.Sub(cp.Observed.At) > 5*time.Minute {
		t.Errorf("observed: %+v", cp.Observed)
	}

	raw, found, err = cl.ConfigMapValue(ctx, fldeploy.DefaultNamespace, fldeploy.PolicyConfigMap, fldeploy.PolicyKey)
	if err != nil || !found {
		t.Fatalf("policy: %v, %v", found, err)
	}
	doc, err := policy.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if by := doc.ByTenant(); len(by["shop/api"]) != 2 || len(by["shop/web"]) != 0 {
		t.Errorf("policy: %+v", by)
	}
	if _, found, err := cl.ConfigMapValue(ctx, fldeploy.DefaultNamespace, "something-else", "x"); found || err != nil {
		t.Errorf("an unheld ConfigMap: found %v, %v", found, err)
	}
}

// snapshot is every path under root, with its mode.
func snapshot(t *testing.T, root string) map[string]fs.FileMode {
	t.Helper()
	out := map[string]fs.FileMode{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		out[path] = info.Mode()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestStartRefusesTheRealDirectories: the guard, against a fake home under
// $TMPDIR — /var on macOS, a link to /private/var, so both sides of each
// comparison must be resolved.
func TestStartRefusesTheRealDirectories(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(home, alias); err != nil {
		t.Fatal(err)
	}
	farcastHome := filepath.Join(t.TempDir(), "farcast-config")
	t.Setenv("FARCAST_CONFIG_HOME", farcastHome)
	// The machine's default farcast directory stays protected while
	// $FARCAST_CONFIG_HOME points elsewhere. os.UserConfigDir reads $HOME
	// (and $XDG_CONFIG_HOME off macOS), so both point into the fake home:
	// the guard is never tried against the real one.
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)
	userConfig, err := os.UserConfigDir()
	if err != nil || !strings.HasPrefix(userConfig, home+string(filepath.Separator)) {
		t.Fatalf("the user configuration directory %q (%v) is not in the fake home", userConfig, err)
	}
	notEmpty := t.TempDir()
	if err := os.WriteFile(filepath.Join(notEmpty, "notes.txt"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, home)

	cases := []struct{ name, dir, want string }{
		{"kube, not yet made", filepath.Join(home, ".kube", "r"), "kubectl's directory"},
		{"gcloud", filepath.Join(home, ".config", "gcloud"), "gcloud's configuration directory"},
		{"gcloud, another case", filepath.Join(home, ".config", "GCloud", "r"), "gcloud's configuration directory"},
		{"the home itself", home, "overlaps"},
		{"the farcast directory", filepath.Join(farcastHome, "r"), "farcast configuration directory"},
		{"kube through an alias", filepath.Join(alias, ".kube", "r"), "kubectl's directory"},
		{"not empty, not a rehearsal", notEmpty, "not empty"},
		{"the default farcast directory, $FARCAST_CONFIG_HOME elsewhere", filepath.Join(userConfig, "farcast", "r"), "default farcast configuration directory"},
	}
	// macOS's firmlinks: /System/Volumes/Data/private is /private, and no
	// symlink says so, so a guard that compares spellings is walked around.
	if data := dataVolumeSpelling(t, home); data != "" {
		cases = append(cases,
			struct{ name, dir, want string }{"kube through the data volume", filepath.Join(data, ".kube", "r"), "kubectl's directory"},
			struct{ name, dir, want string }{"gcloud through the data volume", filepath.Join(data, ".config", "gcloud", "r"), "gcloud's configuration directory"},
			struct{ name, dir, want string }{"the default farcast directory through the data volume", filepath.Join(data, strings.TrimPrefix(userConfig, home), "farcast", "r"), "default farcast configuration directory"})
	}
	for _, c := range cases {
		rig, err := rehearsal.Start(t.Context(), rehearsal.Options{Dir: c.dir, Home: home, Tools: testBinary(t)})
		if err == nil {
			_ = rig.Close()
			t.Errorf("%s: Start accepted %s", c.name, c.dir)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v; want it to say %q", c.name, err, c.want)
		}
	}
	after := snapshot(t, home)
	if len(after) != len(before) {
		t.Errorf("Start wrote under the home: %v", after)
	}
	if _, err := os.Stat(farcastHome); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Start made the farcast directory: %v", err)
	}
	if entries, err := os.ReadDir(notEmpty); err != nil || len(entries) != 1 {
		t.Errorf("Start wrote into a directory that was not its own: %v", entries)
	}
	// A directory the environment names, inside a new one, is refused too:
	// only a rehearsal that already exists owns what is inside it.
	fresh := filepath.Join(t.TempDir(), "r")
	for _, c := range []struct{ key, value, want string }{
		{"CLOUDSDK_CONFIG", filepath.Join(fresh, "gcloud"), "$CLOUDSDK_CONFIG"},
		{"KUBECONFIG", filepath.Join(fresh, "config", "kubeconfig.yaml"), "$KUBECONFIG"},
	} {
		t.Setenv(c.key, c.value)
		rig, err := rehearsal.Start(t.Context(), rehearsal.Options{Dir: fresh, Home: home, Tools: testBinary(t)})
		if err == nil {
			_ = rig.Close()
			t.Errorf("Start accepted %s with %s inside it", fresh, c.key)
		} else if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s inside a new directory: %v", c.key, err)
		}
		t.Setenv(c.key, "")
	}
	if _, err := os.Stat(fresh); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Start made %s: %v", fresh, err)
	}
	// SetScenario refuses the same directories, and anything not a rehearsal.
	if err := rehearsal.SetScenario(notEmpty, rehearsal.ScenarioSealed); err == nil {
		t.Error("SetScenario accepted a directory that holds no rehearsal")
	}
	if err := rehearsal.SetScenario(notEmpty, "no-such-scenario"); err == nil {
		t.Error("SetScenario accepted an unknown scenario")
	}
	if data := dataVolumeSpelling(t, home); data != "" {
		if err := rehearsal.SetScenario(filepath.Join(data, ".kube", "r"), rehearsal.ScenarioSealed); err == nil || !strings.Contains(err.Error(), "kubectl's directory") {
			t.Errorf("SetScenario, kube through the data volume: %v; want the guard's refusal", err)
		}
	}
	if after := snapshot(t, home); len(after) != len(before) {
		t.Errorf("SetScenario wrote under the home: %v", after)
	}
}

// dataVolumeSpelling is dir spelled through macOS's data volume,
// /System/Volumes/Data/private/var/… for /var/…: the same directory, reached
// through a firmlink rather than a symlink. It is "" where there is no such
// spelling, off macOS or on a layout without one.
func dataVolumeSpelling(t *testing.T, dir string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join("/System/Volumes/Data", real)
	a, errA := os.Stat(real)
	b, errB := os.Stat(data)
	if errA != nil || errB != nil || !os.SameFile(a, b) {
		return ""
	}
	return data
}

// TestCAKeyAndKeyringAreUnreadable: both are mode 000, and the app's reads
// never open them — the config package's read observer sees neither.
func TestCAKeyAndKeyringAreUnreadable(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	inst := filepath.Join(rig.ConfigDir, "instances", instance)
	caKey := filepath.Join(inst, "fatline", "ca.key")
	keyring := filepath.Join(inst, "datasphere", "keys.yaml")
	for _, p := range []string{caKey, keyring} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0 {
			t.Errorf("%s is mode %v, want 000", p, info.Mode().Perm())
		}
	}
	argv := loadArgv(t)
	asTheApp(t, rig)
	var mu sync.Mutex
	var read []string
	stop := config.ObserveReads(func(path string) {
		mu.Lock()
		defer mu.Unlock()
		read = append(read, path)
	})
	defer stop()
	if code, out, errOut := farcast(t, rig, argv.Instances); code != 0 {
		t.Fatalf("instances: %d %s %s", code, out, errOut)
	}
	checkHealthy(t, world(t, rig, argv))
	mu.Lock()
	defer mu.Unlock()
	if len(read) == 0 {
		t.Fatal("the read observer saw nothing; it is not wired")
	}
	for _, p := range read {
		if p == caKey || p == keyring {
			t.Errorf("a read opened %s", p)
		}
	}
}

// TestSummarizeSaysNoNames: every world vector's shape, and nothing of what
// it names.
func TestSummarizeSaysNoNames(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "cli", "testdata", "world", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no world vectors: %v", err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := rehearsal.Summarize(bytes.NewReader(data), &out); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
			continue
		}
		var doc struct {
			Error *struct {
				Kind    string `json:"kind"`
				Message string `json:"message"`
			} `json:"error"`
			Hosts []struct {
				Name   string   `json:"name"`
				SeenAs []string `json:"seen_as"`
			} `json:"hosts"`
			Alerts []struct {
				Title string `json:"title"`
			} `json:"alerts"`
			Instance struct {
				Name    string   `json:"name"`
				Caveats []string `json:"caveats"`
			} `json:"instance"`
			Sections map[string]struct {
				Error *struct {
					Kind    string `json:"kind"`
					Message string `json:"message"`
				} `json:"error"`
			} `json:"sections"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		s := out.String()
		forbidden := []string{"github.com", "fatline-5d8c7b9f4", "atlas/", "atlas", "4f2a9c1", "proj-atlas"}
		var kinds []string
		if doc.Error != nil {
			forbidden = append(forbidden, doc.Error.Message)
			kinds = append(kinds, doc.Error.Kind)
		}
		for _, h := range doc.Hosts {
			forbidden = append(forbidden, h.Name)
			forbidden = append(forbidden, h.SeenAs...)
		}
		for _, a := range doc.Alerts {
			forbidden = append(forbidden, a.Title)
		}
		forbidden = append(forbidden, doc.Instance.Caveats...)
		for _, sec := range doc.Sections {
			if sec.Error != nil {
				forbidden = append(forbidden, sec.Error.Message)
				kinds = append(kinds, sec.Error.Kind)
			}
		}
		for _, w := range forbidden {
			if w != "" && strings.Contains(s, w) {
				t.Errorf("%s: the summary says %q:\n%s", filepath.Base(f), w, s)
			}
		}
		for _, k := range kinds {
			if !strings.Contains(s, k) {
				t.Errorf("%s: the summary lacks the kind %s:\n%s", filepath.Base(f), k, s)
			}
		}
		if strings.Contains(s, ":00:") || strings.Contains(s, "T0") || strings.Contains(s, "T1") {
			t.Errorf("%s: the summary carries a time of day:\n%s", filepath.Base(f), s)
		}
	}
	// Free text in a closed field never reaches the summary.
	var out bytes.Buffer
	if err := rehearsal.Summarize(strings.NewReader(`{"schema":1,"generated_at":"x","instance":{"status":"secret-host.example"},"sections":{"spend":{"read":false,"error":{"kind":"leak.example","message":"m"}}},"alerts":[{"kind":"atlas.example","title":"t"}]}`), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "example") {
		t.Errorf("free text reached the summary:\n%s", out.String())
	}
}

// TestCloseIsIdempotent: a second Close is nothing, and every listener is gone.
func TestCloseIsIdempotent(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	addrs := rig.Listeners()
	if len(addrs) != 4 {
		t.Fatalf("listeners %v, want the tunnel, Shrike and two keyholders", addrs)
	}
	for _, a := range addrs {
		if host, _, err := net.SplitHostPort(a); err != nil || host != "127.0.0.1" {
			t.Errorf("listener %s is not on 127.0.0.1", a)
		}
	}
	if err := rig.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rig.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	for _, a := range addrs {
		if c, err := net.DialTimeout("tcp", a, time.Second); err == nil {
			_ = c.Close()
			t.Errorf("%s still accepts after Close", a)
		}
	}
	if _, err := os.Stat(filepath.Join(rig.Dir, "rehearsal.json")); err != nil {
		t.Errorf("Close removed the state directory: %v", err)
	}
}

// TestRestartReusesTheDirectory: a stopped rehearsal starts again on its own
// directory, on its own tunnel port, with its own leaves, and changes nothing
// the operator entered.
func TestRestartReusesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "r")
	home := t.TempDir()
	argv := loadArgv(t)
	o := rehearsal.Options{Dir: dir, Home: home, Tools: testBinary(t)}
	first, err := rehearsal.Start(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	asTheApp(t, first)
	checkHealthy(t, world(t, first, argv))
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(first.ConfigDir, "instances", instance, "metadata.yaml")
	recorded, err := os.ReadFile(meta)
	if err != nil {
		t.Fatal(err)
	}

	second := startRig(t, o)
	if second.TunnelAddr != first.TunnelAddr || second.Dir != first.Dir {
		t.Errorf("restart moved: %s %s, was %s %s", second.TunnelAddr, second.Dir, first.TunnelAddr, first.Dir)
	}
	if now, err := os.ReadFile(meta); err != nil || !bytes.Equal(now, recorded) {
		t.Errorf("a restart rewrote metadata.yaml (%v)", err)
	}
	checkHealthy(t, world(t, second, argv))
	if info, err := os.Stat(filepath.Join(first.ConfigDir, "instances", instance, "fatline", "ca.key")); err != nil || info.Mode().Perm() != 0 {
		t.Errorf("ca.key after a restart: %v, %v", info, err)
	}

	if _, err := rehearsal.Start(t.Context(), o); err == nil || !strings.Contains(err.Error(), "is in use") {
		t.Errorf("a third Start while the second runs: %v; want 'is in use'", err)
	}
	other := o
	other.Scenario = rehearsal.ScenarioSealed
	if _, err := rehearsal.Start(t.Context(), other); err == nil || !strings.Contains(err.Error(), "farcast-rehearsal scenario") {
		t.Errorf("a restart with another scenario: %v", err)
	}
	other = o
	other.Tools = "/usr/bin/true"
	if _, err := rehearsal.Start(t.Context(), other); err == nil || !strings.Contains(err.Error(), "do not link to") {
		t.Errorf("a restart with other tools: %v", err)
	}
}

// TestLedgerIgnoresTheCalendar: the first of a month still shows spending
// split, and a rehearsal past its period refuses every read.
func TestLedgerIgnoresTheCalendar(t *testing.T) {
	s := spec(t)
	now := time.Date(2026, 12, 1, 0, 30, 0, 0, time.UTC)
	s.Started = now.Add(-time.Hour)
	args := []string{"get", "configmap", kernel.DefaultCheckpointName, "-n", fldeploy.DefaultNamespace, "--ignore-not-found", "-o", "json"}
	out, ok := rehearsal.ClusterAnswer(s, args, now)
	if !ok {
		t.Fatal("no checkpoint on the first of a month")
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(out, &cm); err != nil {
		t.Fatal(err)
	}
	var cp kernel.Checkpoint
	if err := json.Unmarshal([]byte(cm.Data[kernel.CheckpointKey()]), &cp); err != nil {
		t.Fatal(err)
	}
	ledger, err := cost.Restore(cp.Ledger)
	if err != nil {
		t.Fatalf("cost.Restore: %v", err)
	}
	if n := len(ledger.Snapshot().Confirmations); n != 1 {
		t.Errorf("%d confirmations, want 1", n)
	}
	if a := ledger.Accrued(); !a.HasConfirmation || a.Calibration != 1 || a.Confirmed <= 0 || a.Expected <= 0 {
		t.Errorf("accrual on the first of a month: %+v", a)
	}
	late := s.Started.Add(25*24*time.Hour + time.Hour)
	if _, ok := rehearsal.ClusterAnswer(s, args, late); ok {
		t.Error("a checkpoint past the period")
	}

	home := t.TempDir()
	rig := startRig(t, rehearsal.Options{Home: home})
	editSpec(t, rig.Dir, func(s *rehearsal.Spec) { s.Started = time.Now().UTC().Add(-25*24*time.Hour - time.Hour) })
	code, stdout, errOut := runTool(filepath.Join(rig.KubeBin, "kubectl"), kubectlArgs(rig, namespaceRead...), kubectlEnv(t, rig))
	if code != 1 || stdout != "" || !strings.Contains(errOut, "older than its 30-day period") {
		t.Errorf("an expired rehearsal: exit %d, %q, %q", code, stdout, errOut)
	}
	if err := rig.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := rehearsal.Start(t.Context(), rehearsal.Options{Dir: rig.Dir, Home: home, Tools: testBinary(t)}); err == nil ||
		!strings.Contains(err.Error(), "older than its 30-day period") {
		t.Errorf("a restart of an expired rehearsal: %v", err)
	}
}

// TestTheLevelIsTheLedgersOwn: on every read of a rehearsal's life, every
// scenario's level is what the kernel's own assessment makes of its ledger —
// never a level set beside a total that contradicts it (phase 7, F6). The
// scenarios at the limit are over it from their first read to their last,
// with the calibration still exactly one; every other scenario is well under.
func TestTheLevelIsTheLedgersOwn(t *testing.T) {
	s := spec(t)
	args := []string{"get", "configmap", kernel.DefaultCheckpointName, "-n", fldeploy.DefaultNamespace, "--ignore-not-found", "-o", "json"}
	for _, name := range rehearsal.Scenarios() {
		s.Scenario = name
		// A rehearsal lives between 24 and 25 days: its period starts at the
		// midnight five days before it did.
		for _, after := range []time.Duration{0, time.Hour, 12 * 24 * time.Hour, 24 * 24 * time.Hour} {
			now := s.Started.Add(after)
			out, ok := rehearsal.ClusterAnswer(s, args, now)
			if !ok {
				t.Fatalf("%s, %s in: no checkpoint", name, after)
			}
			var cm struct {
				Data map[string]string `json:"data"`
			}
			var cp kernel.Checkpoint
			if err := json.Unmarshal(out, &cm); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(cm.Data[kernel.CheckpointKey()]), &cp); err != nil {
				t.Fatal(err)
			}
			ledger, err := cost.Restore(cp.Ledger)
			if err != nil {
				t.Fatal(err)
			}
			a := ledger.Accrued()
			if a.Calibration != 1 || len(a.Discrepancies) != 0 {
				t.Errorf("%s, %s in: calibration %v, discrepancies %v", name, after, a.Calibration, a.Discrepancies)
			}
			_, end := ledger.Period()
			if want := cost.Assess(a.Total, cp.Observed.Limit, cp.Observed.RateHourlyUSD, now, end).Level.String(); cp.Observed.Level != want {
				t.Errorf("%s, %s in: level %q, and the ledger assesses %q", name, after, cp.Observed.Level, want)
			}
			atLimit := name == rehearsal.ScenarioCostReached || name == rehearsal.ScenarioAtFloor
			switch {
			case cp.Observed.Limit != 50:
				t.Errorf("%s, %s in: limit %v, want the record's 50", name, after, cp.Observed.Limit)
			case atLimit && (a.Total < cp.Observed.Limit || cp.Observed.Level != cost.LevelReached.String()):
				t.Errorf("%s, %s in: total %.2f of %v, level %q; a kernel at its limit is over it", name, after, a.Total, cp.Observed.Limit, cp.Observed.Level)
			case !atLimit && cp.Observed.Level != cost.LevelOK.String():
				t.Errorf("%s, %s in: level %q, total %.2f; only the scenarios at the limit approach it", name, after, cp.Observed.Level, a.Total)
			}
		}
	}
}

// TestKeyholdersAnswerStateOnly: through the tunnel, as the operator, the
// keyholders answer GET /v1/state and refuse everything else — and each
// refusal is a calls.log line, which is how the walk sees that a read never
// asked for more.
func TestKeyholdersAnswerStateOnly(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	id, err := config.Dir(rig.ConfigDir).LoadDialIdentity(instance)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(id.ClientCertPEM, id.ClientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(id.CACertPEM)
	conn, err := tunnel.Connect(t.Context(), "https://"+rig.TunnelAddr, tunnel.ClientIdentity{
		Cert: cert, CA: pool, ServerName: identity.ServerName(instance),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	kh, err := keyholder.New(conn, instance, id.CACertPEM, id.ClientCertPEM, id.ClientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		st, err := kh.State(t.Context(), i)
		if err != nil || st.Phase != "unsealed" || st.Generation != 7 {
			t.Errorf("replica %d: %+v, %v", i, st, err)
		}
	}
	if err := rehearsal.SetScenario(rig.Dir, rehearsal.ScenarioSealed); err != nil {
		t.Fatal(err)
	}
	if st, err := kh.State(t.Context(), 1); err != nil || !st.Sealed() {
		t.Errorf("replica 1 in sealed: %+v, %v", st, err)
	}
	if n := len(calls(t, rig)); n != 0 {
		t.Fatalf("state reads were logged as refusals: %v", calls(t, rig))
	}
	if _, err := kh.Seal(t.Context(), 0, false, ""); err == nil {
		t.Error("a keyholder accepted a seal")
	}
	if _, err := kh.ReleaseHold(t.Context(), 1); err == nil {
		t.Error("a keyholder accepted a hold release")
	}
	lines := calls(t, rig)
	if len(lines) != 2 || !strings.Contains(lines[0], " keyholder POST /v1/seal") || !strings.HasSuffix(lines[0], " | refused") ||
		!strings.Contains(lines[1], " keyholder POST /v1/release-hold | refused") {
		t.Errorf("calls.log: %q", lines)
	}
}

// TestTheRehearsalKeeperIsEnrolledByRequest: the harness's keeper is enrolled
// as a real one is since ADR 0020. Its key was made for its request, the CA
// certified that key as a keeper leaf binding the bundle, and the key is the
// harness's alone: nothing under the instance's config directory holds it.
// A rehearsal made before ADR 0020 has an Ed25519 CA, and a restart over one
// is refused.
func TestTheRehearsalKeeperIsEnrolledByRequest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "r")
	o := rehearsal.Options{Dir: dir, Home: t.TempDir(), Tools: testBinary(t)}
	rig, err := rehearsal.Start(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rig.Close() })

	harness := filepath.Join(rig.Dir, "harness")
	certPEM, err := os.ReadFile(filepath.Join(harness, "keeper-phone.crt"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(harness, "keeper-phone.key"))
	if err != nil {
		t.Fatal(err)
	}
	keyFP := privateKeyFingerprint(t, keyPEM)
	if keyFP == "" {
		t.Fatal("keeper-phone.key holds no private key")
	}
	certFP, err := identity.CertKeyFingerprint(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if certFP != keyFP {
		t.Errorf("the keeper's certificate certifies %s; its key is %s", certFP, keyFP)
	}
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var uris []string
	for _, u := range leaf.URIs {
		uris = append(uris, u.String())
	}
	want := []string{identity.KeeperURI(instance, "phone"), identity.KeeperBundleURIPrefix + identity.KeeperBundleDigest([]byte("rehearsal-bundle"))}
	if !slices.Equal(uris, want) {
		t.Errorf("the keeper's leaf names %v; want %v", uris, want)
	}
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("the keeper's key is %T, not ECDSA", leaf.PublicKey)
	}

	// Nothing under the instance's config directory holds that key.
	inst := filepath.Join(rig.ConfigDir, "instances", instance)
	walked := 0
	if err := filepath.WalkDir(inst, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil // ca.key and keys.yaml are mode 000, and are not the keeper's
		}
		walked++
		if bytes.Contains(data, keyPEM) || (bytes.Contains(data, []byte("PRIVATE KEY")) && privateKeyFingerprint(t, data) == keyFP) {
			t.Errorf("%s holds the keeper's private key", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if walked == 0 {
		t.Fatal("guard: the walk read nothing")
	}

	// A rehearsal from before ADR 0020: an Ed25519 CA. A restart refuses it.
	if err := rig.Close(); err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "FarCast Instance CA: " + instance},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, edKey.Public(), edKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inst, "fatline", "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if again, err := rehearsal.Start(t.Context(), o); err == nil {
		_ = again.Close()
		t.Error("a restart over an Ed25519 CA started")
	} else if !strings.Contains(err.Error(), "ADR 0020") || !strings.Contains(err.Error(), "start a new one") {
		t.Errorf("a restart over an Ed25519 CA = %v; want it refused, saying to start a new one", err)
	}
}

// privateKeyFingerprint is the fingerprint of the first PKCS#8 key in data, or
// "" when there is none.
func privateKeyFingerprint(t *testing.T, data []byte) string {
	t.Helper()
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return ""
		}
		if block.Type != "PRIVATE KEY" {
			continue
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			continue
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			continue
		}
		fp, err := identity.KeyFingerprint(s.Public())
		if err != nil {
			t.Fatal(err)
		}
		return fp
	}
}
