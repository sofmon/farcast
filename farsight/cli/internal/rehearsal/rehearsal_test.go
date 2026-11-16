package rehearsal_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/url"
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
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/rehearsal"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/technocore/cost"
	"github.com/sofmon/farcast/technocore/kernel"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

const instance = rehearsal.DefaultInstance

// startRig starts a rehearsal in a new directory under a fake home, and stops
// it when the test ends.
func startRig(t *testing.T, o rehearsal.Options) *rehearsal.Rig {
	t.Helper()
	if o.Dir == "" {
		o.Dir = filepath.Join(t.TempDir(), "r")
	}
	if o.Home == "" {
		o.Home = t.TempDir()
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

// shellNoise are variables a developer's shell may export, none of which the
// FarCast app passes on: its child environment is HOME, TMPDIR, LANG, LC_*
// and a PATH of the system's directories (FarSightKit's ChildEnvironment).
// cli.Main runs in process, with this test's environment, so the rig removes
// them, and the environment rehearsed is the app's, not whatever the
// developer's shell holds. plant then adds back what must make no difference.
var shellNoise = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "no_proxy",
	"FARCAST_CONFIG_HOME", "CLOUDSDK_CONFIG", "KUBECONFIG",
}

// asTheApp gives this process the environment the FarCast app gives farcast
// — PATH and HOME, and no CLOUDSDK_CONFIG — after removing what a developer's
// shell may export. Every test that runs cli.Main calls it. The variables
// must be absent, not empty.
//
// cli.Main changes this process's environment for good: it sets
// GOOGLE_API_USE_CLIENT_CERTIFICATE=false and unsets
// GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES (ADR 0023 decision 1). t.Setenv
// records both first, so each test leaves them as it found them.
func asTheApp(t *testing.T, rig *rehearsal.Rig) {
	t.Helper()
	for _, k := range shellNoise {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []string{"GOOGLE_API_USE_CLIENT_CERTIFICATE", "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"} {
		t.Setenv(k, "")
		if err := os.Unsetenv(k); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", rig.Path())
	t.Setenv("HOME", t.TempDir())
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

// sectionMessage is a section's error message, "" when it has none.
func (d worldDoc) sectionMessage(name string) string {
	if s, ok := d.Sections[name]; ok && s.Error != nil {
		return s.Error.Message
	}
	return ""
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

// sections checks that each named section is what want says.
func (d worldDoc) sections(t *testing.T, scenario, want string, names ...string) {
	t.Helper()
	for _, s := range names {
		if got := d.sectionKind(s); got != want {
			t.Errorf("%s: section %s is %s, want %s (%s)", scenario, s, got, want, d.sectionMessage(s))
		}
	}
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

// callLine is one calls.log line of the cluster or its token endpoint:
// "<time> <who> <METHOD> <target> as <identity> | <outcome>".
type callLine struct {
	who, method, target, as, outcome string
}

// parseCall reads a cluster or token line; ok is false for any other.
func parseCall(l string) (callLine, bool) {
	head, outcome, ok := strings.Cut(l, " | ")
	if !ok {
		return callLine{}, false
	}
	f := strings.Fields(head)
	if len(f) != 6 || (f[1] != "cluster" && f[1] != "token") || f[4] != "as" {
		return callLine{}, false
	}
	if _, err := time.Parse(time.RFC3339, f[0]); err != nil {
		return callLine{}, false
	}
	return callLine{who: f[1], method: f[2], target: f[3], as: f[5], outcome: outcome}, true
}

// clusterCalls are calls.log's cluster lines (not the token endpoint's).
func clusterCalls(t *testing.T, rig *rehearsal.Rig) []callLine {
	t.Helper()
	var out []callLine
	for _, l := range calls(t, rig) {
		if c, ok := parseCall(l); ok && c.who == "cluster" {
			out = append(out, c)
		}
	}
	return out
}

func checkHealthy(t *testing.T, doc worldDoc) {
	t.Helper()
	doc.sections(t, "healthy", "read", "spend", "apps", "policy", "network", "seal")
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
// on, and that must make no difference to how farcast reads: it mints the
// reader's token itself, reads no gcloud or kube configuration, and its
// transports take no proxy. HTTPS_PROXY proves nothing on loopback, which
// Go's environment proxying never proxies; kube's TestTransportsHaveNoProxy
// carries that guarantee.
func plant(t *testing.T) []string {
	t.Helper()
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	for k, v := range map[string]string{
		"CLOUDSDK_AUTH_ACCESS_TOKEN":     "planted-token",
		"CLOUDSDK_CORE_ACCOUNT":          "someone@work.invalid",
		"CLOUDSDK_ACTIVE_CONFIG_NAME":    "work",
		"CLOUDSDK_CONFIG":                filepath.Join(elsewhere, "gcloud"),
		"KUBECONFIG":                     filepath.Join(elsewhere, "kubeconfig"),
		"GOOGLE_APPLICATION_CREDENTIALS": filepath.Join(elsewhere, "credentials.json"),
		"HTTPS_PROXY":                    "http://127.0.0.1:9",
	} {
		t.Setenv(k, v)
	}
	return []string{"planted", "someone@work.invalid", "elsewhere", "127.0.0.1:9", "CLOUDSDK_AUTH_ACCESS_TOKEN",
		"CLOUDSDK_CORE_ACCOUNT", "GOOGLE_APPLICATION_CREDENTIALS"}
}

// worldsReads are the cluster reads one healthy 'world' makes, as calls.log
// spells them.
func worldsReads() []string {
	cm := "/api/v1/namespaces/farcast-system/configmaps/"
	return []string{
		"/apis/apps/v1/namespaces/farcast-system/deployments?limit=500",
		"/apis/apps/v1/namespaces/farcast-system/statefulsets?limit=500",
		"/apis/apps/v1/namespaces/shop/deployments?limit=500",
		"/apis/apps/v1/namespaces/shop/statefulsets?limit=500",
		"/api/v1/namespaces?labelSelector=app.kubernetes.io%2Fmanaged-by%3Dfarcast&limit=500",
		cm + kernel.DefaultNamespacesName,
		cm + kernel.DefaultCheckpointName,
		cm + fldeploy.PolicyConfigMap,
	}
}

// TestWorldReadsTheRehearsalWhole is the rehearsal end to end: the real
// 'farcast version', 'instances' and 'world', run with the app's own argv
// and the app's environment, planted variables included, read every section;
// and the cluster saw only world's reads, each as the reader.
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
			Name     string `json:"name"`
			Reader   string `json:"reader"`
			Migrated bool   `json:"migrated"`
			Status   string `json:"status"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		t.Fatal(err)
	}
	if list.Schema != 2 || len(list.Instances) != 1 || list.Instances[0].Name != instance ||
		list.Instances[0].Reader != "granted" || !list.Instances[0].Migrated || list.Instances[0].Status != "running" {
		t.Fatalf("instances: %s", out)
	}
	if n := len(calls(t, rig)); n != 0 {
		t.Fatalf("version and instances read files only, yet calls.log has %d lines", n)
	}

	checkHealthy(t, world(t, rig, argv))

	reads, mints := 0, 0
	for _, l := range calls(t, rig) {
		c, ok := parseCall(l)
		switch {
		case !ok:
			t.Errorf("a calls.log line that is neither the cluster's nor the token endpoint's: %s", l)
		case c.as != "reader" || c.outcome != "ok":
			t.Errorf("a call not made as the reader, or not answered: %s", l)
		case c.who == "token":
			mints++
			if c.method != http.MethodPost || c.target != "/token" {
				t.Errorf("a token call that is not a POST of /token: %s", l)
			}
		default:
			reads++
			if c.method != http.MethodGet || !slices.Contains(worldsReads(), c.target) {
				t.Errorf("a cluster call that is not one of world's reads: %s", l)
			}
		}
		for _, p := range planted {
			if strings.Contains(l, p) {
				t.Errorf("calls.log names %q: %s", p, l)
			}
		}
	}
	if reads != len(worldsReads()) || mints != 1 {
		t.Errorf("world made %d reads and %d mints; want each of its %d reads once, and one mint", reads, mints, len(worldsReads()))
	}
}

// TestTheRecordIsTheLoopbackReaders: the instance record is what 'farcast
// reader init', 'record' and 'grant' leave on a loopback cluster (§10.1): the
// cluster's endpoint on 127.0.0.1 and the CA it is trusted on, the derived
// loopback reader with a 40-hex key id, granted when the rehearsal started,
// its key and certificate at 0600, server-side apply recorded, and a writer
// credentials.yaml whose token_uri is the cluster's. Nothing of the gcloud
// era is written: no kubeconfig, no gcloud directory, no tools.
func TestTheRecordIsTheLoopbackReaders(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	s, err := rehearsal.LoadSpec(rig.Dir)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := config.Dir(rig.ConfigDir).LoadInstanceMetadata(instance)
	if err != nil {
		t.Fatal(err)
	}
	// farcast-reader- and the first 8 hex characters of the name's SHA-256,
	// as cli's readerName derives it: 2bcd3e14 for "rehearsal".
	if want := "farcast-reader-2bcd3e14@rehearsal.invalid"; meta.Reader == nil || meta.Reader.Email != want {
		t.Fatalf("reader %+v, want %s", meta.Reader, want)
	}
	if r := meta.Reader; len(r.KeyID) != 40 || strings.Trim(r.KeyID, "0123456789abcdef") != "" || !r.GrantedAt.Equal(s.Started) {
		t.Errorf("reader %+v: want a 40-hex key id, granted when the rehearsal started (%s)", r, s.Started)
	}
	if meta.Endpoint != rig.ClusterAddr || meta.Region != "rehearsal-local" || meta.Project != rehearsal.DefaultProject {
		t.Errorf("endpoint %q, region %q, project %q", meta.Endpoint, meta.Region, meta.Project)
	}
	if ssa := meta.ServerSideApply; ssa == nil || !ssa.Since.Equal(s.Started) || ssa.Farcast != "rehearsal" {
		t.Errorf("server_side_apply %+v", ssa)
	}
	for _, f := range []string{"reader.key", "reader.crt", "cluster-ca.crt", "credentials.yaml"} {
		if info, err := os.Stat(instanceFile(rig, f)); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v, %v; want it, 0600", f, info, err)
		}
	}
	creds, err := config.Dir(rig.ConfigDir).LoadInstanceCredentials(instance)
	if err != nil {
		t.Fatal(err)
	}
	var key map[string]string
	if err := json.Unmarshal([]byte(creds.ServiceAccountKey), &key); err != nil {
		t.Fatal(err)
	}
	if len(key) != 4 || key["type"] != "service_account" || key["client_email"] != "writer@rehearsal.invalid" ||
		key["token_uri"] != "https://"+rig.ClusterAddr+"/token" || !strings.Contains(key["private_key"], "PRIVATE KEY") {
		t.Errorf("credentials.yaml's key has %d fields: type %q, client_email %q, token_uri %q", len(key), key["type"], key["client_email"], key["token_uri"])
	}
	for _, gone := range []string{"kube", "sdk", "gcloud", filepath.Join("config", "instances", instance, "kubeconfig.yaml")} {
		if _, err := os.Lstat(filepath.Join(rig.Dir, gone)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: %v; a rehearsal writes none", gone, err)
		}
	}
}

// waitFor polls cond every 20 ms until it holds, for at most 10 seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within 10s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// listening reports whether something accepts on addr.
func listening(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// TestScenariosShowInWorld switches each scenario and reads the very next
// world, with no waiting, except tunnel-down, which takes effect within a
// moment: its read waits until the tunnel's port refuses.
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
	cluster := []string{"spend", "apps", "policy"}
	tunnelSections := []string{"network", "seal"}

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

	set(rehearsal.ScenarioTokenRefused)
	doc = world(t, rig, argv)
	doc.sections(t, "token-refused", "credential_refused", cluster...)
	doc.sections(t, "token-refused", "read", tunnelSections...)

	set(rehearsal.ScenarioUnauthorized)
	doc = world(t, rig, argv)
	doc.sections(t, "unauthorized", "unauthorized", cluster...)
	doc.sections(t, "unauthorized", "read", tunnelSections...)

	// Only the checkpoint and the policy are refused: the metered-namespace
	// list still answers, so apps reads.
	set(rehearsal.ScenarioForbidden)
	doc = world(t, rig, argv)
	doc.sections(t, "forbidden", "forbidden", "spend", "policy")
	doc.sections(t, "forbidden", "read", "apps", "network", "seal")
	for _, s := range []string{"spend", "policy"} {
		if m := doc.sectionMessage(s); !strings.HasSuffix(m, "; run 'farcast reader grant "+instance+"'") {
			t.Errorf("forbidden: section %s says %q; an RBAC refusal says to run 'farcast reader grant'", s, m)
		}
	}

	set(rehearsal.ScenarioReaderMissing)
	doc = world(t, rig, argv)
	doc.sections(t, "reader-missing", "credential_missing", cluster...)
	doc.sections(t, "reader-missing", "read", tunnelSections...)
	code, out, errOut := farcast(t, rig, argv.Instances)
	if code != 0 || errOut != "" || !strings.Contains(string(out), `"reader":"key_missing"`) {
		t.Errorf("reader-missing: instances exited %d: %s %s; want the reader's key missing", code, out, errOut)
	}

	// Every other scenario puts the reader's key back: this read's cluster
	// sections read. The tunnel stops within a moment.
	set(rehearsal.ScenarioTunnelDown)
	waitFor(t, "the tunnel stopping", func() bool { return !listening(rig.TunnelAddr) })
	doc = world(t, rig, argv)
	doc.sections(t, "tunnel-down", "tunnel_unreachable", tunnelSections...)
	doc.sections(t, "tunnel-down", "read", cluster...)
	if !listening(rig.ClusterAddr) {
		t.Error("tunnel-down stopped the cluster too")
	}

	// And every other scenario brings the tunnel back.
	set(rehearsal.ScenarioDenied)
	waitFor(t, "the tunnel listening again", func() bool { return listening(rig.TunnelAddr) })
	doc = world(t, rig, argv)
	denied := false
	for _, a := range doc.Alerts {
		denied = denied || (a.Kind == "denied" && a.Subject["app"] == "shop/web")
	}
	if !denied || !doc.hasLine("egress", "app", "shop/web", "host", "tracker.invalid", "denied") {
		t.Errorf("denied: alerts %+v, lines %+v", doc.Alerts, doc.Lines)
	}
	doc.sections(t, "denied", "read", "spend", "apps", "policy", "network", "seal")
}

// TestAScenarioThatMovesSomethingStartsThatWay: a rehearsal started in
// tunnel-down still brings its tunnel up for the keeper's start-up read, and
// Start returns with it stopped; one started in reader-missing writes its
// reader's key aside from the first.
func TestAScenarioThatMovesSomethingStartsThatWay(t *testing.T) {
	t.Run("tunnel-down", func(t *testing.T) {
		rig := startRig(t, rehearsal.Options{Scenario: rehearsal.ScenarioTunnelDown})
		if listening(rig.TunnelAddr) {
			t.Error("Start returned with the tunnel listening in tunnel-down")
		}
		if err := rehearsal.SetScenario(rig.Dir, rehearsal.ScenarioHealthy); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the tunnel listening", func() bool { return listening(rig.TunnelAddr) })
		argv := loadArgv(t)
		asTheApp(t, rig)
		checkHealthy(t, world(t, rig, argv))
	})
	t.Run("reader-missing", func(t *testing.T) {
		rig := startRig(t, rehearsal.Options{Scenario: rehearsal.ScenarioReaderMissing})
		inst := filepath.Join(rig.ConfigDir, "instances", instance)
		if _, err := os.Stat(filepath.Join(inst, "reader.key")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("reader.key: %v; want it moved aside", err)
		}
		if info, err := os.Stat(filepath.Join(inst, "reader.key.away")); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("reader.key.away: %v, %v; want the key there, 0600", info, err)
		}
	})
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
	doc.sections(t, "at-floor", "read", "spend", "apps", "policy", "network", "seal")
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

// instanceFile is a file in the rehearsal instance's config directory.
func instanceFile(rig *rehearsal.Rig, name string) string {
	return filepath.Join(rig.ConfigDir, "instances", instance, name)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// clusterClient is an HTTPS client that trusts the rig's cluster on its
// cluster-ca.crt, as farcast does, and takes no proxy.
func clusterClient(t *testing.T, rig *rehearsal.Rig) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(readFile(t, instanceFile(rig, "cluster-ca.crt"))) {
		t.Fatal("cluster-ca.crt holds no certificate")
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
}

// rsaKey is the first PKCS#8 RSA key in keyPEM.
func rsaKey(t *testing.T, keyPEM []byte) *rsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := k.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("a %T, not an RSA key", k)
	}
	return key
}

// theReader is the rehearsal instance's reader: its key and its email, as
// the record holds them.
func theReader(t *testing.T, rig *rehearsal.Rig) (*rsa.PrivateKey, string) {
	t.Helper()
	meta, err := config.Dir(rig.ConfigDir).LoadInstanceMetadata(instance)
	if err != nil || meta.Reader == nil {
		t.Fatalf("the rehearsal's reader: %+v, %v", meta, err)
	}
	return rsaKey(t, readFile(t, instanceFile(rig, "reader.key"))), meta.Reader.Email
}

// theWriter is the writer credentials.yaml holds.
func theWriter(t *testing.T, rig *rehearsal.Rig) kube.Credential {
	t.Helper()
	creds, err := config.Dir(rig.ConfigDir).LoadInstanceCredentials(instance)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := kube.ParseServiceAccountJSON([]byte(creds.ServiceAccountKey))
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// claimsFor are the claims of a 2LO assertion for iss, as the vendored
// encoder writes them for kube's client (kube.TokenScopes, space-separated),
// aimed at the rig's token endpoint.
func claimsFor(rig *rehearsal.Rig, iss string) map[string]any {
	now := time.Now().Unix()
	return map[string]any{
		"iss": iss, "scope": strings.Join(kube.TokenScopes(), " "), "aud": "https://" + rig.ClusterAddr + "/token",
		"iat": now - 10, "exp": now + 3590,
	}
}

// assertion is a JWT the claims make, signed RS256 with key.
func assertion(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(body)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc.EncodeToString(sig)
}

// mint posts an assertion to the rig's token endpoint and returns the status,
// the token minted, and the OAuth error when it refused.
func mint(t *testing.T, rig *rehearsal.Rig, a string) (status int, token, refusal string) {
	t.Helper()
	resp, err := clusterClient(t, rig).PostForm("https://"+rig.ClusterAddr+"/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {a},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var answer struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		t.Fatalf("the token endpoint's answer: %v", err)
	}
	return resp.StatusCode, answer.AccessToken, answer.Error
}

// readerToken is a token minted for the rehearsal's reader.
func readerToken(t *testing.T, rig *rehearsal.Rig) string {
	t.Helper()
	key, email := theReader(t, rig)
	code, token, refusal := mint(t, rig, assertion(t, key, claimsFor(rig, email)))
	if code != http.StatusOK || token == "" {
		t.Fatalf("the reader's mint: %d %s", code, refusal)
	}
	return token
}

// ask sends one request to the rig's cluster with a bearer token ("" for
// none) and returns the status and the answer's kind ("Status" for a
// refusal, the list's or object's kind otherwise).
func ask(t *testing.T, rig *rehearsal.Rig, method, target, token string) (int, string) {
	t.Helper()
	var body io.Reader
	if method != http.MethodGet && method != http.MethodDelete {
		body = strings.NewReader("{}")
	}
	req, err := http.NewRequestWithContext(t.Context(), method, "https://"+rig.ClusterAddr+target, body)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := clusterClient(t, rig).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var answer struct {
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		t.Fatalf("%s %s: the answer is not JSON: %v", method, target, err)
	}
	return resp.StatusCode, answer.Kind
}

// TestTheRigAnswersOnlyWorldsReads: with the reader's token, world's reads
// are answered, an absent farcast-system ConfigMap with a 404 Status; every
// other request is 405 and a "refused: no answer" line. A request with no
// token, or one the cluster never minted, is 401.
func TestTheRigAnswersOnlyWorldsReads(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	s, err := rehearsal.LoadSpec(rig.Dir)
	if err != nil {
		t.Fatal(err)
	}
	token := readerToken(t, rig)
	for _, target := range worldsReads() {
		if code, kind := ask(t, rig, http.MethodGet, target, token); code != http.StatusOK || kind == "Status" {
			t.Errorf("GET %s: %d %s; want it answered", target, code, kind)
		}
	}
	absent := "/api/v1/namespaces/farcast-system/configmaps/something-else"
	if code, kind := ask(t, rig, http.MethodGet, absent, token); code != http.StatusNotFound || kind != "Status" {
		t.Errorf("an absent ConfigMap: %d %s; want a 404 Status", code, kind)
	}

	cm := "/api/v1/namespaces/farcast-system/configmaps"
	deployments := "/apis/apps/v1/namespaces/shop/deployments"
	selector := "labelSelector=app.kubernetes.io%2Fmanaged-by%3Dfarcast"
	refused := []struct{ method, target string }{
		{http.MethodPost, cm + "?fieldManager=farcast"},
		{http.MethodPatch, cm + "/" + kernel.DefaultCheckpointName + "?fieldManager=farcast"},
		{http.MethodPut, cm + "/" + kernel.DefaultCheckpointName},
		{http.MethodDelete, cm + "/" + kernel.DefaultCheckpointName},
		{http.MethodGet, cm + "?limit=500"},
		{http.MethodGet, cm + "/" + kernel.DefaultCheckpointName + "?resourceVersion=0"},
		{http.MethodGet, "/api/v1/namespaces/shop/configmaps/" + kernel.DefaultCheckpointName},
		{http.MethodGet, "/api/v1/namespaces/farcast-system/secrets?limit=500"},
		{http.MethodGet, "/api/v1/secrets?limit=500"},
		{http.MethodGet, "/api/v1/namespaces/shop/pods?limit=500"},
		{http.MethodGet, "/api/v1/namespaces/shop/pods/api-0/log"},
		{http.MethodGet, deployments + "?limit=500&continue=abc"},
		{http.MethodGet, deployments + "?limit=500&watch=true"},
		{http.MethodGet, deployments + "?limit=500&limit=1"},
		{http.MethodGet, deployments + "/api"},
		{http.MethodGet, "/apis/apps/v1/namespaces/shop/replicasets?limit=500"},
		{http.MethodGet, "/apis/apps/v1/deployments?limit=500"},
		{http.MethodGet, "/api/v1/namespaces?limit=500"},
		{http.MethodGet, "/api/v1/namespaces?labelSelector=app.kubernetes.io%2Fmanaged-by%3Dsomeone&limit=500"},
		{http.MethodGet, "/api/v1/namespaces?" + selector + "&" + selector},
		{http.MethodGet, "/api/v1/namespaces?" + selector + "&continue=abc"},
		{http.MethodGet, "/version"},
	}
	for _, r := range refused {
		if code, kind := ask(t, rig, r.method, r.target, token); code != http.StatusMethodNotAllowed || kind != "Status" {
			t.Errorf("%s %s: %d %s; want a 405 Status", r.method, r.target, code, kind)
		}
		u, err := url.Parse(r.target)
		if err != nil {
			t.Fatal(err)
		}
		if code, _ := rehearsal.ClusterAnswer(s, r.method, u.Path, u.RawQuery, time.Now()); code != http.StatusMethodNotAllowed {
			t.Errorf("ClusterAnswer answered %s %s with %d", r.method, r.target, code)
		}
	}

	if code, _ := ask(t, rig, http.MethodGet, worldsReads()[0], ""); code != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", code)
	}
	if code, _ := ask(t, rig, http.MethodGet, worldsReads()[0], "not-a-token-it-minted"); code != http.StatusUnauthorized {
		t.Errorf("a token it never minted: %d, want 401", code)
	}

	got := map[string]int{}
	for _, c := range clusterCalls(t, rig) {
		got[c.as+" | "+c.outcome]++
	}
	want := map[string]int{
		"reader | ok":                                    len(worldsReads()) + 1,
		"reader | refused: no answer":                    len(refused),
		"none | refused: no token the cluster minted":    1,
		"unknown | refused: no token the cluster minted": 1,
	}
	if !maps.Equal(got, want) {
		t.Errorf("calls.log's cluster lines, by identity and outcome: %v, want %v", got, want)
	}
	for _, l := range calls(t, rig) {
		if strings.Contains(l, token) || strings.Contains(l, "not-a-token-it-minted") {
			t.Errorf("calls.log holds a token: %s", l)
		}
	}
}

// TestTheRigRefusesAWriterTokenOnARead: the writer credentials.yaml holds
// mints, and every request its token makes is refused with a 403 Status,
// world's reads included and whatever else it asks: the writer is checked
// before anything is answered.
func TestTheRigRefusesAWriterTokenOnARead(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	ep, err := kube.ParseEndpoint(rig.ClusterAddr, "", readFile(t, instanceFile(rig, "cluster-ca.crt")))
	if err != nil {
		t.Fatal(err)
	}
	writer := theWriter(t, rig)
	kc, err := kube.New(kube.Config{Endpoint: ep, Credential: writer, Identity: kube.Writer})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	forbidden := func(what string, err error) {
		t.Helper()
		var ae *kube.APIError
		if !errors.Is(err, tkube.ErrForbidden) || !errors.As(err, &ae) || !ae.KubernetesStatus {
			t.Errorf("%s as the writer: %v; want a 403 Kubernetes Status", what, err)
		}
	}
	_, err = kc.GetConfigMap(ctx, fldeploy.DefaultNamespace, kernel.DefaultCheckpointName)
	forbidden("the checkpoint", err)
	_, err = kc.ListNamespaces(ctx, "app.kubernetes.io/managed-by=farcast")
	forbidden("the namespaces", err)
	_, err = kc.ListDeployments(ctx, "shop")
	forbidden("shop's deployments", err)

	// Whatever it asks: a request the reader would get 405 for is 403 too.
	_, token, _ := mint(t, rig, assertion(t, rsaKey(t, writer.PrivateKeyPEM), claimsFor(rig, writer.Email)))
	if code, kind := ask(t, rig, http.MethodPost, "/api/v1/namespaces/farcast-system/configmaps", token); code != http.StatusForbidden || kind != "Status" {
		t.Errorf("a writer's POST: %d %s; want a 403 Status", code, kind)
	}

	writes := 0
	for _, l := range calls(t, rig) {
		c, ok := parseCall(l)
		switch {
		case !ok || c.as != "writer":
			t.Errorf("a line that is not the writer's: %s", l)
		case c.who == "token":
			if c.outcome != "ok" {
				t.Errorf("the writer's mint: %s", l)
			}
		case c.outcome != "refused: a writer token on a read":
			t.Errorf("a writer's request not refused as one: %s", l)
		default:
			writes++
		}
	}
	if writes != 4 {
		t.Errorf("calls.log refuses %d of the writer's requests, want 4", writes)
	}
}

// TestTheRigsTokenEndpointChecksTheAssertion: the token endpoint mints for an
// assertion the reader's or the writer's key signed, aimed at it, with
// kube.TokenScopes' two scopes (cloud-platform then userinfo.email), and
// refuses every other with invalid_grant, userinfo.email alone included; in
// token-refused it refuses the reader's too, and 'world' shows
// credential_refused. No calls.log line holds an assertion or a token.
func TestTheRigsTokenEndpointChecksTheAssertion(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	readerKey, readerEmail := theReader(t, rig)
	writer := theWriter(t, rig)
	writerKey := rsaKey(t, writer.PrivateKeyPEM)
	var sent []string
	try := func(what string, key *rsa.PrivateKey, claims map[string]any, wantCode int) string {
		t.Helper()
		a := assertion(t, key, claims)
		sent = append(sent, a)
		code, token, refusal := mint(t, rig, a)
		if code != wantCode {
			t.Errorf("%s: %d %s, want %d", what, code, refusal, wantCode)
		}
		if code != http.StatusOK && refusal != "invalid_grant" {
			t.Errorf("%s: refused with %q, want invalid_grant", what, refusal)
		}
		return token
	}

	token := try("the reader", readerKey, claimsFor(rig, readerEmail), http.StatusOK)
	if code, _ := ask(t, rig, http.MethodGet, worldsReads()[0], token); code != http.StatusOK {
		t.Errorf("the reader's token reads: %d", code)
	}
	try("the writer", writerKey, claimsFor(rig, writer.Email), http.StatusOK)
	with := func(iss, key string, value any) map[string]any {
		c := claimsFor(rig, iss)
		c[key] = value
		return c
	}
	try("an unregistered iss", readerKey, claimsFor(rig, "someone@rehearsal.invalid"), http.StatusBadRequest)
	try("the reader's iss under the writer's key", writerKey, claimsFor(rig, readerEmail), http.StatusBadRequest)
	try("another aud", readerKey, with(readerEmail, "aud", "https://oauth2.googleapis.com/token"), http.StatusBadRequest)
	try("userinfo.email alone", readerKey, with(readerEmail, "scope", kube.ScopeUserinfoEmail), http.StatusBadRequest)
	try("cloud-platform alone", readerKey, with(readerEmail, "scope", kube.ScopeCloudPlatform), http.StatusBadRequest)
	try("the two scopes in the reverse order", readerKey,
		with(readerEmail, "scope", kube.ScopeUserinfoEmail+" "+kube.ScopeCloudPlatform), http.StatusBadRequest)
	past := time.Now().Add(-2 * time.Hour).Unix()
	expired := claimsFor(rig, readerEmail)
	expired["iat"], expired["exp"] = past, past+3600
	try("an expired assertion", readerKey, expired, http.StatusBadRequest)

	if err := rehearsal.SetScenario(rig.Dir, rehearsal.ScenarioTokenRefused); err != nil {
		t.Fatal(err)
	}
	try("the reader in token-refused", readerKey, claimsFor(rig, readerEmail), http.StatusBadRequest)
	argv := loadArgv(t)
	asTheApp(t, rig)
	world(t, rig, argv).sections(t, "token-refused", "credential_refused", "spend", "apps", "policy")

	got := map[string]int{}
	for _, l := range calls(t, rig) {
		for _, a := range sent {
			if strings.Contains(l, a) || strings.Contains(l, strings.SplitN(a, ".", 2)[0]) {
				t.Errorf("calls.log holds an assertion: %s", l)
			}
		}
		if strings.Contains(l, token) {
			t.Errorf("calls.log holds a token: %s", l)
		}
		if c, ok := parseCall(l); ok && c.who == "token" {
			got[c.method+" "+c.target+" as "+c.as+" | "+c.outcome]++
		}
	}
	want := map[string]int{
		"POST /token as reader | ok":                                             1,
		"POST /token as writer | ok":                                             1,
		"POST /token as unknown | refused: the assertion did not verify":         7,
		"POST /token as reader | refused: token-refused refuses every assertion": 2,
	}
	if !maps.Equal(got, want) {
		t.Errorf("calls.log's token lines: %v, want %v", got, want)
	}
}

// TestRetiredScenariosAreRefused: signed-out and identity-mismatch went with
// the gcloud identity. Start and SetScenario each refuse them, saying what
// replaced them, and write nothing; any other name that is not a scenario
// says what the scenarios are.
func TestRetiredScenariosAreRefused(t *testing.T) {
	if got := rehearsal.RetiredScenarios(); !slices.Equal(got, []string{"signed-out", "identity-mismatch"}) {
		t.Fatalf("RetiredScenarios = %v", got)
	}
	rig := startRig(t, rehearsal.Options{})
	before := readFile(t, filepath.Join(rig.Dir, "rehearsal.json"))
	for _, name := range rehearsal.RetiredScenarios() {
		if slices.Contains(rehearsal.Scenarios(), name) {
			t.Errorf("%s is still a scenario", name)
		}
		want := fmt.Sprintf("scenario %q was retired with ADR 0023 M2; use token-refused or forbidden", name)
		if err := rehearsal.CheckScenario(name); err == nil || err.Error() != want {
			t.Errorf("CheckScenario(%q) = %v, want %q", name, err, want)
		}
		dir := filepath.Join(t.TempDir(), "r")
		if r, err := rehearsal.Start(t.Context(), rehearsal.Options{Dir: dir, Home: t.TempDir(), Scenario: name}); err == nil {
			_ = r.Close()
			t.Errorf("Start in %s started", name)
		} else if err.Error() != want {
			t.Errorf("Start in %s: %v, want %q", name, err, want)
		}
		if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Start in %s made its directory: %v", name, err)
		}
		if err := rehearsal.SetScenario(rig.Dir, name); err == nil || err.Error() != want {
			t.Errorf("SetScenario(%q) = %v, want %q", name, err, want)
		}
	}
	if after := readFile(t, filepath.Join(rig.Dir, "rehearsal.json")); !bytes.Equal(after, before) {
		t.Errorf("a refused scenario rewrote rehearsal.json:\n%s", after)
	}
	err := rehearsal.CheckScenario("no-such-scenario")
	if err == nil || !strings.HasPrefix(err.Error(), `unknown scenario "no-such-scenario"; the scenarios are healthy, `) {
		t.Errorf("an unknown name: %v", err)
	}
	for _, name := range rehearsal.Scenarios() {
		if err := rehearsal.CheckScenario(name); err != nil {
			t.Errorf("CheckScenario(%q) = %v", name, err)
		}
	}
}

// TestSlowClusterHoldsEveryAnswer: in slow-cluster the cluster holds an API
// read and a /token mint each for SlowSeconds (cut to 50 ms here); in any
// other scenario SlowSeconds holds nothing.
func TestSlowClusterHoldsEveryAnswer(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	key, email := theReader(t, rig)
	timed := func(f func()) time.Duration {
		start := time.Now()
		f()
		return time.Since(start)
	}

	editSpec(t, rig.Dir, func(s *rehearsal.Spec) { s.Scenario, s.SlowSeconds = rehearsal.ScenarioSlowCluster, 0.05 })
	var token string
	if took := timed(func() {
		var code int
		code, token, _ = mint(t, rig, assertion(t, key, claimsFor(rig, email)))
		if code != http.StatusOK {
			t.Fatalf("the slow mint: %d", code)
		}
	}); took < 50*time.Millisecond {
		t.Errorf("slow-cluster minted in %s; it holds /token first", took)
	}
	if took := timed(func() {
		if code, _ := ask(t, rig, http.MethodGet, worldsReads()[0], token); code != http.StatusOK {
			t.Fatalf("the slow read: %d", code)
		}
	}); took < 50*time.Millisecond {
		t.Errorf("slow-cluster answered in %s; it holds every read first", took)
	}
	if s, err := rehearsal.LoadSpec(rig.Dir); err != nil || s.SlowSeconds != 0.05 {
		t.Fatalf("the spec's slow_seconds: %v, %v", s.SlowSeconds, err)
	}

	editSpec(t, rig.Dir, func(s *rehearsal.Spec) { s.Scenario, s.SlowSeconds = rehearsal.ScenarioHealthy, 5 })
	if took := timed(func() {
		_, token, _ = mint(t, rig, assertion(t, key, claimsFor(rig, email)))
		if code, _ := ask(t, rig, http.MethodGet, worldsReads()[0], token); code != http.StatusOK {
			t.Fatalf("the read: %d", code)
		}
	}); took >= 2500*time.Millisecond {
		t.Errorf("healthy took %s with slow_seconds 5; only slow-cluster holds", took)
	}
}

// spec is a rehearsal's record, made by hand for the pure tests.
func spec(t *testing.T) rehearsal.Spec {
	t.Helper()
	root := t.TempDir()
	return rehearsal.Spec{
		Instance: instance, Project: rehearsal.DefaultProject,
		Scenario: rehearsal.ScenarioHealthy, Started: time.Now().UTC().Add(-time.Hour).Truncate(time.Second),
		Dirs: rehearsal.Dirs{Root: root, Config: filepath.Join(root, "config")},
		Images: map[string]string{
			"fatline": "registry.rehearsal.invalid/farcast/fatline@sha256:" + strings.Repeat("1", 64),
			"shrike":  "registry.rehearsal.invalid/farcast/shrike@sha256:" + strings.Repeat("2", 64),
		},
		SlowSeconds: 25,
	}
}

// TestClusterAnswersDecode reads the rig's own cluster through farcast's
// cluster client, opened as the instance's reader from the rehearsal's record,
// as world opens it.
func TestClusterAnswersDecode(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	s, err := rehearsal.LoadSpec(rig.Dir)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := config.Dir(rig.ConfigDir).LoadInstanceMetadata(instance)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := kube.ParseEndpoint(meta.Endpoint, meta.Region, readFile(t, instanceFile(rig, "cluster-ca.crt")))
	if err != nil {
		t.Fatal(err)
	}
	cl, err := cluster.Open(kube.Config{Endpoint: ep, Identity: kube.Reader, Credential: kube.Credential{
		Email: meta.Reader.Email, PrivateKeyID: meta.Reader.KeyID, PrivateKeyPEM: readFile(t, instanceFile(rig, "reader.key")),
	}}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	now := time.Now().UTC()

	sys, err := cl.Workloads(ctx, fldeploy.DefaultNamespace)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]cluster.Workload{}
	for _, w := range sys {
		got[w.Name] = w
	}
	if f := got["fatline"]; f.Kind != "Deployment" || f.Desired != 1 || f.Ready != 1 || len(f.Images) != 2 || f.Images[0] != s.Images["fatline"] {
		t.Errorf("fatline: %+v", f)
	}
	if k := got["datasphered"]; k.Kind != "StatefulSet" || k.Desired != 2 || k.Ready != 2 {
		t.Errorf("datasphered: %+v", k)
	}
	if k := got["technocore"]; k.Kind != "Deployment" || k.Desired != 1 || k.Ready != 1 {
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
		rig, err := rehearsal.Start(t.Context(), rehearsal.Options{Dir: c.dir, Home: home})
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
		rig, err := rehearsal.Start(t.Context(), rehearsal.Options{Dir: fresh, Home: home})
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
// never open them — the config package's read observer sees neither, nor the
// writer's credentials.yaml: 'world' reads as the reader alone.
func TestCAKeyAndKeyringAreUnreadable(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	inst := filepath.Join(rig.ConfigDir, "instances", instance)
	caKey := filepath.Join(inst, "fatline", "ca.key")
	keyring := filepath.Join(inst, "datasphere", "keys.yaml")
	credentials := filepath.Join(inst, "credentials.yaml")
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
		if p == caKey || p == keyring || p == credentials {
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
			Groups []struct {
				AppsError *struct {
					Kind    string `json:"kind"`
					Message string `json:"message"`
				} `json:"apps_error"`
			} `json:"groups"`
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
		for _, g := range doc.Groups {
			if g.AppsError != nil {
				forbidden = append(forbidden, g.AppsError.Message)
				kinds = append(kinds, g.AppsError.Kind)
			}
		}
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

// TestSummarizeKnowsEveryKind (A18-18, mutation O45): summarize's closed set
// of error kinds is the CLI's 21, from the kinds vector the CLI's own test
// pins: each prints as itself, and each kind ADR 0023 M2 retired as "other".
// A kind missing from summarize's hand copy would print as "other" with
// nothing else noticing.
func TestSummarizeKnowsEveryKind(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "cli", "testdata", "kinds", "kinds.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Kinds []string `json:"kinds"`
	}
	if err := json.Unmarshal(data, &v); err != nil || len(v.Kinds) != 21 {
		t.Fatalf("the kinds vector: %v, %d kinds", err, len(v.Kinds))
	}
	// The kinds cli's retiredKinds names (ADR 0023 M2), never emitted again.
	retired := []string{"kubectl_missing", "kubectl_failed", "gcloud_mismatch", "gcloud_signed_out", "auth_tool_missing"}
	for _, row := range append(slices.Clone(v.Kinds), retired...) {
		want := row
		if slices.Contains(retired, row) {
			want = "other"
		}
		var out bytes.Buffer
		if err := rehearsal.Summarize(strings.NewReader(`{"error":{"kind":"`+row+`","message":"m","code":1}}`), &out); err != nil {
			t.Fatal(err)
		}
		if got := out.String(); got != "error: kind "+want+", exit 1\n" {
			t.Errorf("the kind %s summarizes as %q, want the kind %s", row, got, want)
		}
	}
}

// TestCloseIsIdempotent: a second Close is nothing, and every listener is gone.
func TestCloseIsIdempotent(t *testing.T) {
	rig := startRig(t, rehearsal.Options{})
	addrs := rig.Listeners()
	if len(addrs) != 5 || addrs[0] != rig.TunnelAddr || addrs[1] != rig.ClusterAddr {
		t.Fatalf("listeners %v, want the tunnel, the cluster, Shrike and two keyholders", addrs)
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
		if listening(a) {
			t.Errorf("%s still accepts after Close", a)
		}
	}
	if _, err := os.Stat(filepath.Join(rig.Dir, "rehearsal.json")); err != nil {
		t.Errorf("Close removed the state directory: %v", err)
	}
}

// TestRestartReusesTheDirectory: a stopped rehearsal starts again on its own
// directory, on its own tunnel and cluster ports, with its own leaves and
// keys, and changes nothing the operator entered; its cluster has a new CA,
// so cluster-ca.crt is written anew. A restart never reads credentials.yaml,
// and one in reader-missing knows its reader by reader.crt.
func TestRestartReusesTheDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "r")
	home := t.TempDir()
	argv := loadArgv(t)
	o := rehearsal.Options{Dir: dir, Home: home}
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
	meta := instanceFile(first, "metadata.yaml")
	recorded := readFile(t, meta)
	firstCA := readFile(t, instanceFile(first, "cluster-ca.crt"))
	credentials := instanceFile(first, "credentials.yaml")
	if err := os.Chmod(credentials, 0); err != nil {
		t.Fatal(err)
	}

	second := startRig(t, o)
	if second.TunnelAddr != first.TunnelAddr || second.ClusterAddr != first.ClusterAddr || second.Dir != first.Dir {
		t.Errorf("restart moved: %s %s %s, was %s %s %s", second.TunnelAddr, second.ClusterAddr, second.Dir,
			first.TunnelAddr, first.ClusterAddr, first.Dir)
	}
	if now, err := os.ReadFile(meta); err != nil || !bytes.Equal(now, recorded) {
		t.Errorf("a restart rewrote metadata.yaml (%v)", err)
	}
	if ca := readFile(t, instanceFile(second, "cluster-ca.crt")); bytes.Equal(ca, firstCA) {
		t.Error("a restart kept cluster-ca.crt; its cluster has a new CA")
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
	other.Project = "another-project"
	if _, err := rehearsal.Start(t.Context(), other); err == nil || !strings.Contains(err.Error(), "another project") {
		t.Errorf("a restart with another project: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}

	if err := rehearsal.SetScenario(dir, rehearsal.ScenarioReaderMissing); err != nil {
		t.Fatal(err)
	}
	third := startRig(t, o)
	world(t, third, argv).sections(t, "reader-missing after a restart", "credential_missing", "spend", "apps", "policy")
	if err := rehearsal.SetScenario(dir, rehearsal.ScenarioHealthy); err != nil {
		t.Fatal(err)
	}
	checkHealthy(t, world(t, third, argv))
}

// TestARehearsalMadeBeforeM24IsRefused: a directory a harness from before ADR
// 0023 M2.4 made — fake tools and a gcloud directory, and no cluster CA — is
// refused by Start and by SetScenario, whatever its scenario, and nothing in
// it changes.
func TestARehearsalMadeBeforeM24IsRefused(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "old")
	for _, d := range []string{"kube/bin", "sdk/bin", "gcloud/configurations", "harness", "config/instances/" + instance} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const want = "this rehearsal was made before ADR 0023 M2.4 moved its cluster into the harness; start a new one in a new directory"
	for _, scenario := range []string{"signed-out", rehearsal.ScenarioHealthy} {
		old, err := json.Marshal(map[string]any{
			"instance": instance, "account": "operator@rehearsal.invalid", "project": rehearsal.DefaultProject,
			"scenario": scenario, "started": time.Now().UTC().Add(-time.Hour).Truncate(time.Second),
			"dirs": map[string]string{
				"root": dir, "config": filepath.Join(dir, "config"), "gcloud": filepath.Join(dir, "gcloud"),
				"kube_bin": filepath.Join(dir, "kube", "bin"), "sdk_bin": filepath.Join(dir, "sdk", "bin"),
			},
			"images": map[string]string{}, "slow_seconds": 25,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "rehearsal.json"), old, 0o600); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, dir)
		if rig, err := rehearsal.Start(t.Context(), rehearsal.Options{Dir: dir, Home: t.TempDir()}); err == nil {
			_ = rig.Close()
			t.Errorf("%s: a restart of a pre-M2.4 rehearsal started", scenario)
		} else if err.Error() != want {
			t.Errorf("%s: Start = %v, want %q", scenario, err, want)
		}
		if err := rehearsal.SetScenario(dir, rehearsal.ScenarioSealed); err == nil || err.Error() != want {
			t.Errorf("%s: SetScenario = %v, want %q", scenario, err, want)
		}
		if after := snapshot(t, dir); !maps.Equal(after, before) {
			t.Errorf("%s: the refusals changed the directory: %v, was %v", scenario, after, before)
		}
		if got := readFile(t, filepath.Join(dir, "rehearsal.json")); !bytes.Equal(got, old) {
			t.Errorf("%s: rehearsal.json was rewritten", scenario)
		}
	}
}

// checkpointPath is the kernel's checkpoint, as world reads it.
const checkpointPath = "/api/v1/namespaces/farcast-system/configmaps/" + kernel.DefaultCheckpointName

// checkpointOf decodes a checkpoint ConfigMap's answer.
func checkpointOf(t *testing.T, body []byte) kernel.Checkpoint {
	t.Helper()
	var cm struct {
		Kind string            `json:"kind"`
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(body, &cm); err != nil || cm.Kind != "ConfigMap" {
		t.Fatalf("not a ConfigMap (%v): %s", err, body)
	}
	var cp kernel.Checkpoint
	if err := json.Unmarshal([]byte(cm.Data[kernel.CheckpointKey()]), &cp); err != nil {
		t.Fatal(err)
	}
	return cp
}

// TestLedgerIgnoresTheCalendar: the first of a month still shows spending
// split, and a rehearsal past its period refuses every read with a 500 that
// says so, never a 503, which the client would retry.
func TestLedgerIgnoresTheCalendar(t *testing.T) {
	s := spec(t)
	now := time.Date(2026, 12, 1, 0, 30, 0, 0, time.UTC)
	s.Started = now.Add(-time.Hour)
	code, body := rehearsal.ClusterAnswer(s, http.MethodGet, checkpointPath, "", now)
	if code != http.StatusOK {
		t.Fatalf("no checkpoint on the first of a month: %d %s", code, body)
	}
	ledger, err := cost.Restore(checkpointOf(t, body).Ledger)
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
	for _, target := range worldsReads() {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatal(err)
		}
		code, body := rehearsal.ClusterAnswer(s, http.MethodGet, u.Path, u.RawQuery, late)
		var st struct {
			Kind    string `json:"kind"`
			Message string `json:"message"`
		}
		if code != http.StatusInternalServerError || json.Unmarshal(body, &st) != nil || st.Kind != "Status" ||
			!strings.Contains(st.Message, "older than its 30-day period") {
			t.Errorf("%s past the period: %d %s", target, code, body)
		}
	}

	home := t.TempDir()
	rig := startRig(t, rehearsal.Options{Home: home})
	editSpec(t, rig.Dir, func(s *rehearsal.Spec) { s.Started = time.Now().UTC().Add(-25*24*time.Hour - time.Hour) })
	argv := loadArgv(t)
	asTheApp(t, rig)
	doc := world(t, rig, argv)
	doc.sections(t, "expired", "cluster_rejected", "spend", "apps", "policy")
	if m := doc.sectionMessage("spend"); !strings.Contains(m, "older than its 30-day period") {
		t.Errorf("an expired rehearsal's spend says %q", m)
	}
	refused := 0
	for _, c := range clusterCalls(t, rig) {
		if c.outcome == "refused: this rehearsal is older than its 30-day period; start a new one" {
			refused++
		}
	}
	if refused == 0 {
		t.Errorf("calls.log records no expired read: %v", calls(t, rig))
	}
	if err := rig.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := rehearsal.Start(t.Context(), rehearsal.Options{Dir: rig.Dir, Home: home}); err == nil ||
		!strings.Contains(err.Error(), "older than its 30-day period") {
		t.Errorf("a restart of an expired rehearsal: %v", err)
	}
}

// TestTheLevelIsTheLedgersOwn: on every read of a rehearsal's life, every
// scenario's level is what the kernel's own assessment makes of its ledger —
// never a level set beside a total that contradicts it (phase 7, F6). The
// scenarios at the limit are over it from their first read to their last,
// with the calibration still exactly one; every other scenario is well under.
// unauthorized and forbidden serve no checkpoint at all.
func TestTheLevelIsTheLedgersOwn(t *testing.T) {
	s := spec(t)
	for _, name := range rehearsal.Scenarios() {
		s.Scenario = name
		// A rehearsal lives between 24 and 25 days: its period starts at the
		// midnight five days before it did.
		for _, after := range []time.Duration{0, time.Hour, 12 * 24 * time.Hour, 24 * 24 * time.Hour} {
			now := s.Started.Add(after)
			code, body := rehearsal.ClusterAnswer(s, http.MethodGet, checkpointPath, "", now)
			switch name {
			case rehearsal.ScenarioUnauthorized:
				if code != http.StatusUnauthorized {
					t.Errorf("%s: %d, want 401", name, code)
				}
				continue
			case rehearsal.ScenarioForbidden:
				if code != http.StatusForbidden {
					t.Errorf("%s: %d, want 403", name, code)
				}
				continue
			}
			if code != http.StatusOK {
				t.Fatalf("%s, %s in: no checkpoint: %d %s", name, after, code, body)
			}
			cp := checkpointOf(t, body)
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
	o := rehearsal.Options{Dir: dir, Home: t.TempDir()}
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
