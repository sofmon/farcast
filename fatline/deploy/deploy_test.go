package deploy

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

func sampleConfig() Config {
	return Config{
		Image:         "example/fatline:test",
		CACertPEM:     []byte("CA-PEM"),
		ServerCertPEM: []byte("SRV-CRT"),
		ServerKeyPEM:  []byte("SRV-KEY"),
	}
}

func TestRenderValidation(t *testing.T) {
	cases := map[string]Config{
		"missing image":    {CACertPEM: []byte("x"), ServerCertPEM: []byte("y"), ServerKeyPEM: []byte("z")},
		"missing material": {Image: "img"},
		"unknown carrier":  {Image: "img", Carrier: "Weird", CACertPEM: []byte("x"), ServerCertPEM: []byte("y"), ServerKeyPEM: []byte("z")},
	}
	for name, c := range cases {
		if _, err := Render(c); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func docsByKind(t *testing.T, out []byte) map[string]map[string]any {
	t.Helper()
	res := map[string]map[string]any{}
	for d := range strings.SplitSeq(string(out), "\n---\n") {
		if strings.TrimSpace(d) == "" {
			continue
		}
		var m map[string]any
		if err := yaml.Unmarshal([]byte(d), &m); err != nil {
			t.Fatalf("rendered document is not valid YAML: %v\n%s", err, d)
		}
		kind, _ := m["kind"].(string)
		res[kind] = m
	}
	return res
}

func TestRenderDocuments(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	docs := docsByKind(t, out)
	for _, want := range []string{"Namespace", "Secret", "Deployment", "PodDisruptionBudget", "Service"} {
		if _, ok := docs[want]; !ok {
			t.Fatalf("missing %s document; got kinds %v", want, keys(docs))
		}
	}

	// Default carrier is the public load balancer.
	spec, ok := docs["Service"]["spec"].(map[string]any)
	if !ok || spec["type"] != "LoadBalancer" {
		t.Fatalf("service spec=%v, want type LoadBalancer", docs["Service"]["spec"])
	}

	// The Secret round-trips the mTLS material, base64-encoded.
	data, ok := docs["Secret"]["data"].(map[string]any)
	if !ok {
		t.Fatal("secret has no data map")
	}
	if got := b64(t, data["ca.crt"]); got != "CA-PEM" {
		t.Errorf("ca.crt=%q, want CA-PEM", got)
	}
	if got := b64(t, data["server.key"]); got != "SRV-KEY" {
		t.Errorf("server.key=%q, want SRV-KEY", got)
	}
	// The CA *private key* must never be in the workload.
	if _, leaked := data["ca.key"]; leaked {
		t.Error("CA private key must never appear in the rendered Secret")
	}
}

func TestRenderAutopilotCompliant(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"runAsNonRoot: true", "allowPrivilegeEscalation: false", "requests:", "cpu: 100m", "memory: 128Mi", "- ALL"} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered workload missing %q (Autopilot compliance)", want)
		}
	}
	for _, forbidden := range []string{"privileged: true", "hostNetwork"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("workload must not use %q", forbidden)
		}
	}
}

func TestRenderClusterIPCarrier(t *testing.T) {
	c := sampleConfig()
	c.Carrier = CarrierClusterIP
	out, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "type: ClusterIP") {
		t.Fatal("expected a ClusterIP service for the cluster-internal carrier")
	}
}

func b64(t *testing.T, v any) string {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("secret value is not a string: %T", v)
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("secret value is not valid base64: %v", err)
	}
	return string(decoded)
}

func keys(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestRenderSecretIsReadableByTheNonRootContainer pins the pairing that makes
// the mTLS material usable: the pod runs as 65532 and must not run as root, so
// the secret has to be group-readable and the volume group-owned. A 0400 mount
// leaves it root-only and FatLine crash-loops on "permission denied" reading
// its own server certificate — which is exactly what the first live deploy did.
func TestRenderSecretIsReadableByTheNonRootContainer(t *testing.T) {
	out, err := Render(Config{
		Image:         "example.test/repo/fatline@sha256:" + strings.Repeat("a", 64),
		Carrier:       CarrierLoadBalancer,
		CACertPEM:     []byte("ca"),
		ServerCertPEM: []byte("crt"),
		ServerKeyPEM:  []byte("key"),
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := string(out)
	for _, want := range []string{
		"runAsUser: 65532",
		"runAsGroup: 65532",
		"fsGroup: 65532",
		"defaultMode: 288", // 0440
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered manifest is missing %q — the container could not read its own key", want)
		}
	}
	if strings.Contains(got, "defaultMode: 256") {
		t.Error("secret is mounted 0400: root-only, unreadable by the non-root container")
	}
}

// TestRenderMTLSHashTracksTheMaterial: rotating the mTLS material must change
// the pod template, or nothing restarts. Kubernetes updates a mounted Secret in
// place and FatLine loads its certificate once at start-up, so without this
// fingerprint a rotation would update the Secret, leave the Deployment spec
// byte-identical, and let the rollout report success while the old certificate
// kept serving.
func TestRenderMTLSHashTracksTheMaterial(t *testing.T) {
	render := func(serverCert string) string {
		out, err := Render(Config{
			Image:         "example.test/repo/fatline@sha256:" + strings.Repeat("a", 64),
			Carrier:       CarrierLoadBalancer,
			CACertPEM:     []byte("ca"),
			ServerCertPEM: []byte(serverCert),
			ServerKeyPEM:  []byte("key"),
		})
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		return string(out)
	}
	first, rotated, same := render("leaf-1"), render("leaf-2"), render("leaf-1")

	if !strings.Contains(first, "farcast.sofmon.com/mtls-hash:") {
		t.Fatal("pod template carries no mTLS fingerprint; a rotation would restart nothing")
	}
	hash := func(manifest string) string {
		_, rest, _ := strings.Cut(manifest, "farcast.sofmon.com/mtls-hash: ")
		line, _, _ := strings.Cut(rest, "\n")
		return strings.TrimSpace(line)
	}
	if hash(first) == hash(rotated) {
		t.Error("rotating the server leaf left the fingerprint unchanged; the Pod would keep the old certificate")
	}
	if hash(first) != hash(same) {
		t.Error("identical material produced different fingerprints; every redeploy would churn the Pod")
	}
}

// nested walks a rendered document by key path, failing rather than panicking
// on a missing or wrongly-typed level.
func nested(t *testing.T, doc map[string]any, path ...string) any {
	t.Helper()
	var cur any = doc
	for i, k := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%v: level %q is not a map", path[:i], k)
		}
		cur, ok = m[k]
		if !ok {
			t.Fatalf("%v: missing key %q", path[:i], k)
		}
	}
	return cur
}

// The tunnel is the only path an unseal push can take (ADR 0008), so a single
// replica makes storage recovery wait on FatLine's own reschedule. ADR 0009
// decision 11 buys the second replica; this test is what keeps someone from
// "optimizing" ~$4/month back into an unrecoverable instance.
func TestRenderRunsTwoReplicasByDefault(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	docs := docsByKind(t, out)
	if got := nested(t, docs["Deployment"], "spec", "replicas"); got != uint64(2) && got != 2 {
		t.Errorf("replicas=%v (%T), want 2 — the recovery floor, not a tuning default", got, got)
	}
}

// A PodDisruptionBudget whose selector does not match the Deployment's pods is
// a document that protects nothing while reporting success. The budget and the
// workload it guards are rendered from the same template, so the only way to
// catch a divergence is to compare them.
func TestRenderPodDisruptionBudgetGuardsTheTunnel(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	docs := docsByKind(t, out)

	if got := nested(t, docs["PodDisruptionBudget"], "spec", "minAvailable"); got != uint64(1) && got != 1 {
		t.Errorf("minAvailable=%v (%T), want 1 — a drain must wait, not take the last tunnel", got, got)
	}

	budget := nested(t, docs["PodDisruptionBudget"], "spec", "selector", "matchLabels")
	workload := nested(t, docs["Deployment"], "spec", "selector", "matchLabels")
	if fmt.Sprint(budget) != fmt.Sprint(workload) {
		t.Errorf("PDB selector %v does not match the Deployment's pod selector %v; the budget guards nothing", budget, workload)
	}
}

// DoNotSchedule is the reflex and the wrong answer on Autopilot: with one
// schedulable node the second replica stays Pending forever, which is the
// single-replica state the constraint was added to prevent. datasphered made
// the same call for the same reason.
func TestRenderSpreadsRepicasSoftly(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "whenUnsatisfiable: ScheduleAnyway") {
		t.Error("topology spread must be soft; a hard constraint strands the second replica")
	}
	if strings.Contains(s, "whenUnsatisfiable: DoNotSchedule") {
		t.Error("DoNotSchedule leaves the second replica Pending when only one node fits")
	}
}

func TestRenderRejectsAReplicaCountBelowOne(t *testing.T) {
	c := sampleConfig()
	c.Replicas = -1
	if _, err := Render(c); err == nil {
		t.Fatal("expected an error for a negative replica count")
	}
}

// One replica is still renderable — tests and the ClusterIP fallback want it —
// but only when asked for explicitly.
func TestRenderHonoursAnExplicitReplicaCount(t *testing.T) {
	c := sampleConfig()
	c.Replicas = 1
	out, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	docs := docsByKind(t, out)
	if got := nested(t, docs["Deployment"], "spec", "replicas"); got != uint64(1) && got != 1 {
		t.Errorf("replicas=%v, want 1", got)
	}
}

// The exported request constants exist so an operator-facing cost estimate can
// be computed from the same numbers the manifest asks for. That only holds if
// the rendered YAML really carries them — a template that hardcoded "100m"
// while the constant said something else would quote a price for a workload
// that was never deployed.
func TestRenderedRequestsMatchTheExportedConstants(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		fmt.Sprintf("cpu: %dm", RequestCPUMilli),
		fmt.Sprintf("memory: %dMi", RequestMemMiB),
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered workload does not request %q; the cost estimate would quote a workload nobody deployed", want)
		}
	}
}
