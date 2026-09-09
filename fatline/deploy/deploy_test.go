package deploy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
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

// The egress proxy needs a Service of its own, and it must never be the
// tunnel's.
//
// Found on the 4.2 walk: applications were pointed at
// fatline.farcast-system:3128 and the tunnel's Service published only 8443, so
// FARCAST_FATLINE_PROXY resolved and connected to nothing — an application's
// only route out did not exist.
//
// The obvious fix is the dangerous one. The tunnel's Service is a public
// LoadBalancer (ADR 0005); adding the proxy port to it would put an open
// forward proxy on the internet, and anyone could route traffic through the
// instance.
func TestTheEgressProxyHasItsOwnClusterIPServiceAndIsNeverPublished(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}

	var tunnel, egress map[string]any
	for _, doc := range strings.Split(string(out), "\n---\n") {
		var m map[string]any
		if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatalf("invalid YAML: %v", err)
		}
		if k, _ := m["kind"].(string); k != "Service" {
			continue
		}
		switch nested(t, m, "metadata", "name") {
		case DefaultName:
			tunnel = m
		case EgressService:
			egress = m
		}
	}

	if egress == nil {
		t.Fatal("no egress Service; applications have no route out at all")
	}
	if got := nested(t, egress, "spec", "type"); got != "ClusterIP" {
		t.Errorf("egress Service type = %v, want ClusterIP — this port must never leave the cluster", got)
	}
	if got := fmt.Sprint(nested(t, egress, "spec", "ports")); !strings.Contains(got, fmt.Sprint(DefaultEgressPort)) {
		t.Errorf("egress Service does not publish %d: %v", DefaultEgressPort, got)
	}

	if tunnel == nil {
		t.Fatal("no tunnel Service")
	}
	// The one that must not happen.
	if got := fmt.Sprint(nested(t, tunnel, "spec", "ports")); strings.Contains(got, fmt.Sprint(DefaultEgressPort)) {
		t.Errorf("the PUBLIC Service publishes the egress proxy port (%v); that is an open forward proxy on the internet",
			got)
	}
}

// FatLine mounts the per-application egress policy `farcast run` writes, and
// the mount is optional because connect deploys FatLine before any application
// exists to have one — a missing policy is a closed instance, not a broken one
// (ADR 0013 decision 5).
func TestTheEgressPolicyIsMountedAndOptional(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	docs := docsByKind(t, out)

	if !strings.Contains(string(out), "--policy="+policyMountPath+"/"+PolicyKey) {
		t.Error("FatLine is not told where its egress policy is")
	}

	spec := docs["Deployment"]["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)

	var mounted bool
	for _, c := range spec["containers"].([]any) {
		for _, m := range c.(map[string]any)["volumeMounts"].([]any) {
			mm := m.(map[string]any)
			if mm["name"] == "policy" {
				mounted = true
				if mm["mountPath"] != policyMountPath {
					t.Errorf("policy mounted at %v, want %v", mm["mountPath"], policyMountPath)
				}
				if mm["readOnly"] != true {
					t.Error("FatLine can write to its own egress policy")
				}
			}
		}
	}
	if !mounted {
		t.Fatal("the policy volume is not mounted")
	}

	var found bool
	for _, v := range spec["volumes"].([]any) {
		vm := v.(map[string]any)
		if vm["name"] != "policy" {
			continue
		}
		found = true
		cm := vm["configMap"].(map[string]any)
		if cm["name"] != PolicyConfigMap {
			t.Errorf("policy volume reads %v, want %v", cm["name"], PolicyConfigMap)
		}
		if cm["optional"] != true {
			t.Error("the policy volume is not optional; FatLine would not start before the first farcast run")
		}
	}
	if !found {
		t.Fatal("no policy volume")
	}
}

// containersOf returns the pod's containers by name.
func containersOf(t *testing.T, out []byte) map[string]map[string]any {
	t.Helper()
	docs := docsByKind(t, out)
	raw := nested(t, docs["Deployment"], "spec", "template", "spec", "containers")
	list, ok := raw.([]any)
	if !ok {
		t.Fatalf("containers is %T, not a list", raw)
	}
	res := map[string]map[string]any{}
	for _, c := range list {
		m, ok := c.(map[string]any)
		if !ok {
			t.Fatalf("container is %T, not a map", c)
		}
		name, _ := m["name"].(string)
		res[name] = m
	}
	return res
}

func argsOf(t *testing.T, container map[string]any) []string {
	t.Helper()
	raw, ok := container["args"].([]any)
	if !ok {
		t.Fatalf("args is %T, not a list", container["args"])
	}
	var out []string
	for _, a := range raw {
		s, _ := a.(string)
		out = append(out, s)
	}
	return out
}

// Shrike is co-scheduled with FatLine, not deployed as its own workload.
//
// It was built at 2.2 and the two-container Pod was scoped to Planck at 4.2,
// where it did not ship — so for two phases nothing deployed the monitor at
// all and a policy violation in a running instance reached nobody. This is the
// join that closes it.
func TestShrikeIsCoScheduledWithFatLine(t *testing.T) {
	c := sampleConfig()
	c.ShrikeImage = "example/shrike:test"
	out, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	containers := containersOf(t, out)
	if len(containers) != 2 {
		t.Fatalf("rendered %d containers, want fatline + shrike: %v", len(containers), keysOf(containers))
	}
	sh, ok := containers[ShrikeName]
	if !ok {
		t.Fatalf("no %q container: %v", ShrikeName, keysOf(containers))
	}
	if got := sh["image"]; got != "example/shrike:test" {
		t.Errorf("shrike image = %v", got)
	}

	// Both ends of the wire agree on one path, and it is the socket Shrike
	// listens on. Two spellings of it would be a sidecar that silently
	// receives nothing.
	var fatlineSocket, shrikeSocket string
	for _, a := range argsOf(t, containers["fatline"]) {
		if v, ok := strings.CutPrefix(a, "--shrike-socket="); ok {
			fatlineSocket = v
		}
	}
	for _, a := range argsOf(t, sh) {
		if v, ok := strings.CutPrefix(a, "--socket="); ok {
			shrikeSocket = v
		}
	}
	if fatlineSocket == "" {
		t.Error("fatline was not told where the sidecar listens")
	}
	if fatlineSocket != shrikeSocket {
		t.Errorf("the two ends disagree: fatline dials %q, shrike listens on %q", fatlineSocket, shrikeSocket)
	}

	// Shrike reads the same policy document FatLine enforces from.
	if !strings.Contains(strings.Join(argsOf(t, sh), " "), PolicyKey) {
		t.Error("shrike was not given the egress policy")
	}

	// The socket lives on a volume both containers mount, and Shrike's mount
	// is writable because it is the end that creates the socket.
	vols := nested(t, docsByKind(t, out)["Deployment"], "spec", "template", "spec", "volumes")
	if !strings.Contains(mustJSON(t, vols), "shrike-wire") {
		t.Error("no shared volume for the socket")
	}
	for _, m := range []struct {
		container map[string]any
		name      string
	}{{containers["fatline"], "fatline"}, {sh, ShrikeName}} {
		mounts := mustJSON(t, m.container["volumeMounts"])
		if !strings.Contains(mounts, "shrike-wire") {
			t.Errorf("%s does not mount the socket volume", m.name)
		}
	}
	if strings.Contains(mustJSON(t, sh["volumeMounts"]), `"shrike-wire","readOnly":true`) {
		t.Error("shrike's socket mount is read-only; it is the end that creates the socket")
	}
}

// And without an image, FatLine deploys alone — which is every instance
// connected before the sidecar shipped. FatLine logs every decision itself
// either way, so the monitor's absence costs alerting, never the record.
func TestWithoutAShrikeImageFatLineDeploysAlone(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	containers := containersOf(t, out)
	if len(containers) != 1 {
		t.Fatalf("rendered %d containers, want fatline alone: %v", len(containers), keysOf(containers))
	}
	if strings.Contains(string(out), "--shrike-socket") {
		t.Error("fatline was told to dial a sidecar that was not rendered")
	}
	if strings.Contains(string(out), "shrike-wire") {
		t.Error("the socket volume was rendered with no sidecar to use it")
	}
}

// The sidecar must be admissible on Autopilot on the same terms as every other
// container this project runs (ADR 0003).
func TestShrikeSidecarIsAutopilotCompliant(t *testing.T) {
	c := sampleConfig()
	c.ShrikeImage = "example/shrike:test"
	out, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	sh := containersOf(t, out)[ShrikeName]
	req := mustJSON(t, nested(t, sh, "resources", "requests"))
	if !strings.Contains(req, "cpu") || !strings.Contains(req, "memory") {
		t.Errorf("the sidecar declares no resource requests: %s", req)
	}
	sec := mustJSON(t, sh["securityContext"])
	for _, want := range []string{`"allowPrivilegeEscalation":false`, `"readOnlyRootFilesystem":true`, "ALL"} {
		if !strings.Contains(sec, want) {
			t.Errorf("securityContext missing %s: %s", want, sec)
		}
	}
}

func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
