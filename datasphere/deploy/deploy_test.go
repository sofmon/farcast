package deploy

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// digest is a syntactically valid content digest; the tests care that the image
// is pinned, not what it points at.
const digest = "@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func sampleConfig() Config {
	return Config{
		Image:         "us-central1-docker.pkg.dev/proj/farcast-prod/system/datasphered" + digest,
		Instance:      "prod",
		Bucket:        "farcast-prod-0a1b2c3d",
		Project:       "example-project",
		Location:      "us-central1",
		CACertPEM:     []byte("CA-PEM"),
		ServerCertPEM: []byte("SRV-CRT"),
		ServerKeyPEM:  []byte("SRV-KEY"),
	}
}

func TestRenderValidation(t *testing.T) {
	material := func(c Config) Config {
		c.CACertPEM, c.ServerCertPEM, c.ServerKeyPEM = []byte("x"), []byte("y"), []byte("z")
		return c
	}
	cases := map[string]Config{
		"missing image":     material(Config{}),
		"missing material":  {Image: "img" + digest},
		"partial material":  {Image: "img" + digest, CACertPEM: []byte("x"), ServerCertPEM: []byte("y")},
		"negative replicas": material(Config{Image: "img" + digest, Replicas: -1}),
		"colliding ports":   material(Config{Image: "img" + digest, DataPort: 8443, StatusPort: 8443}),
	}
	for name, c := range cases {
		if _, err := Render(c); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// TestRenderRefusesAnImageThatIsNotDigestPinned: ADR 0008 decision 1 deploys the
// keyholder pinned by digest. A tag is a mutable pointer the registry's owner
// can re-aim, and the one in-cluster component that holds key material is the
// last place to accept "whatever :latest means today" — so the refusal lives in
// Render rather than in every caller's discipline.
func TestRenderRefusesAnImageThatIsNotDigestPinned(t *testing.T) {
	for _, image := range []string{
		"example.test/repo/datasphered:latest",
		"example.test/repo/datasphered:v1.2.3",
		"example.test/repo/datasphered",
		"example.test/repo/datasphered@sha256:short",
		"example.test/repo/datasphered@sha256:" + strings.Repeat("z", 64), // not hex
		"example.test/repo/datasphered@md5:" + strings.Repeat("a", 32),
	} {
		c := sampleConfig()
		c.Image = image
		if _, err := Render(c); err == nil {
			t.Errorf("Render accepted image %q, which is not digest-pinned", image)
		}
	}
	// ...and accepts the pinned form.
	if _, err := Render(sampleConfig()); err != nil {
		t.Fatalf("Render rejected a digest-pinned image: %v", err)
	}
}

// docsByID parses the apply stream and keys each document by "Kind/name" —
// unlike FatLine's workload this one renders three Services, so kind alone is
// not an identity.
func docsByID(t *testing.T, out []byte) map[string]map[string]any {
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
		meta, _ := m["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		res[kind+"/"+name] = m
	}
	return res
}

func render(t *testing.T, c Config) ([]byte, map[string]map[string]any) {
	t.Helper()
	out, err := Render(c)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return out, docsByID(t, out)
}

// dig walks a nested map/slice tree; a numeric path element indexes a slice.
// It returns nil for any miss, so a caller asserting on the result reports the
// missing field rather than panicking on a type assertion.
func dig(v any, path ...string) any {
	for _, p := range path {
		switch node := v.(type) {
		case map[string]any:
			v = node[p]
		case []any:
			i := int(p[0] - '0')
			if i < 0 || i >= len(node) {
				return nil
			}
			v = node[i]
		default:
			return nil
		}
		if v == nil {
			return nil
		}
	}
	return v
}

// num normalizes whatever integer type the YAML decoder produced.
func num(t *testing.T, v any) int64 {
	t.Helper()
	switch n := v.(type) {
	case int:
		return int64(n)
	case int64:
		return n
	case uint64:
		return int64(n)
	case float64:
		return int64(n)
	default:
		t.Fatalf("value %v (%T) is not a number", v, v)
		return 0
	}
}

func TestRenderDocuments(t *testing.T) {
	_, docs := render(t, sampleConfig())
	for _, want := range []string{
		"Namespace/farcast-system",
		"Secret/datasphered-mtls",
		"StatefulSet/datasphered",
		"PodDisruptionBudget/datasphered",
		"Service/datasphered",
		"Service/datasphered-status",
		"Service/datasphered-unseal",
	} {
		if _, ok := docs[want]; !ok {
			t.Fatalf("missing %s document; got %v", want, keys(docs))
		}
	}
	if len(docs) != 8 {
		t.Errorf("rendered %d documents, want 8: %v", len(docs), keys(docs))
	}
	// A Deployment cannot give per-ordinal DNS, so the keyholder is a
	// StatefulSet — see TestRenderPodManagementPolicyMustBeParallel.
	for id := range docs {
		if strings.HasPrefix(id, "Deployment/") {
			t.Errorf("keyholder rendered as %s; it must be a StatefulSet", id)
		}
	}
}

func TestRenderSecretCarriesTransportMaterialOnly(t *testing.T) {
	_, docs := render(t, sampleConfig())
	data, ok := docs["Secret/datasphered-mtls"]["data"].(map[string]any)
	if !ok {
		t.Fatal("secret has no data map")
	}
	for key, want := range map[string]string{"ca.crt": "CA-PEM", "server.crt": "SRV-CRT", "server.key": "SRV-KEY"} {
		if got := b64(t, data[key]); got != want {
			t.Errorf("%s=%q, want %q", key, got, want)
		}
	}
	// The CA *private* key must never reach the cluster — nor may any keyring
	// entry, master or derived: a Secret is etcd, and ADR 0008 exists to keep
	// the keyring off cloud-resident storage.
	for _, forbidden := range []string{"ca.key", "kek", "keys.yaml", "name.key", "bundle"} {
		if _, leaked := data[forbidden]; leaked {
			t.Errorf("rendered Secret carries %q; only transport material may be here", forbidden)
		}
	}
}

// TestRenderHasNoVolumes is the negative assertion ADR 0008 decision 1 is made
// of: "no volumes of any kind". An emptyDir is node disk, a Secret volume is a
// file the process could be made to leave behind, and a projected
// ServiceAccount token is a volume too — so the mTLS material arrives through
// env + secretKeyRef and the token is switched off.
func TestRenderHasNoVolumes(t *testing.T) {
	out, docs := render(t, sampleConfig())

	podSpec, ok := dig(docs["StatefulSet/datasphered"], "spec", "template", "spec").(map[string]any)
	if !ok {
		t.Fatal("StatefulSet has no pod spec")
	}
	if v, present := podSpec["volumes"]; present {
		t.Errorf("pod spec declares volumes: %v", v)
	}
	if v, present := docs["StatefulSet/datasphered"]["spec"].(map[string]any)["volumeClaimTemplates"]; present {
		t.Errorf("StatefulSet declares volumeClaimTemplates: %v", v)
	}
	container, ok := dig(podSpec, "containers", "0").(map[string]any)
	if !ok {
		t.Fatal("pod spec has no container")
	}
	if v, present := container["volumeMounts"]; present {
		t.Errorf("container declares volumeMounts: %v", v)
	}
	if automount, present := podSpec["automountServiceAccountToken"]; !present || automount != false {
		t.Errorf("automountServiceAccountToken=%v (present=%v), want false — a projected token is a volume, and it is one the cloud mints", automount, present)
	}

	// Belt and braces over the raw stream, so a volume added under a key this
	// test does not walk still fails. Comment lines are stripped first: the
	// template *talks about* emptyDir in the comment explaining why there is
	// none, and prose is not a manifest key.
	for _, forbidden := range []string{
		"volumes:", "volumeMounts:", "volumeClaimTemplates:",
		"emptyDir", "hostPath", "persistentVolumeClaim", "downwardAPI", "configMap", "projected:",
	} {
		if strings.Contains(stripComments(out), forbidden) {
			t.Errorf("rendered workload contains %q; ADR 0008 decision 1 permits no volumes of any kind", forbidden)
		}
	}

	// The material has to reach the process somehow, and this is the somehow.
	if !strings.Contains(string(out), "secretKeyRef") {
		t.Error("no secretKeyRef in the workload: with no volumes, env is the only path the TLS material has")
	}
}

// stripComments removes whole-line YAML comments so raw-text assertions are made
// against the manifest and not against the commentary explaining it.
func stripComments(out []byte) string {
	var b strings.Builder
	for line := range strings.SplitSeq(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// TestRenderPodManagementPolicyMustBeParallel pins the setting whose default
// deadlocks the fleet. Under OrderedReady the controller creates pod-0 and waits
// for it to be Ready before creating pod-1 — but a fresh replica comes back
// SEALED and a sealed replica fails readiness by design, so pod-1 would never be
// created and the fleet would sit at one replica permanently, silently deleting
// the whole benefit ADR 0008 decision 6 bought. If this test ever fails, the
// answer is not to change the assertion.
func TestRenderPodManagementPolicyMustBeParallel(t *testing.T) {
	_, docs := render(t, sampleConfig())
	spec, ok := docs["StatefulSet/datasphered"]["spec"].(map[string]any)
	if !ok {
		t.Fatal("StatefulSet has no spec")
	}
	if got := spec["podManagementPolicy"]; got != "Parallel" {
		t.Fatalf("podManagementPolicy=%v, want Parallel — OrderedReady never starts pod-1, because pod-0 is never Ready while sealed", got)
	}
}

func TestRenderRolloutSettings(t *testing.T) {
	_, docs := render(t, sampleConfig())
	spec, ok := docs["StatefulSet/datasphered"]["spec"].(map[string]any)
	if !ok {
		t.Fatal("StatefulSet has no spec")
	}
	if got := num(t, spec["replicas"]); got != 2 {
		t.Errorf("replicas=%d, want 2 (ADR 0008 decision 6)", got)
	}
	// The headless Service governs DNS; without it there are no stable
	// per-ordinal names to unseal.
	if got := spec["serviceName"]; got != "datasphered-unseal" {
		t.Errorf("serviceName=%v, want datasphered-unseal", got)
	}
	if got := dig(spec, "updateStrategy", "type"); got != "RollingUpdate" {
		t.Errorf("updateStrategy.type=%v, want RollingUpdate", got)
	}
	if got := num(t, dig(spec, "updateStrategy", "rollingUpdate", "partition")); got != 0 {
		t.Errorf("updateStrategy.rollingUpdate.partition=%d, want 0", got)
	}
	if got := num(t, spec["minReadySeconds"]); got != 0 {
		t.Errorf("minReadySeconds=%d, want 0 — readiness here means unsealed, so a settle window is time added to a gate only a human can open", got)
	}
}

// TestRenderTopologySpreadIsSoft pins ScheduleAnyway against the reflex to
// harden it. DoNotSchedule is the stricter setting and on GKE Autopilot it
// causes the very outage the constraint exists to prevent: when only one node
// fits, a hard constraint leaves the second replica Pending forever and the
// fleet runs at one replica — exactly the state ADR 0008 decision 6 bought the
// second replica to avoid. Co-located replicas still survive a single-pod OOM
// and a rollout; a Pending replica survives nothing.
func TestRenderTopologySpreadIsSoft(t *testing.T) {
	out, docs := render(t, sampleConfig())
	constraint, ok := dig(docs["StatefulSet/datasphered"], "spec", "template", "spec", "topologySpreadConstraints", "0").(map[string]any)
	if !ok {
		t.Fatal("no topologySpreadConstraints on the pod spec")
	}
	if got := num(t, constraint["maxSkew"]); got != 1 {
		t.Errorf("maxSkew=%d, want 1", got)
	}
	if got := constraint["topologyKey"]; got != "kubernetes.io/hostname" {
		t.Errorf("topologyKey=%v, want kubernetes.io/hostname", got)
	}
	if got := constraint["whenUnsatisfiable"]; got != "ScheduleAnyway" {
		t.Fatalf("whenUnsatisfiable=%v, want ScheduleAnyway — a hard constraint makes the second replica unschedulable when one node fits", got)
	}
	if strings.Contains(stripComments(out), "DoNotSchedule") {
		t.Error("workload uses DoNotSchedule: the hardening causes the outage it prevents")
	}
}

func TestRenderPodDisruptionBudget(t *testing.T) {
	_, docs := render(t, sampleConfig())
	pdb, ok := docs["PodDisruptionBudget/datasphered"]
	if !ok {
		t.Fatal("no PodDisruptionBudget: a node drain would take the last loaded replica")
	}
	if got := pdb["apiVersion"]; got != "policy/v1" {
		t.Errorf("apiVersion=%v, want policy/v1", got)
	}
	if got := num(t, dig(pdb, "spec", "minAvailable")); got != 1 {
		t.Errorf("minAvailable=%d, want 1 (ADR 0008 decision 6)", got)
	}
	if got := dig(pdb, "spec", "selector", "matchLabels", "app.kubernetes.io/name"); got != "datasphered" {
		t.Errorf("PDB selects %v; it must select the keyholder pods", got)
	}
}

// TestRenderServicesPublishNotReadyAddressesWhereItMatters covers the
// distinction the three Services exist for. A sealed replica is never Ready, so
// which Service publishes not-ready endpoints decides what an application and an
// operator see during a seal:
//
//   - data (8443): must NOT publish them. A sealed replica holds no key
//     material; every call it accepted would be an ErrStorageSealed a Ready
//     sibling would have served.
//   - status (8444): MUST publish them, or when every replica is sealed the SDK
//     dials a Service with zero endpoints and gets an opaque connection error
//     instead of ErrStorageSealed — defeating ADR 0008 decision 7 in exactly the
//     scenario it was written for.
//   - unseal (9443): MUST publish them, or the unseal path cannot bootstrap at
//     all, because sealed is precisely when you need to reach the pod.
func TestRenderServicesPublishNotReadyAddressesWhereItMatters(t *testing.T) {
	_, docs := render(t, sampleConfig())

	dataSpec, ok := docs["Service/datasphered"]["spec"].(map[string]any)
	if !ok {
		t.Fatal("data Service has no spec")
	}
	if v, present := dataSpec["publishNotReadyAddresses"]; present && v != false {
		t.Errorf("data Service publishes not-ready addresses (%v); a sealed replica must not receive app traffic", v)
	}
	if got := dataSpec["type"]; got != "ClusterIP" {
		t.Errorf("data Service type=%v, want ClusterIP", got)
	}
	if got := num(t, dig(dataSpec, "ports", "0", "port")); got != 8443 {
		t.Errorf("data Service port=%d, want 8443", got)
	}

	for _, svc := range []struct {
		id   string
		port int64
		why  string
	}{
		{"Service/datasphered-status", 8444, "an all-sealed fleet would give the SDK a dial error instead of ErrStorageSealed"},
		{"Service/datasphered-unseal", 9443, "a sealed pod is never Ready, and sealed is when the unseal push must reach it"},
	} {
		spec, ok := docs[svc.id]["spec"].(map[string]any)
		if !ok {
			t.Fatalf("%s has no spec", svc.id)
		}
		if spec["publishNotReadyAddresses"] != true {
			t.Errorf("%s: publishNotReadyAddresses=%v, want true — %s", svc.id, spec["publishNotReadyAddresses"], svc.why)
		}
		if got := num(t, dig(spec, "ports", "0", "port")); got != svc.port {
			t.Errorf("%s port=%d, want %d", svc.id, got, svc.port)
		}
	}

	// The unseal Service is headless so each replica gets a stable
	// per-ordinal name: datasphered-0.datasphered-unseal.<ns>.svc.cluster.local.
	// Unsealing is per-replica, and "whichever pod the Service picked" is not an
	// answer when both must end up loaded.
	unseal := docs["Service/datasphered-unseal"]["spec"].(map[string]any)
	if got := unseal["clusterIP"]; got != "None" {
		t.Errorf("unseal Service clusterIP=%v, want None — without a headless Service the operator cannot address a replica deterministically", got)
	}
	if got := docs["Service/datasphered-status"]["spec"].(map[string]any)["clusterIP"]; got != nil {
		t.Errorf("status Service clusterIP=%v, want a normal virtual IP", got)
	}
}

// TestRenderLivenessIsNotSealGated is the test that must not be quietly fixed
// away. Liveness and readiness answer different questions here: readiness means
// "unsealed" and liveness means "the process is not wedged". Point liveness at
// the readiness endpoint and a sealed replica is killed, restarted, sealed
// again, and killed again — a crash loop whose only cure is the operator,
// during exactly the window ADR 0008 concedes the operator is absent. A seal is
// a correct state, not a fault.
func TestRenderLivenessIsNotSealGated(t *testing.T) {
	_, docs := render(t, sampleConfig())
	container, ok := dig(docs["StatefulSet/datasphered"], "spec", "template", "spec", "containers", "0").(map[string]any)
	if !ok {
		t.Fatal("StatefulSet has no container")
	}

	ready, live := container["readinessProbe"], container["livenessProbe"]
	if ready == nil {
		t.Fatal("no readinessProbe: a sealed replica would receive app traffic it can only refuse")
	}
	if live == nil {
		t.Fatal("no livenessProbe")
	}
	readyPath := dig(ready, "httpGet", "path")
	livePath := dig(live, "httpGet", "path")
	if readyPath != "/readyz" {
		t.Errorf("readinessProbe path=%v, want /readyz (503 while sealed)", readyPath)
	}
	if livePath != "/livez" {
		t.Errorf("livenessProbe path=%v, want /livez", livePath)
	}
	if readyPath == livePath {
		t.Fatalf("liveness and readiness share the endpoint %v: a seal would crash-loop the pod, and only an absent operator could stop it", livePath)
	}
	// Both ride the status port, which is the one listener a sealed replica
	// still answers on and the one the kubelet can reach unauthenticated.
	if got := dig(live, "httpGet", "port"); got != "status" {
		t.Errorf("livenessProbe port=%v, want the status port", got)
	}
	if got := dig(ready, "httpGet", "port"); got != "status" {
		t.Errorf("readinessProbe port=%v, want the status port", got)
	}
}

func TestRenderAutopilotCompliant(t *testing.T) {
	out, docs := render(t, sampleConfig())
	podSpec, _ := dig(docs["StatefulSet/datasphered"], "spec", "template", "spec").(map[string]any)
	container, _ := dig(podSpec, "containers", "0").(map[string]any)

	if got := dig(podSpec, "securityContext", "runAsNonRoot"); got != true {
		t.Errorf("runAsNonRoot=%v, want true", got)
	}
	if got := num(t, dig(podSpec, "securityContext", "runAsUser")); got != 65532 {
		t.Errorf("runAsUser=%d, want 65532", got)
	}
	if got := dig(podSpec, "securityContext", "seccompProfile", "type"); got != "RuntimeDefault" {
		t.Errorf("seccompProfile.type=%v, want RuntimeDefault", got)
	}
	if got := dig(container, "securityContext", "readOnlyRootFilesystem"); got != true {
		t.Errorf("readOnlyRootFilesystem=%v, want true", got)
	}
	if got := dig(container, "securityContext", "allowPrivilegeEscalation"); got != false {
		t.Errorf("allowPrivilegeEscalation=%v, want false", got)
	}
	if got := dig(container, "securityContext", "capabilities", "drop", "0"); got != "ALL" {
		t.Errorf("capabilities.drop=%v, want [ALL]", got)
	}
	if got := dig(container, "resources", "requests", "cpu"); got != "100m" {
		t.Errorf("cpu request=%v, want 100m", got)
	}
	if got := dig(container, "resources", "requests", "memory"); got != "128Mi" {
		t.Errorf("memory request=%v, want 128Mi", got)
	}
	for _, forbidden := range []string{"privileged: true", "hostNetwork", "hostPID", "hostIPC"} {
		if strings.Contains(stripComments(out), forbidden) {
			t.Errorf("workload must not use %q", forbidden)
		}
	}
}

// TestRenderDisablesTracebacks: a panic in the one process holding the derived
// bundle must not print goroutine stacks, and with core dumps disabled must not
// leave a copy of RAM on node disk either (ADR 0008 decision 1).
func TestRenderDisablesTracebacks(t *testing.T) {
	_, docs := render(t, sampleConfig())
	env, ok := dig(docs["StatefulSet/datasphered"], "spec", "template", "spec", "containers", "0", "env").([]any)
	if !ok {
		t.Fatal("container has no env")
	}
	for _, e := range env {
		m, _ := e.(map[string]any)
		if m["name"] == "GOTRACEBACK" {
			if m["value"] != "none" {
				t.Errorf("GOTRACEBACK=%v, want none", m["value"])
			}
			return
		}
	}
	t.Error("GOTRACEBACK is not set; a panic would print goroutine stacks from the process holding the bundle")
}

func TestRenderTLSMaterialArrivesThroughEnv(t *testing.T) {
	_, docs := render(t, sampleConfig())
	env, ok := dig(docs["StatefulSet/datasphered"], "spec", "template", "spec", "containers", "0", "env").([]any)
	if !ok {
		t.Fatal("container has no env")
	}
	want := map[string]string{
		"DATASPHERED_TLS_CA":   "ca.crt",
		"DATASPHERED_TLS_CERT": "server.crt",
		"DATASPHERED_TLS_KEY":  "server.key",
	}
	for _, e := range env {
		m, _ := e.(map[string]any)
		name, _ := m["name"].(string)
		key, ok := want[name]
		if !ok {
			continue
		}
		if got := dig(m, "valueFrom", "secretKeyRef", "name"); got != "datasphered-mtls" {
			t.Errorf("%s reads from secret %v, want datasphered-mtls", name, got)
		}
		if got := dig(m, "valueFrom", "secretKeyRef", "key"); got != key {
			t.Errorf("%s reads key %v, want %s", name, got, key)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("%s is not in the container env; with no volumes there is no other path for the TLS material", name)
	}
}

// TestRenderMTLSHashTracksTheMaterial: rotating the mTLS material must change
// the pod template, or nothing restarts. Kubernetes updates a Secret in place —
// and an env-injected value is not even re-read by the running container — while
// `datasphered` loads its certificate once at start-up. Without this fingerprint
// a rotation would update the Secret, leave the StatefulSet spec byte-identical,
// and let the rollout report success while the old certificate kept serving.
func TestRenderMTLSHashTracksTheMaterial(t *testing.T) {
	render := func(serverCert string) string {
		c := sampleConfig()
		c.ServerCertPEM = []byte(serverCert)
		out, err := Render(c)
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
		t.Error("rotating the server leaf left the fingerprint unchanged; the Pods would keep the old certificate")
	}
	if hash(first) != hash(same) {
		t.Error("identical material produced different fingerprints; every redeploy would churn the fleet")
	}
}

func TestRenderHonoursConfig(t *testing.T) {
	c := sampleConfig()
	c.Namespace, c.Name = "other-ns", "keyholder"
	c.Replicas = 3
	c.DataPort, c.StatusPort, c.UnsealPort = 9001, 9002, 9003

	_, docs := render(t, c)
	for _, want := range []string{
		"Namespace/other-ns",
		"StatefulSet/keyholder",
		"PodDisruptionBudget/keyholder",
		"Service/keyholder",
		"Service/keyholder-status",
		"Service/keyholder-unseal",
	} {
		if _, ok := docs[want]; !ok {
			t.Fatalf("missing %s; got %v", want, keys(docs))
		}
	}
	if got := num(t, dig(docs["StatefulSet/keyholder"], "spec", "replicas")); got != 3 {
		t.Errorf("replicas=%d, want 3", got)
	}
	if got := dig(docs["StatefulSet/keyholder"], "spec", "serviceName"); got != "keyholder-unseal" {
		t.Errorf("serviceName=%v, want keyholder-unseal", got)
	}
	if got := num(t, dig(docs["Service/keyholder-unseal"], "spec", "ports", "0", "port")); got != 9003 {
		t.Errorf("unseal port=%d, want 9003", got)
	}
	// The Secret name is fixed, not derived: it is a contract with the CLI that
	// writes it, exactly as fatline-mtls is.
	if _, ok := docs["Secret/datasphered-mtls"]; !ok {
		t.Errorf("mTLS secret is not datasphered-mtls; got %v", keys(docs))
	}
	// Every document lands in the configured namespace, or the apply would
	// scatter the workload across two.
	for id, doc := range docs {
		if strings.HasPrefix(id, "Namespace/") {
			continue
		}
		if got := dig(doc, "metadata", "namespace"); got != "other-ns" {
			t.Errorf("%s namespace=%v, want other-ns", id, got)
		}
	}
}

// TestRenderNamespaceMatchesFatLine keeps the shared document convergent. Both
// modules render the Namespace they deploy into and either stream may be applied
// first, so the document has to be identical rather than merely compatible — two
// managers writing the same value is a no-op, two writing different labels is a
// tug-of-war on every redeploy.
func TestRenderNamespaceMatchesFatLine(t *testing.T) {
	_, docs := render(t, sampleConfig())
	ns, ok := docs["Namespace/farcast-system"]
	if !ok {
		t.Fatal("no Namespace document")
	}
	if got := dig(ns, "metadata", "labels", "app.kubernetes.io/managed-by"); got != "farcast" {
		t.Errorf("namespace managed-by=%v, want farcast (FatLine renders the same document)", got)
	}
	if got := dig(ns, "metadata", "labels"); len(got.(map[string]any)) != 1 {
		t.Errorf("namespace labels=%v; FatLine renders exactly managed-by, and the two must agree", got)
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

// A keyholder with no bucket would start, pass its probes, and refuse every
// write — a failure that looks like a bug in the application. It is caught at
// render time instead.
func TestRenderRequiresAStorageTarget(t *testing.T) {
	for _, mutate := range []func(Config) Config{
		func(c Config) Config { c.Instance = ""; return c },
		func(c Config) Config { c.Bucket = ""; return c },
		func(c Config) Config { c.Instance, c.Bucket = "", ""; return c },
	} {
		if _, err := Render(mutate(sampleConfig())); err == nil {
			t.Error("Render accepted a config with no storage target")
		}
	}
}

// The target must reach the container, or the keyholder refuses to start and
// the Pod crash-loops with a message nobody sees until they read the logs.
func TestRenderPassesTheStorageTargetAsArguments(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"--instance=prod",
		"--bucket=farcast-prod-0a1b2c3d",
		"--provider=gcs",
		"--project=example-project",
		"--location=us-central1",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("rendered workload is missing %q", want)
		}
	}
}

// An empty project or location must be omitted rather than passed as an empty
// flag, which the adapter would read as a deliberate blank.
func TestRenderOmitsEmptyOptionalTargetFields(t *testing.T) {
	c := sampleConfig()
	c.Project, c.Location = "", ""
	out, err := Render(c)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, unwanted := range []string{"--project=", "--location="} {
		if strings.Contains(string(out), unwanted) {
			t.Errorf("rendered workload carries an empty %q", unwanted)
		}
	}
}

// The keyholder needs its own cloud identity: a grant on the namespace default
// account would hand the instance's storage to anything running beside it.
func TestRenderGivesTheKeyholderItsOwnServiceAccount(t *testing.T) {
	out, docs := render(t, sampleConfig())
	if _, ok := docs["ServiceAccount/datasphered"]; !ok {
		t.Fatal("no ServiceAccount rendered")
	}
	if !strings.Contains(string(out), "serviceAccountName: datasphered") {
		t.Error("the pod does not use the ServiceAccount that was rendered for it")
	}
	// And still no token is mounted: the metadata server identifies the Pod
	// from its ServiceAccount out of band.
	if !strings.Contains(string(out), "automountServiceAccountToken: false") {
		t.Error("a projected token was mounted; decision 1 forbids every volume")
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
