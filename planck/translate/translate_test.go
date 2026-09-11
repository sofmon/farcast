package translate

import (
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/manifest/parser"
)

const digest = "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func sampleConfig() Config {
	return Config{
		Manifest: parser.Manifest{
			Name: "my-platform",
			Apps: []parser.App{
				{Name: "api", Containerfile: "./services/api/Containerfile"},
				{Name: "web", Containerfile: "./services/web/Containerfile"},
			},
		},
		Images: map[string]string{
			"api": "reg/app/my-platform/api" + digest,
			"web": "reg/app/my-platform/web" + digest,
		},
		Credentials: map[string]string{
			"api": "api-egress-credential",
			"web": "web-egress-credential",
		},
		Instance:          "p42",
		StorageScope:      "app",
		StorageServerName: "p42.datasphered.farcast",
		StorageCAPEM:      []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"),
		SecretsPrefix:     "app/secrets/",
		Identities: map[string]AppIdentity{
			"api": {CertPEM: []byte("-----BEGIN CERTIFICATE-----\nAPILEAF\n-----END CERTIFICATE-----"), KeyPEM: []byte("-----BEGIN PRIVATE KEY-----\nAPIKEY\n-----END PRIVATE KEY-----")},
			"web": {CertPEM: []byte("-----BEGIN CERTIFICATE-----\nWEBLEAF\n-----END CERTIFICATE-----"), KeyPEM: []byte("-----BEGIN PRIVATE KEY-----\nWEBKEY\n-----END PRIVATE KEY-----")},
		},
	}
}

func render(t *testing.T, c Config) (string, []map[string]any) {
	t.Helper()
	out, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	var docs []map[string]any
	for _, d := range strings.Split(string(out), "\n---\n") {
		if strings.TrimSpace(d) == "" {
			continue
		}
		var m map[string]any
		if err := yaml.Unmarshal([]byte(d), &m); err != nil {
			t.Fatalf("rendered document is not valid YAML: %v\n%s", err, d)
		}
		docs = append(docs, m)
	}
	return string(out), docs
}

func pick(t *testing.T, docs []map[string]any, kind, name string) map[string]any {
	t.Helper()
	for _, d := range docs {
		k, _ := d["kind"].(string)
		meta, _ := d["metadata"].(map[string]any)
		if k == kind && meta != nil && meta["name"] == name {
			return d
		}
	}
	t.Fatalf("no %s named %q in the rendered stream", kind, name)
	return nil
}

func at(t *testing.T, doc map[string]any, path ...string) any {
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

func labels(t *testing.T, v any) map[string]string {
	t.Helper()
	raw, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("not a label map: %T", v)
	}
	out := map[string]string{}
	for k, val := range raw {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}

func TestRenderProducesOneNamespaceAndFiveDocumentsPerApp(t *testing.T) {
	_, docs := render(t, sampleConfig())
	if len(docs) != 1+2*5 {
		t.Fatalf("rendered %d documents, want 11 (a namespace plus five per app)", len(docs))
	}
	pick(t, docs, "Namespace", "my-platform")
	for _, app := range []string{"api", "web"} {
		for _, kind := range []string{"ConfigMap", "Deployment", "Service", "NetworkPolicy"} {
			pick(t, docs, kind, app)
		}
	}
}

// The 4.1 walk's lesson, applied before it can bite again: a controller does
// not copy its own labels onto the pods it creates, and TechnoCore meters
// PODS. Without managed-by on the pod template the application is invisible to
// the cost meter — which then reports $0 and looks healthy.
func TestEveryPodTemplateCarriesTheLabelsTheKernelNeeds(t *testing.T) {
	_, docs := render(t, sampleConfig())
	for _, app := range []string{"api", "web"} {
		dep := pick(t, docs, "Deployment", app)
		pod := labels(t, at(t, dep, "spec", "template", "metadata", "labels"))
		if pod["app.kubernetes.io/managed-by"] != "farcast" {
			t.Errorf("%s pod template lacks managed-by; the cost meter would not see it", app)
		}
		if pod["farcast.sofmon.com/tier"] != "app" {
			t.Errorf("%s pod tier = %q, want app", app, pod["farcast.sofmon.com/tier"])
		}
		// And on the workload, which is what a shutdown scales.
		wl := labels(t, at(t, dep, "metadata", "labels"))
		if wl["farcast.sofmon.com/tier"] != "app" {
			t.Errorf("%s workload tier = %q, want app — an unclassified workload is protected, "+
				"so a cost shutdown could not contain it", app, wl["farcast.sofmon.com/tier"])
		}
	}
}

// An application does not get its own public address: the instance has exactly
// one point of presence and it is FatLine's. A LoadBalancer here would hand
// every app a way around the boundary and a standing bill nobody approved.
func TestServicesAreClusterIPNeverLoadBalancer(t *testing.T) {
	out, docs := render(t, sampleConfig())
	for _, app := range []string{"api", "web"} {
		if got := at(t, pick(t, docs, "Service", app), "spec", "type"); got != "ClusterIP" {
			t.Errorf("%s service type = %v, want ClusterIP", app, got)
		}
	}
	// As YAML values, not as words: the template's own comment explains why
	// ClusterIP is used, and a bare substring search matches the explanation.
	for _, forbidden := range []string{"type: LoadBalancer", "type: NodePort", "externalIPs", "hostPort"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("a translated workload must never publish itself outside the cluster (%q)", forbidden)
		}
	}
	// Every Service in the stream, not only the two looked up by name.
	for _, d := range docs {
		if k, _ := d["kind"].(string); k != "Service" {
			continue
		}
		if got := at(t, d, "spec", "type"); got != "ClusterIP" {
			t.Errorf("a Service has type %v", got)
		}
	}
}

// Deny-by-default has to be real rather than advisory: an app that ignores
// FARCAST_FATLINE_PROXY must fail, not find another route out.
func TestEgressIsDeniedExceptDNSFatLineAndStorage(t *testing.T) {
	_, docs := render(t, sampleConfig())
	np := pick(t, docs, "NetworkPolicy", "api")

	types := at(t, np, "spec", "policyTypes").([]any)
	if len(types) != 2 || fmt.Sprint(types) != "[Ingress Egress]" {
		t.Fatalf("policyTypes = %v, want both Ingress and Egress — an Egress-less policy denies nothing outbound", types)
	}

	rules := at(t, np, "spec", "egress").([]any)
	if len(rules) != 3 {
		t.Fatalf("egress has %d rules, want 3 (DNS, FatLine, storage): %v", len(rules), rules)
	}

	// Every rule must name both a destination and a port; a rule with an
	// empty `to` allows the entire internet.
	for i, r := range rules {
		m := r.(map[string]any)
		to, ok := m["to"].([]any)
		if !ok || len(to) == 0 {
			t.Errorf("egress rule %d has no destination, which allows everything", i)
		}
		if ports, ok := m["ports"].([]any); !ok || len(ports) == 0 {
			t.Errorf("egress rule %d names no ports", i)
		}
	}
}

// Storage is optional. Without a scope the app gets no storage variables and
// no route to the keyholder — rather than a route to a keyholder it has no
// credentials for.
func TestWithoutStorageThereIsNoStorageEnvOrEgress(t *testing.T) {
	c := sampleConfig()
	c.StorageScope, c.StorageCAPEM = "", nil
	out, docs := render(t, c)

	if strings.Contains(out, "FARCAST_STORAGE_") {
		t.Error("storage variables were injected for a deployment with no scope")
	}
	rules := at(t, pick(t, docs, "NetworkPolicy", "api"), "spec", "egress").([]any)
	if len(rules) != 2 {
		t.Errorf("egress has %d rules, want 2 (DNS and FatLine only)", len(rules))
	}
	// The proxy is always injected: an app with no storage still has a
	// boundary to respect.
	if !strings.Contains(out, "FARCAST_FATLINE_PROXY") {
		t.Error("the egress proxy variable is not optional")
	}
}

func TestTheSDKContractReachesTheContainer(t *testing.T) {
	_, docs := render(t, sampleConfig())
	cm := at(t, pick(t, docs, "ConfigMap", "api"), "data").(map[string]any)
	// FARCAST_FATLINE_PROXY is deliberately NOT here: it carries the app's
	// egress credential and lives in the Secret (ADR 0013).
	if _, ok := cm["FARCAST_FATLINE_PROXY"]; ok {
		t.Error("the proxy address is in the ConfigMap; it carries a credential and belongs in the Secret")
	}
	for _, key := range []string{
		"FARCAST_STORAGE_ENDPOINT", "FARCAST_STORAGE_STATUS_ENDPOINT",
		"FARCAST_STORAGE_SCOPE", "FARCAST_STORAGE_SERVER_NAME", "FARCAST_STORAGE_CA",
	} {
		if v, ok := cm[key]; !ok || v == "" {
			t.Errorf("ConfigMap is missing %s", key)
		}
	}
	if !strings.HasPrefix(cm["FARCAST_STORAGE_ENDPOINT"].(string), "https://") {
		t.Error("the storage endpoint must be https")
	}
	if !strings.Contains(cm["FARCAST_STORAGE_CA"].(string), "BEGIN CERTIFICATE") {
		t.Errorf("the CA did not survive rendering: %q", cm["FARCAST_STORAGE_CA"])
	}
	// The address and the identity are separate values and must not be
	// conflated (sdk/go's FARCAST_STORAGE_SERVER_NAME).
	if strings.Contains(cm["FARCAST_STORAGE_ENDPOINT"].(string), cm["FARCAST_STORAGE_SERVER_NAME"].(string)) {
		t.Error("the endpoint and the pinned server name should not be the same string")
	}
	// And the container actually consumes it.
	dep := pick(t, docs, "Deployment", "api")
	containers := at(t, dep, "spec", "template", "spec", "containers").([]any)
	c0 := containers[0].(map[string]any)
	if _, ok := c0["envFrom"]; !ok {
		t.Error("the container does not read its ConfigMap")
	}
}

// An application has no business reaching the API server, and a projected
// token is the difference between an app compromise and a cluster compromise.
func TestApplicationsGetNoKubernetesIdentity(t *testing.T) {
	_, docs := render(t, sampleConfig())
	spec := at(t, pick(t, docs, "Deployment", "api"), "spec", "template", "spec").(map[string]any)
	if spec["automountServiceAccountToken"] != false {
		t.Errorf("automountServiceAccountToken = %v, want false", spec["automountServiceAccountToken"])
	}
	if _, ok := spec["serviceAccountName"]; ok {
		t.Error("a translated application must not be given a ServiceAccount")
	}
}

func TestRenderIsAutopilotCompliant(t *testing.T) {
	out, _ := render(t, sampleConfig())
	for _, want := range []string{
		"allowPrivilegeEscalation: false", "type: RuntimeDefault",
		fmt.Sprintf("cpu: %dm", RequestCPUMilli), fmt.Sprintf("memory: %dMi", RequestMemMiB), "- ALL",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered workload missing %q", want)
		}
	}
	for _, forbidden := range []string{"privileged: true", "hostNetwork", "hostPath", "hostPID"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("workload must not use %q", forbidden)
		}
	}
}

// A translation that guessed an image, or emitted a tag, would deploy
// something other than what was built.
func TestRenderRefusesAnythingNotDigestPinned(t *testing.T) {
	cases := map[string]func(*Config){
		"no image at all": func(c *Config) { delete(c.Images, "web") },
		"floating tag":    func(c *Config) { c.Images["web"] = "reg/app/web:latest" },
		"short digest":    func(c *Config) { c.Images["web"] = "reg/app/web@sha256:abc" },
		"non-hex digest":  func(c *Config) { c.Images["web"] = "reg/app/web@sha256:" + strings.Repeat("z", 64) },
	}
	for name, mutate := range cases {
		c := sampleConfig()
		mutate(&c)
		if _, err := Render(c); err == nil {
			t.Errorf("%s: expected a refusal", name)
		}
	}
}

func TestRenderRefusesNamespacesThatAreNotItsToUse(t *testing.T) {
	for _, ns := range []string{"farcast-system", "kube-system", "kube-public"} {
		c := sampleConfig()
		c.Namespace = ns
		if _, err := Render(c); err == nil {
			t.Errorf("namespace %q was accepted", ns)
		}
	}
}

func TestRenderValidatesNames(t *testing.T) {
	bad := []string{"Has-Capitals", "-leading", "trailing-", "under_score", strings.Repeat("a", 64), "with space"}
	for _, name := range bad {
		c := sampleConfig()
		c.Manifest.Apps[0].Name = name
		c.Images[name] = "reg/app/x" + digest
		if _, err := Render(c); err == nil {
			t.Errorf("app name %q was accepted", name)
		}
	}
	for _, ns := range bad {
		c := sampleConfig()
		c.Namespace = ns
		if _, err := Render(c); err == nil {
			t.Errorf("namespace %q was accepted", ns)
		}
	}

	// An empty namespace is not invalid — it defaults to the manifest's name,
	// which is the documented behaviour and is checked elsewhere. An empty
	// app name has no such fallback and must be refused.
	c := sampleConfig()
	c.Namespace = ""
	if _, err := Render(c); err != nil {
		t.Errorf("an empty namespace should default to the manifest name, got %v", err)
	}
	c = sampleConfig()
	c.Manifest.Apps[0].Name = ""
	if _, err := Render(c); err == nil {
		t.Error("an app with no name was accepted")
	}
}

func TestRenderRefusesDuplicateAndEmptyManifests(t *testing.T) {
	dup := sampleConfig()
	dup.Manifest.Apps = append(dup.Manifest.Apps, parser.App{Name: "api"})
	if _, err := Render(dup); err == nil {
		t.Error("a manifest with two apps of the same name was accepted")
	}

	empty := sampleConfig()
	empty.Manifest.Apps = nil
	if _, err := Render(empty); err == nil {
		t.Error("a manifest declaring no apps was accepted")
	}

	unnamed := sampleConfig()
	unnamed.Manifest.Name = ""
	if _, err := Render(unnamed); err == nil {
		t.Error("a manifest with no name was accepted")
	}
}

// The namespace defaults to the manifest's name but is separable, so the same
// repository can be deployed twice without editing it.
func TestNamespaceDefaultsToTheManifestNameAndIsOverridable(t *testing.T) {
	_, docs := render(t, sampleConfig())
	pick(t, docs, "Namespace", "my-platform")

	c := sampleConfig()
	c.Namespace = "staging"
	_, docs = render(t, c)
	pick(t, docs, "Namespace", "staging")
	if got := at(t, pick(t, docs, "Deployment", "api"), "metadata", "namespace"); got != "staging" {
		t.Errorf("deployment namespace = %v, want staging", got)
	}
}

// Found on the 4.2 walk, on a live cluster, and it made another criterion
// unreadable: with DNS broken an application cannot reach anything, so
// "blocked from the internet" and "cannot resolve" look identical and the
// egress test proves nothing.
//
// GKE Autopilot runs NodeLocal DNSCache, which listens on a LINK-LOCAL
// address. A rule permitting DNS "to the kube-system namespace" is correct on
// a cluster without the cache and silently wrong on one with it.
func TestDNSReachesTheNodeLocalCacheAsWellAsKubeDNS(t *testing.T) {
	_, docs := render(t, sampleConfig())
	rules := at(t, pick(t, docs, "NetworkPolicy", "api"), "spec", "egress").([]any)

	var dns map[string]any
	for _, r := range rules {
		m := r.(map[string]any)
		for _, p := range m["ports"].([]any) {
			if fmt.Sprint(p.(map[string]any)["port"]) == "53" {
				dns = m
			}
		}
	}
	if dns == nil {
		t.Fatal("no DNS rule; an application would resolve nothing")
	}

	var viaNamespace, viaNodeLocal bool
	for _, d := range dns["to"].([]any) {
		m := d.(map[string]any)
		if _, ok := m["namespaceSelector"]; ok {
			viaNamespace = true
		}
		if b, ok := m["ipBlock"].(map[string]any); ok && fmt.Sprint(b["cidr"]) == NodeLocalDNS {
			viaNodeLocal = true
		}
	}
	if !viaNamespace {
		t.Error("DNS does not reach kube-dns directly")
	}
	if !viaNodeLocal {
		t.Errorf("DNS does not reach %s; on GKE Autopilot that is where it lives", NodeLocalDNS)
	}
	if !strings.HasSuffix(NodeLocalDNS, "/32") {
		t.Errorf("NodeLocalDNS = %q; it must stay a single address", NodeLocalDNS)
	}
}

// The Service an application is pointed at and the pod label its policy
// selects are different names, and conflating them yields a configuration
// that looks right and permits nothing.
//
// Found on the 4.2 walk: FARCAST_FATLINE_PROXY named "fatline", which is the
// tunnel's public Service and does not publish the proxy port.
func TestTheProxyAddressIsTheEgressServiceAndThePolicySelectsThePods(t *testing.T) {
	_, docs := render(t, sampleConfig())

	proxy := at(t, pick(t, docs, "Secret", "api-egress"), "stringData").(map[string]any)["FARCAST_FATLINE_PROXY"].(string)
	if !strings.Contains(proxy, FatLineService) {
		t.Errorf("proxy = %q, want the egress Service %q", proxy, FatLineService)
	}
	if FatLineService == FatLineWorkload {
		t.Error("the Service and the workload must not share a name; the tunnel's Service does not publish the proxy port")
	}

	// The policy selects PODS, which carry the workload's name, not the
	// Service's.
	rules := at(t, pick(t, docs, "NetworkPolicy", "api"), "spec", "egress").([]any)
	var found bool
	for _, r := range rules {
		for _, d := range r.(map[string]any)["to"].([]any) {
			m := d.(map[string]any)
			ps, ok := m["podSelector"].(map[string]any)
			if !ok {
				continue
			}
			labels := ps["matchLabels"].(map[string]any)
			if labels["app.kubernetes.io/name"] == FatLineWorkload {
				found = true
			}
			if labels["app.kubernetes.io/name"] == FatLineService {
				t.Error("the policy selects pods by the SERVICE name; no pod carries it and the rule permits nothing")
			}
		}
	}
	if !found {
		t.Errorf("no egress rule selects FatLine's pods (%q)", FatLineWorkload)
	}
}

// The credential is what identifies an application to FatLine, so it must
// reach the container — and must not be somewhere every reader of ConfigMaps
// can see it (ADR 0013).
func TestEachAppGetsItsOwnCredentialInItsOwnSecret(t *testing.T) {
	out, docs := render(t, sampleConfig())

	seen := map[string]string{}
	for _, app := range []string{"api", "web"} {
		sec := at(t, pick(t, docs, "Secret", app+"-egress"), "stringData").(map[string]any)
		proxy, ok := sec["FARCAST_FATLINE_PROXY"].(string)
		if !ok || proxy == "" {
			t.Fatalf("%s has no proxy address", app)
		}
		if !strings.Contains(proxy, "-egress-credential@") {
			t.Errorf("%s's proxy address carries no credential: %q", app, proxy)
		}
		seen[app] = proxy
	}
	if seen["api"] == seen["web"] {
		t.Fatal("both applications were given the same egress address; they would be indistinguishable to FatLine")
	}

	// The Deployment must actually consume it, or the credential is written
	// and never presented.
	var sourced bool
	for _, c := range at(t, pick(t, docs, "Deployment", "api"), "spec", "template", "spec", "containers").([]any) {
		for _, e := range c.(map[string]any)["envFrom"].([]any) {
			if ref, ok := e.(map[string]any)["secretRef"].(map[string]any); ok && ref["name"] == "api-egress" {
				sourced = true
			}
		}
	}
	if !sourced {
		t.Error("the app's Deployment does not read its egress Secret")
	}

	// And no credential leaked into a ConfigMap on the way.
	for _, d := range docs {
		if d["kind"] != "ConfigMap" {
			continue
		}
		if strings.Contains(fmt.Sprint(d["data"]), "-egress-credential") {
			t.Errorf("a credential reached a ConfigMap: %v", d["metadata"])
		}
	}
	_ = out
}

// An app with no credential would deploy, reach nothing, and report it as an
// unidentified caller rather than as the misconfiguration it is.
func TestTranslateRefusesAnAppWithNoCredential(t *testing.T) {
	c := sampleConfig()
	delete(c.Credentials, "web")
	if _, err := Render(c); err == nil {
		t.Fatal("Render accepted an app with no egress credential")
	}
}

// Each application is pointed at its own secrets subtree, fully qualified.
//
// The SDK never derives this: a prefix guessed one segment away addresses
// somebody else's subtree, or one the keyholder does not protect.
func TestEachAppGetsItsOwnSecretsPrefix(t *testing.T) {
	_, docs := render(t, sampleConfig())
	for app, want := range map[string]string{
		"api": "app/secrets/api/",
		"web": "app/secrets/web/",
	} {
		cm := at(t, pick(t, docs, "ConfigMap", app), "data").(map[string]any)
		if got := cm["FARCAST_SECRETS_PREFIX"]; got != want {
			t.Errorf("%s: FARCAST_SECRETS_PREFIX = %v, want %q", app, got, want)
		}
	}
}

// An instance recorded before the scope prefix was written down gets no
// secrets wiring rather than a guessed one. The SDK then reports the
// capability as absent, which is true.
func TestWithoutASecretsPrefixNoSecretsAreWired(t *testing.T) {
	c := sampleConfig()
	c.SecretsPrefix = ""
	out, _ := render(t, c)
	if strings.Contains(out, "FARCAST_SECRETS_PREFIX") {
		t.Error("a secrets prefix was rendered for an instance that has none recorded")
	}
}

func TestASecretsPrefixMustEndAtASegmentBoundary(t *testing.T) {
	c := sampleConfig()
	c.SecretsPrefix = "app/secrets"
	if _, err := Render(c); err == nil {
		t.Error("Render accepted a prefix that claims a partial name")
	}
}

// Ambient identity reaches the container.
//
// Without it the SDK stamps every log record with the executable's base name
// and the string "local", so two applications built from one image are
// indistinguishable in the operator's log stream — and farcast.AppName(), the
// accessor ADR 0017 points applications at because Config refuses this
// namespace, answers with something the manifest never said. Found live on the
// 5.3 walk, where both applications logged themselves as "demo".
func TestAmbientIdentityReachesEachApp(t *testing.T) {
	_, docs := render(t, sampleConfig())
	for _, app := range []string{"api", "web"} {
		cm := at(t, pick(t, docs, "ConfigMap", app), "data").(map[string]any)
		if got := cm["FARCAST_APP_NAME"]; got != app {
			t.Errorf("%s: FARCAST_APP_NAME = %v, want %q", app, got, app)
		}
		if got := cm["FARCAST_INSTANCE_ID"]; got != "p42" {
			t.Errorf("%s: FARCAST_INSTANCE_ID = %v, want the instance", app, got)
		}
	}
}

// A deployment rendered without an instance name carries no instance variable
// rather than an empty one: the SDK's own "local" fallback is a truer answer
// than a blank string that looks like an identity.
func TestWithoutAnInstanceNoInstanceIDIsRendered(t *testing.T) {
	c := sampleConfig()
	c.Instance = ""
	out, _ := render(t, c)
	if strings.Contains(out, "FARCAST_INSTANCE_ID") {
		t.Error("an empty instance id was rendered")
	}
	if !strings.Contains(out, "FARCAST_APP_NAME") {
		t.Error("the app name is not optional")
	}
}

// Each application's storage identity reaches the container beside its egress
// credential, in the Secret and never in the ConfigMap (ADR 0018 decision 6).
func TestEachAppGetsItsOwnStorageIdentityInTheSecret(t *testing.T) {
	_, docs := render(t, sampleConfig())
	for app, marker := range map[string]string{"api": "APILEAF", "web": "WEBLEAF"} {
		sec := at(t, pick(t, docs, "Secret", app+"-egress"), "stringData").(map[string]any)
		cert, _ := sec["FARCAST_STORAGE_CLIENT_CERT"].(string)
		key, _ := sec["FARCAST_STORAGE_CLIENT_KEY"].(string)
		if !strings.Contains(cert, marker) {
			t.Errorf("%s: FARCAST_STORAGE_CLIENT_CERT does not carry %s's own leaf", app, app)
		}
		if !strings.Contains(key, strings.ToUpper(app)+"KEY") {
			t.Errorf("%s: FARCAST_STORAGE_CLIENT_KEY does not carry %s's own key", app, app)
		}
		// A ConfigMap is readable by anything that can read ConfigMaps.
		cm := at(t, pick(t, docs, "ConfigMap", app), "data").(map[string]any)
		if _, leaked := cm["FARCAST_STORAGE_CLIENT_KEY"]; leaked {
			t.Errorf("%s: the private key is in the ConfigMap", app)
		}
	}
}

// The keyholder admits only callers it can identify, so an application
// deployed with storage and no identity would reach nothing and report a
// transport failure. Refused here, where the message can say what is missing.
func TestStorageWiredWithoutAnIdentityIsRefused(t *testing.T) {
	c := sampleConfig()
	delete(c.Identities, "web")
	_, err := Render(c)
	if err == nil {
		t.Fatal("Render deployed an application with storage and no identity")
	}
	if !strings.Contains(err.Error(), "web") || !strings.Contains(err.Error(), "identity") {
		t.Errorf("err = %v, want it to name the app and the missing identity", err)
	}
}

// Without storage there is nothing to identify to, and no key should be
// minted or rendered for it.
func TestWithoutStorageNoIdentityIsRenderedOrRequired(t *testing.T) {
	c := sampleConfig()
	c.StorageScope, c.StorageCAPEM, c.SecretsPrefix, c.Identities = "", nil, "", nil
	out, _ := render(t, c)
	if strings.Contains(out, "FARCAST_STORAGE_CLIENT") {
		t.Error("a storage identity was rendered for a deployment with no storage")
	}
}
