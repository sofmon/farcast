package deploy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

const testImage = "us-central1-docker.pkg.dev/p/farcast-i/system/technocore@sha256:" +
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func sampleConfig() Config {
	return Config{Image: testImage, Instance: "p41", CostLimit: 50}
}

func docs(t *testing.T, out []byte) []map[string]any {
	t.Helper()
	var res []map[string]any
	for _, d := range strings.Split(string(out), "\n---\n") {
		if strings.TrimSpace(d) == "" {
			continue
		}
		var m map[string]any
		if err := yaml.Unmarshal([]byte(d), &m); err != nil {
			t.Fatalf("rendered document is not valid YAML: %v\n%s", err, d)
		}
		res = append(res, m)
	}
	return res
}

func ofKind(t *testing.T, out []byte, kind string) []map[string]any {
	t.Helper()
	var res []map[string]any
	for _, d := range docs(t, out) {
		if k, _ := d["kind"].(string); k == kind {
			res = append(res, d)
		}
	}
	return res
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

func TestRenderProducesTheWholeWorkload(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"Namespace", "ServiceAccount", "ClusterRole", "RoleBinding", "Role", "Deployment"} {
		if len(ofKind(t, out, kind)) == 0 {
			t.Errorf("missing a %s document", kind)
		}
	}
}

func TestRenderValidation(t *testing.T) {
	cases := map[string]Config{
		"missing image":     {Instance: "p41", CostLimit: 50},
		"floating tag":      {Image: "repo/technocore:latest", Instance: "p41", CostLimit: 50},
		"short digest":      {Image: "repo/technocore@sha256:abc", Instance: "p41", CostLimit: 50},
		"non-hex digest":    {Image: "repo/technocore@sha256:" + strings.Repeat("z", 64), Instance: "p41", CostLimit: 50},
		"missing instance":  {Image: testImage, CostLimit: 50},
		"zero cost limit":   {Image: testImage, Instance: "p41"},
		"negative limit":    {Image: testImage, Instance: "p41", CostLimit: -1},
		"managed namespace": {Image: testImage, Instance: "p41", CostLimit: 50, Meter: []string{"farcast-system", "kube-system"}},
		"empty namespace":   {Image: testImage, Instance: "p41", CostLimit: 50, Meter: []string{""}},
	}
	for name, c := range cases {
		if _, err := Render(c); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// A kernel deployed with no limit would meter an instance and never act,
// which is the one configuration that looks like cost control and is not.
func TestAKernelWithoutALimitIsRefusedAtRenderTime(t *testing.T) {
	c := sampleConfig()
	c.CostLimit = 0
	_, err := Render(c)
	if err == nil || !strings.Contains(err.Error(), "enforces nothing") {
		t.Fatalf("err = %v, want a refusal naming what a zero limit means", err)
	}
}

// The rule set is a ClusterRole so it can be written once, but binding it
// cluster-wide would hand the kernel every pod in the cluster — including the
// managed namespaces ADR 0003 puts out of bounds. RoleBindings grant it in
// named namespaces only.
func TestPermissionsAreNeverGrantedClusterWide(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(ofKind(t, out, "ClusterRoleBinding")); n != 0 {
		t.Fatalf("rendered %d ClusterRoleBindings; the kernel must never hold cluster-wide grants", n)
	}
	if !strings.Contains(string(out), "kind: ClusterRole\n") {
		t.Error("expected a ClusterRole carrying the rules")
	}
}

// The verbs are exactly what technocore/kube calls. Anything beyond that is
// permission the kernel was never designed to need.
func TestTheClusterRoleGrantsOnlyWhatTheClientCalls(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	cr := ofKind(t, out, "ClusterRole")[0]
	rules, ok := cr["rules"].([]any)
	if !ok {
		t.Fatal("ClusterRole has no rules")
	}

	// Keyed by API GROUP and resource, not resource alone: "pods" in the core
	// group is what Autopilot bills, and "pods" in metrics.k8s.io is what one
	// is using. Collapsing them would let a grant on either look like a grant
	// on the other.
	got := map[string][]string{}
	for _, r := range rules {
		m := r.(map[string]any)
		for _, g := range m["apiGroups"].([]any) {
			group := g.(string)
			if group == "" {
				group = "core"
			}
			for _, res := range m["resources"].([]any) {
				for _, v := range m["verbs"].([]any) {
					key := group + "/" + res.(string)
					got[key] = append(got[key], v.(string))
				}
			}
		}
	}
	want := map[string][]string{
		"core/pods":              {"list"},
		"apps/deployments":       {"list"},
		"apps/deployments/scale": {"patch"},
		"metrics.k8s.io/pods":    {"list"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("cluster rules = %v, want exactly %v", got, want)
	}

	// The loop polls, so it never needs watch; the shutdown scales, so it
	// never needs delete. Both would be permission granted for a design the
	// kernel does not have.
	for _, forbidden := range []string{"watch", "delete", "deletecollection", "escalate", "bind", "impersonate"} {
		if strings.Contains(string(out), `"`+forbidden+`"`) {
			t.Errorf("the kernel must not be granted %q", forbidden)
		}
	}
}

// Kubernetes cannot restrict create by resourceName, so create is namespace
// scoped and everything afterwards is pinned to the one object. Without the
// pin the kernel could read and rewrite any ConfigMap in the namespace it
// shares with FatLine and datasphered.
func TestTheLedgerRoleIsPinnedToItsOwnConfigMap(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	role := ofKind(t, out, "Role")[0]
	rules := at(t, role, "rules").([]any)

	// The property, not a count: exactly one rule may be unnamed, it may
	// grant only create, and every other rule must be pinned to a specific
	// object. Asserting a rule count instead would have to be edited every
	// time a ConfigMap is added, and an assertion that gets edited to pass is
	// not an assertion.
	var named, unnamed map[string]any
	unnamedCount := 0
	for _, r := range rules {
		m := r.(map[string]any)
		if _, ok := m["resourceNames"]; !ok {
			unnamed = m
			unnamedCount++
			continue
		}
		if fmt.Sprint(m["resourceNames"]) == "[technocore-ledger]" {
			named = m
		}
		// No pinned rule may grant list: listing defeats the pin by
		// returning every ConfigMap in the namespace.
		for _, v := range m["verbs"].([]any) {
			if v == "list" || v == "watch" {
				t.Errorf("rule %v grants %v, which defeats the resourceName pin", m["resourceNames"], v)
			}
		}
	}
	if unnamedCount != 1 {
		t.Fatalf("ledger Role has %d unnamed rules, want exactly 1 (create, which cannot be name-restricted)", unnamedCount)
	}

	// The kernel may write its OWN state and nothing else. The confirmations
	// and the metered-namespace list are the OPERATOR's inputs: a kernel that
	// could edit either could correct its own estimate or narrow its own
	// scope, and a narrowed scope looks identical to an instance that is not
	// spending anything.
	writable := map[string]bool{}
	for _, r := range rules {
		m := r.(map[string]any)
		names, ok := m["resourceNames"]
		if !ok {
			continue
		}
		for _, v := range m["verbs"].([]any) {
			switch v {
			case "update", "patch", "create", "delete", "deletecollection":
				writable[fmt.Sprint(names)] = true
			}
		}
	}
	own := map[string]bool{"[technocore-ledger]": true, "[technocore-profiles]": true}
	for name := range writable {
		if !own[name] {
			t.Errorf("the kernel may write %v, which is not its own state", name)
		}
	}
	for name := range own {
		if !writable[name] {
			t.Errorf("the kernel cannot write %v, which is its own state", name)
		}
	}
	// Named for what they are, so this test fails if an operator input ever
	// becomes writable rather than quietly widening with the set above.
	for _, operatorInput := range []string{"[technocore-confirmed]", "[technocore-namespaces]"} {
		if writable[operatorInput] {
			t.Errorf("%s is an operator input and must be read-only to the kernel", operatorInput)
		}
	}
	if named == nil || unnamed == nil {
		t.Fatal("expected one named and one unnamed configmap rule")
	}
	if fmt.Sprint(unnamed["verbs"]) != "[create]" {
		t.Errorf("the unnamed rule grants %v; only create cannot be name-restricted", unnamed["verbs"])
	}
	if fmt.Sprint(named["resourceNames"]) != "[technocore-ledger]" {
		t.Errorf("named rule covers %v, want just the ledger", named["resourceNames"])
	}
	for _, v := range named["verbs"].([]any) {
		if v == "list" {
			t.Error("list on configmaps would defeat the resourceName pin")
		}
	}
}

// The kernel reads the operator's confirmations and must never be able to
// write one. A kernel that could author a confirmation could fabricate the one
// input that corrects its own estimate — which, with the calibration clamp,
// is what makes a confirmed figure untrusted input twice over rather than once.
func TestTheKernelCanReadConfirmationsButNeverWriteThem(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	var rule map[string]any
	for _, r := range at(t, ofKind(t, out, "Role")[0], "rules").([]any) {
		m := r.(map[string]any)
		if fmt.Sprint(m["resourceNames"]) == "[technocore-confirmed]" {
			rule = m
		}
	}
	if rule == nil {
		t.Fatal("no rule grants the kernel access to the confirmations it is supposed to read")
	}
	if fmt.Sprint(rule["verbs"]) != "[get]" {
		t.Errorf("confirmations verbs = %v, want exactly [get]", rule["verbs"])
	}
}

// A rolling update runs two kernels at once; both would meter into their own
// ledgers and race to write the same checkpoint, and the period's spending
// would become whichever wrote last.
func TestTheKernelIsASingleReplicaReplacedNotOverlapped(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	dep := ofKind(t, out, "Deployment")[0]
	if got := at(t, dep, "spec", "replicas"); got != uint64(1) && got != 1 {
		t.Errorf("replicas = %v, want 1 — the ledger has one writer", got)
	}
	if got := at(t, dep, "spec", "strategy", "type"); got != "Recreate" {
		t.Errorf("strategy = %v, want Recreate — a rolling update would run two meters at once", got)
	}
	// A PDB on a single replica makes every drain hang forever.
	if len(ofKind(t, out, "PodDisruptionBudget")) != 0 {
		t.Error("a single-replica workload must not carry a PDB; the drain would never complete")
	}
}

// The kernel's whole job is talking to the API server, so unlike datasphered
// it does need its projected token.
func TestTheKernelGetsItsServiceAccountToken(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	dep := ofKind(t, out, "Deployment")[0]
	if got := at(t, dep, "spec", "template", "spec", "automountServiceAccountToken"); got != true {
		t.Errorf("automountServiceAccountToken = %v, want true", got)
	}
	if got := at(t, dep, "spec", "template", "spec", "serviceAccountName"); got != DefaultName {
		t.Errorf("serviceAccountName = %v, want %q", got, DefaultName)
	}
}

func TestRenderIsAutopilotCompliant(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"runAsNonRoot: true", "allowPrivilegeEscalation: false", "readOnlyRootFilesystem: true",
		fmt.Sprintf("cpu: %dm", RequestCPUMilli), fmt.Sprintf("memory: %dMi", RequestMemMiB), "- ALL",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered workload missing %q", want)
		}
	}
	for _, forbidden := range []string{"privileged: true", "hostNetwork", "hostPath", "emptyDir"} {
		if strings.Contains(s, forbidden) {
			t.Errorf("workload must not use %q", forbidden)
		}
	}
}

// The kernel is the one workload that never stops itself.
func TestTheKernelIsClassifiedAsKernel(t *testing.T) {
	out, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	dep := ofKind(t, out, "Deployment")[0]
	for _, path := range [][]string{
		{"metadata", "labels"},
		{"spec", "template", "metadata", "labels"},
	} {
		labels := at(t, dep, path...).(map[string]any)
		if labels["farcast.sofmon.com/tier"] != "kernel" {
			t.Errorf("%v tier = %v, want kernel", path, labels["farcast.sofmon.com/tier"])
		}
	}
}

// One RoleBinding per metered namespace: the kernel reads pods where FarCast
// owns the namespace and nowhere else.
func TestOneRoleBindingPerMeteredNamespace(t *testing.T) {
	c := sampleConfig()
	c.Meter = []string{"farcast-system", "farcast-apps"}
	out, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, rb := range ofKind(t, out, "RoleBinding") {
		if at(t, rb, "roleRef", "kind") != "ClusterRole" {
			continue
		}
		seen[at(t, rb, "metadata", "namespace").(string)] = true
	}
	for _, ns := range c.Meter {
		if !seen[ns] {
			t.Errorf("no RoleBinding in %q; the kernel cannot read pods there", ns)
		}
	}
	if len(seen) != 2 {
		t.Errorf("bound in %d namespaces, want exactly the 2 metered ones", len(seen))
	}
	// The arguments must agree with the grants, or the kernel asks for
	// namespaces it cannot read and reports a permissions error as a cost.
	if !strings.Contains(string(out), "--namespaces=farcast-system,farcast-apps") {
		t.Error("the metered namespaces argument does not match the RoleBindings")
	}
}

func TestTheCostLimitReachesTheContainer(t *testing.T) {
	c := sampleConfig()
	c.CostLimit = 73.5
	c.CostCurrency = "EUR"
	c.CostPeriod = "monthly"
	out, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--cost-limit=73.5", "--cost-currency=EUR", "--cost-period=monthly", "--instance=p41"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing argument %q", want)
		}
	}
}

// Applying this binding is what makes an application visible to the cost
// meter at all. It lives in TechnoCore's package rather than the translator
// that creates application namespaces: a translator writing its own version
// would be a second copy of the kernel's permission model, free to drift from
// the ClusterRole it references.
func TestRenderNamespaceBindingGrantsTheKernelInOneNamespace(t *testing.T) {
	out, err := RenderNamespaceBinding("demo", "", "")
	if err != nil {
		t.Fatal(err)
	}
	docs := docs(t, out)
	if len(docs) != 1 {
		t.Fatalf("rendered %d documents, want exactly one RoleBinding", len(docs))
	}
	rb := docs[0]
	if k, _ := rb["kind"].(string); k != "RoleBinding" {
		t.Fatalf("kind = %v, want RoleBinding — a ClusterRoleBinding would grant the whole cluster", k)
	}
	if got := at(t, rb, "metadata", "namespace"); got != "demo" {
		t.Errorf("bound in %v, want demo", got)
	}
	if got := at(t, rb, "roleRef", "kind"); got != "ClusterRole" {
		t.Errorf("roleRef kind = %v, want ClusterRole (the rule set)", got)
	}
	if got := at(t, rb, "roleRef", "name"); got != DefaultName {
		t.Errorf("roleRef name = %v, want %q", got, DefaultName)
	}
	subjects := at(t, rb, "subjects").([]any)
	s0 := subjects[0].(map[string]any)
	if s0["name"] != DefaultName || s0["namespace"] != DefaultNamespace {
		t.Errorf("subject = %v, want the kernel's ServiceAccount in %q", s0, DefaultNamespace)
	}
}

func TestRenderNamespaceBindingNeedsANamespace(t *testing.T) {
	if _, err := RenderNamespaceBinding("", "", ""); err == nil {
		t.Fatal("expected an error without a namespace")
	}
}

// The binding names the ClusterRole the workload renders. If the two spellings
// ever diverge the binding references a role that does not exist, and the
// kernel is refused in every application namespace.
func TestTheBindingReferencesTheClusterRoleTheWorkloadRenders(t *testing.T) {
	workload, err := Render(sampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	cr := ofKind(t, workload, "ClusterRole")[0]
	roleName := at(t, cr, "metadata", "name")

	out, err := RenderNamespaceBinding("demo", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := at(t, docs(t, out)[0], "roleRef", "name"); got != roleName {
		t.Errorf("the binding references ClusterRole %v; the workload renders %v", got, roleName)
	}
}
