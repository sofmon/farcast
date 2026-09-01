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

	got := map[string][]string{}
	for _, r := range rules {
		m := r.(map[string]any)
		for _, res := range m["resources"].([]any) {
			for _, v := range m["verbs"].([]any) {
				got[res.(string)] = append(got[res.(string)], v.(string))
			}
		}
	}
	want := map[string][]string{
		"pods":              {"list"},
		"deployments":       {"list"},
		"deployments/scale": {"patch"},
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
	if len(rules) != 3 {
		t.Fatalf("ledger Role has %d rules, want 3 (unnamed create, named maintenance, named read)", len(rules))
	}

	var named, unnamed map[string]any
	for _, r := range rules {
		m := r.(map[string]any)
		if _, ok := m["resourceNames"]; !ok {
			unnamed = m
			continue
		}
		if fmt.Sprint(m["resourceNames"]) == "[technocore-ledger]" {
			named = m
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
