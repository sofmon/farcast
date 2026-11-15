package cli

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	goparser "go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// rbacDoc is the part of a rendered RBAC document these tests read.
type rbacDoc struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string            `yaml:"name"`
		Namespace string            `yaml:"namespace"`
		Labels    map[string]string `yaml:"labels"`
	} `yaml:"metadata"`
	Rules []struct {
		APIGroups     []string `yaml:"apiGroups"`
		Resources     []string `yaml:"resources"`
		Verbs         []string `yaml:"verbs"`
		ResourceNames []string `yaml:"resourceNames"`
	} `yaml:"rules"`
	RoleRef struct {
		APIGroup string `yaml:"apiGroup"`
		Kind     string `yaml:"kind"`
		Name     string `yaml:"name"`
	} `yaml:"roleRef"`
	Subjects []struct {
		APIGroup string `yaml:"apiGroup"`
		Kind     string `yaml:"kind"`
		Name     string `yaml:"name"`
	} `yaml:"subjects"`
}

// rbacDocs splits a rendered stream as the client will, and decodes each
// document.
func rbacDocs(t *testing.T, stream []byte) []rbacDoc {
	t.Helper()
	docs, err := kube.SplitStream(stream)
	if err != nil {
		t.Fatalf("the stream is refused: %v", err)
	}
	out := make([]rbacDoc, 0, len(docs))
	for _, d := range docs {
		var o rbacDoc
		if err := yaml.Unmarshal(d.Raw, &o); err != nil {
			t.Fatalf("document %d does not decode: %v", d.Index, err)
		}
		out = append(out, o)
	}
	return out
}

// ADR 0023 M2.3, mutation 54: the ConfigMaps the reader may get are exactly
// the ones the read commands read, by the constants those call sites pass.
// The call sites are found in this package's source, so a new read of a
// ConfigMap, or one renamed, fails here until the role names it too; and
// technocore-confirmed, which nothing reads, is never among them.
func TestReaderRoleNamesTheConfigMapsReadsUse(t *testing.T) {
	// Every expression a read site may name its ConfigMap with, and its value.
	known := map[string]string{
		"kernel.DefaultNamespacesName":  kernel.DefaultNamespacesName,
		"kernel.DefaultCheckpointName":  kernel.DefaultCheckpointName,
		"kernel.DefaultProfilesName":    kernel.DefaultProfilesName,
		"fldeploy.PolicyConfigMap":      fldeploy.PolicyConfigMap,
		`dsdeploy.PinConfigMapName("")`: dsdeploy.PinConfigMapName(""),
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	read := map[string][]string{} // ConfigMap name → the sites that read it
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := goparser.ParseFile(fset, f, nil, goparser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "ConfigMapValue" && sel.Sel.Name != "ConfigMapData") {
				return true
			}
			site := fset.Position(call.Pos()).String()
			if len(call.Args) < 3 {
				t.Errorf("%s: %s with %d arguments; want (ctx, namespace, name, …)", site, sel.Sel.Name, len(call.Args))
				return true
			}
			var expr strings.Builder
			if err := printer.Fprint(&expr, fset, call.Args[2]); err != nil {
				t.Fatal(err)
			}
			v, ok := known[expr.String()]
			if !ok {
				t.Errorf("%s reads the ConfigMap %s, which the reader's role does not name: add it to readerConfigMaps and to this test", site, expr.String())
				return true
			}
			read[v] = append(read[v], site)
			return true
		})
	}
	if len(read) == 0 {
		t.Fatal("found no ConfigMap read in this package's source")
	}
	var sites []string
	for name := range read {
		sites = append(sites, name)
	}
	sort.Strings(sites)

	stream, err := renderReaderRBAC(readerEmail("atlas", "proj-test1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var rendered []string
	for _, d := range rbacDocs(t, stream) {
		if d.Kind != "ClusterRole" || d.Metadata.Name != readerRole {
			continue
		}
		for _, r := range d.Rules {
			if slices.Contains(r.Resources, "configmaps") {
				rendered = append(rendered, r.ResourceNames...)
			}
		}
	}
	if !slices.Equal(rendered, readerConfigMaps) {
		t.Errorf("the role names the ConfigMaps %q; readerConfigMaps is %q", rendered, readerConfigMaps)
	}
	got := slices.Clone(rendered)
	sort.Strings(got)
	if !slices.Equal(got, sites) {
		t.Errorf("the role names the ConfigMaps %q, and the read sites read %q (%v)", got, sites, read)
	}
	if slices.Contains(rendered, kernel.DefaultConfirmationsName) {
		t.Errorf("the role names %s, which nothing reads", kernel.DefaultConfirmationsName)
	}
	if want := []string{"technocore-namespaces", "technocore-ledger", "technocore-profiles", "fatline-egress-policy", "datasphered-pin"}; !slices.Equal(rendered, want) {
		t.Errorf("the role names %q; design §7.2 names %q", rendered, want)
	}
}

// ADR 0023 M2.3, mutation 55 (P3, decided): the reader holds one thing
// cluster-wide, namespaces list. Everything else is a rule set bound per
// namespace, in farcast-system and the metered namespaces, so it reads
// nothing in a namespace it is not bound in, kube-system among them. kubetest,
// authorizing the reader with the rendered stream alone, agrees.
func TestReaderRBACBindsOnlyNamespacesClusterWide(t *testing.T) {
	const name = "atlas"
	email := readerName(name) + "@kubetest.invalid"
	stream, err := renderReaderRBAC(email, []string{"web", "farcast-system", "web", "api"})
	if err != nil {
		t.Fatal(err)
	}
	docs := rbacDocs(t, stream)

	var clusterBindings, bindings []rbacDoc
	roles := map[string]rbacDoc{}
	for _, d := range docs {
		if d.Metadata.Labels["app.kubernetes.io/managed-by"] != "farcast" || d.Metadata.Labels["app.kubernetes.io/part-of"] != "farcast-reader" {
			t.Errorf("%s %s carries labels %v", d.Kind, d.Metadata.Name, d.Metadata.Labels)
		}
		switch d.Kind {
		case "ClusterRoleBinding":
			clusterBindings = append(clusterBindings, d)
		case "RoleBinding":
			bindings = append(bindings, d)
		case "ClusterRole":
			roles[d.Metadata.Name] = d
		default:
			t.Errorf("the reader's RBAC holds a %s", d.Kind)
		}
	}
	subject := func(d rbacDoc) bool {
		return len(d.Subjects) == 1 && d.Subjects[0].Kind == "User" && d.Subjects[0].Name == email &&
			d.Subjects[0].APIGroup == "rbac.authorization.k8s.io"
	}
	if len(clusterBindings) != 1 {
		t.Fatalf("%d ClusterRoleBindings; want the one for namespaces list", len(clusterBindings))
	}
	crb := clusterBindings[0]
	if crb.Metadata.Name != readerNamespacesRole || crb.RoleRef.Kind != "ClusterRole" || crb.RoleRef.Name != readerNamespacesRole || !subject(crb) {
		t.Errorf("the ClusterRoleBinding is %+v", crb)
	}
	ns, ok := roles[readerNamespacesRole]
	if !ok || len(ns.Rules) != 1 || !slices.Equal(ns.Rules[0].APIGroups, []string{""}) ||
		!slices.Equal(ns.Rules[0].Resources, []string{"namespaces"}) || !slices.Equal(ns.Rules[0].Verbs, []string{"list"}) ||
		len(ns.Rules[0].ResourceNames) != 0 {
		t.Errorf("the cluster-wide role is %+v; want namespaces list alone", ns)
	}
	var where []string
	for _, b := range bindings {
		if b.Metadata.Name != readerRole || b.RoleRef.Kind != "ClusterRole" || b.RoleRef.Name != readerRole || !subject(b) {
			t.Errorf("a RoleBinding is %+v", b)
		}
		where = append(where, b.Metadata.Namespace)
	}
	if want := []string{"farcast-system", "web", "api"}; !slices.Equal(where, want) {
		t.Errorf("the reader is bound in %q; want %q, farcast-system first and each once", where, want)
	}
	role := roles[readerRole]
	type rule struct{ groups, resources, verbs, names string }
	var got []rule
	for _, r := range role.Rules {
		got = append(got, rule{strings.Join(r.APIGroups, ","), strings.Join(r.Resources, ","), strings.Join(r.Verbs, ","), strings.Join(r.ResourceNames, ",")})
	}
	want := []rule{
		{"apps", "deployments,statefulsets", "get,list", ""},
		{"", "pods", "list", ""},
		{"", "pods/log", "get", ""},
		{"batch", "jobs", "get", ""},
		{"", "configmaps", "get", strings.Join(readerConfigMaps, ",")},
	}
	if !slices.Equal(got, want) {
		t.Errorf("the per-namespace role is\n%+v\nwant\n%+v", got, want)
	}

	// The same stream, as kubetest's authorizer reads it.
	s := kubetest.New(t, kubetest.WithRBAC(email, stream))
	ep, err := kube.ParseEndpoint(s.Endpoint(), "", s.CAPEM())
	if err != nil {
		t.Fatal(err)
	}
	kc, err := kube.New(kube.Config{Endpoint: ep, Credential: s.CredentialFor("reader", email), Identity: kube.Reader})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	allowed := func(what string, err error) {
		t.Helper()
		if errors.Is(err, tkube.ErrForbidden) {
			t.Errorf("%s: forbidden: %v", what, err)
		}
	}
	forbidden := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, tkube.ErrForbidden) {
			t.Errorf("%s: %v; want forbidden", what, err)
		}
	}
	_, err = kc.ListNamespaces(ctx, readerGrantSelector)
	allowed("namespaces list", err)
	_, err = kc.ListPods(ctx, "farcast-system", "")
	allowed("pods list in farcast-system", err)
	_, err = kc.ListDeployments(ctx, "web")
	allowed("deployments list in web", err)
	_, err = kc.GetConfigMap(ctx, "farcast-system", kernel.DefaultCheckpointName)
	allowed("the ledger", err)
	_, err = kc.ListPods(ctx, "kube-system", "")
	forbidden("pods list in kube-system", err)
	_, err = kc.ListDeployments(ctx, "")
	forbidden("deployments list across every namespace", err)
	_, err = kc.ListPods(ctx, "unmetered", "")
	forbidden("pods list in a namespace nothing bound", err)
	_, err = kc.GetConfigMap(ctx, "farcast-system", kernel.DefaultConfirmationsName)
	forbidden("the confirmations ConfigMap", err)
	_, err = kc.GetService(ctx, "farcast-system", "fatline")
	forbidden("a Service", err)
}

// The renderers refuse anything that would not stay one YAML scalar, or
// that is not a reader farcast derives: the RBAC binds exactly the derived
// account, in DNS-label namespaces outside kube-.
func TestReaderRBACRefusesWhatItCannotRenderSafely(t *testing.T) {
	good := readerEmail("atlas", "proj-test1")
	for _, email := range []string{
		"",
		"writer@kubetest.invalid",
		"farcast-installer@proj-test1.iam.gserviceaccount.com",
		strings.ToUpper(good),
		good + "\nkind: ClusterRoleBinding",
		good + " ",
		readerName("atlas") + `@a"b.invalid`,
		readerName("atlas") + "@a b.invalid",
		readerName("atlas") + "@.invalid",
		readerName("atlas") + "@invalid",
		readerName("atlas") + "@proj-test1.iam.gserviceaccount.com.invalid.x",
		readerName("atlas") + "@P.iam.gserviceaccount.com",
		"farcast-reader-1234abc@proj-test1.iam.gserviceaccount.com",
	} {
		if b, err := renderReaderRBAC(email, nil); err == nil || b != nil {
			t.Errorf("renderReaderRBAC(%q) = %d bytes, %v; want a refusal", email, len(b), err)
		}
		if b, err := renderReaderBinding(email, "web"); err == nil || b != nil {
			t.Errorf("renderReaderBinding(%q) = %d bytes, %v; want a refusal", email, len(b), err)
		}
	}
	for _, ns := range []string{"", "kube-system", "kube-public", "Web", "web\nkind: x", "-web", "web-", "a b", strings.Repeat("a", 64)} {
		if b, err := renderReaderRBAC(good, []string{ns}); err == nil || b != nil {
			t.Errorf("renderReaderRBAC with namespace %q = %d bytes, %v; want a refusal", ns, len(b), err)
		}
		if b, err := renderReaderBinding(good, ns); err == nil || b != nil {
			t.Errorf("renderReaderBinding(%q) = %d bytes, %v; want a refusal", ns, len(b), err)
		}
	}
	for _, email := range []string{good, readerName("atlas") + "@kubetest.invalid", readerName("atlas") + "@rehearsal.invalid"} {
		if _, err := renderReaderRBAC(email, []string{"web"}); err != nil {
			t.Errorf("renderReaderRBAC(%q): %v", email, err)
		}
	}
}

// withReader records name for 'kernel meter', 'run' and 'kernel
// deploy' with a Google-mode reader: none, one whose grant never ran, one
// granted the metered scope, one granted it whose record farcast cannot
// render from (a project ID Google never issues), or one granted it whose
// email was edited by hand to the installer's, which is not the derived
// reader.
func withReader(t *testing.T, dir config.Dir, name, state string) {
	t.Helper()
	meta, err := dir.LoadInstanceMetadata(name)
	if err != nil {
		t.Fatal(err)
	}
	meta.Project = "proj-test1"
	switch state {
	case "none":
		meta.Reader = nil
	case "recorded":
		meta.Reader = &config.Reader{Email: readerEmail(name, "proj-test1"), KeyID: readerTestKeyID}
	case "metered":
		meta.Reader = &config.Reader{Email: readerEmail(name, "proj-test1"), KeyID: readerTestKeyID, GrantedAt: readerGrantedAt, Scope: readerScopeMetered}
	case "unsafe":
		meta.Project = "Proj_Test1"
		meta.Reader = &config.Reader{Email: readerEmail(name, "Proj_Test1"), KeyID: readerTestKeyID, GrantedAt: readerGrantedAt, Scope: readerScopeMetered}
	case "edited":
		meta.Reader = &config.Reader{Email: "farcast-installer@proj-test1.iam.gserviceaccount.com", KeyID: readerTestKeyID, GrantedAt: readerGrantedAt, Scope: readerScopeMetered}
	default:
		t.Fatalf("no reader state %q", state)
	}
	if err := dir.SaveInstanceMetadata(name, meta); err != nil {
		t.Fatal(err)
	}
}

// readerBindingsIn is the namespaces a set of applied streams bound the
// reader in, in order.
func readerBindingsIn(t *testing.T, streams []string) []string {
	t.Helper()
	var where []string
	for _, s := range streams {
		docs, err := kube.SplitStream([]byte(s))
		if err != nil {
			t.Fatalf("an applied stream is refused: %v", err)
		}
		for _, d := range docs {
			if d.Kind.Kind == "RoleBinding" && d.Name == readerRole {
				where = append(where, d.Namespace)
			}
		}
	}
	return where
}

// Design §7.2: 'kernel meter', 'run' and 'kernel deploy' bind the reader in
// a namespace they meter only when 'reader grant' recorded the metered scope,
// the consent to "every namespace the kernel meters, now and later"; then
// each adds one per namespace it binds and says so. A reader recorded but not
// granted gets none, and a granted one whose record cannot be rendered from,
// or whose email is not the derived reader, gets none either, said on stderr
// in words that stay true while the command applies its own stream.
func TestReaderBindingsFollowOnlyAConsentedScope(t *testing.T) {
	type outcome struct {
		bound  []string
		stdout string
		stderr string
	}
	commands := []struct {
		name string
		want []string // where a metered reader is bound
		run  func(t *testing.T, state string) outcome
	}{
		{"kernel meter", []string{"demo"}, func(t *testing.T, state string) outcome {
			dir := config.Dir(t.TempDir())
			meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace)
			withReader(t, dir, "p42", state)
			env, out, errb := testEnvBoth(dir, output.ModeHuman)
			fc := &fakeCluster{}
			if err := meterCmd(fc).Run(context.Background(), env, []string{"p42", "demo"}); err != nil {
				t.Fatal(err)
			}
			var applied []string
			for _, m := range fc.applied {
				applied = append(applied, string(m))
			}
			return outcome{readerBindingsIn(t, applied), out.String(), errb.String()}
		}},
		{"run", []string{"my-platform"}, func(t *testing.T, state string) outcome {
			dir := config.Dir(t.TempDir())
			runnableInstance(t, dir, "p43")
			withReader(t, dir, "p43", state)
			env, out, errb := testEnvBoth(dir, output.ModeHuman)
			f := newFakeRun(twoAppManifest)
			if err := runCmd(f).Run(context.Background(), env, []string{"p43", "github.com/example/my-platform"}); err != nil {
				t.Fatal(err)
			}
			return outcome{readerBindingsIn(t, f.applied), out.String(), errb.String()}
		}},
		{"kernel deploy", []string{"farcast-apps", "farcast-system"}, func(t *testing.T, state string) outcome {
			dir := config.Dir(t.TempDir())
			connectedInstance(t, dir, "p50")
			withReader(t, dir, "p50", state)
			env, out, errb := testEnvBoth(dir, output.ModeHuman)
			fc := &fakeCluster{}
			c := testKernelDeploy(fc, &fakeBuilder{})
			c.namespaces = "farcast-apps"
			if err := c.Run(context.Background(), env, []string{"p50"}); err != nil {
				t.Fatal(err)
			}
			var applied []string
			for _, m := range fc.applied {
				applied = append(applied, string(m))
			}
			return outcome{readerBindingsIn(t, applied), out.String(), errb.String()}
		}},
	}
	instance := map[string]string{"kernel meter": "p42", "run": "p43", "kernel deploy": "p50"}
	for _, cmd := range commands {
		for _, state := range []string{"none", "recorded", "metered", "unsafe", "edited"} {
			t.Run(cmd.name+"/"+state, func(t *testing.T) {
				got := cmd.run(t, state)
				email := readerEmail(instance[cmd.name], "proj-test1")
				if state != "metered" {
					if len(got.bound) != 0 {
						t.Errorf("a reader %s was bound in %q", state, got.bound)
					}
					if strings.Contains(got.stdout, "may now read") {
						t.Errorf("the result names a reader binding:\n%s", got.stdout)
					}
					warned := strings.Contains(got.stderr, "no reader binding is added")
					refused := state == "unsafe" || state == "edited"
					if refused && !warned {
						t.Errorf("an unrenderable granted reader got no binding, silently:\n%s", got.stderr)
					}
					if !refused && warned {
						t.Errorf("stderr warns of a reader binding nothing consented to:\n%s", got.stderr)
					}
					// The command goes on to apply its own stream, so the
					// warning never says nothing was sent.
					if state == "edited" && (strings.Contains(got.stderr, "nothing was sent") || !strings.Contains(got.stderr, "no RBAC was rendered for it")) {
						t.Errorf("the warning does not say what was left out:\n%s", got.stderr)
					}
					return
				}
				bound := slices.Clone(got.bound)
				sort.Strings(bound)
				if !slices.Equal(bound, cmd.want) {
					t.Errorf("the reader was bound in %q; want %q, once each", got.bound, cmd.want)
				}
				for _, ns := range cmd.want {
					if line := "the reader " + email + " may now read " + ns + "\n"; !strings.Contains(got.stdout, line) {
						t.Errorf("the result does not say %q:\n%s", line, got.stdout)
					}
				}
			})
		}
	}
}

// The results' JSON names the reader bindings a command added, as the meter
// fact's reader_bindings_created will for plans, and omits both fields when
// it added none.
func TestMeterResultNamesTheReaderBindingsItAdded(t *testing.T) {
	for _, state := range []string{"metered", "recorded"} {
		dir := config.Dir(t.TempDir())
		meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace)
		withReader(t, dir, "p42", state)
		env, out := testEnv(dir, output.ModeJSON)
		if err := meterCmd(&fakeCluster{}).Run(context.Background(), env, []string{"p42", "demo", "other"}); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Reader   *string  `json:"reader"`
			Bindings []string `json:"reader_bindings_created"`
		}
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("%v:\n%s", err, out)
		}
		if state == "recorded" {
			if doc.Reader != nil || doc.Bindings != nil {
				t.Errorf("no binding was added, and the result names %v, %q:\n%s", doc.Reader, doc.Bindings, out)
			}
			continue
		}
		if doc.Reader == nil || *doc.Reader != readerEmail("p42", "proj-test1") || !slices.Equal(doc.Bindings, []string{"demo", "other"}) {
			t.Errorf("the result names %v, %q:\n%s", doc.Reader, doc.Bindings, out)
		}
	}
}

// The reader's texts promise only the namespaces its renderers refuse. A
// kube- namespace is never bound: validNamespace refuses it, for the reader
// as for the kernel. GKE's other managed namespaces are not refused, so no
// text may say the reader is kept out of "GKE's managed namespaces" while one
// of them renders; a change that refuses them may bring the claim back.
func TestReaderTextsPromiseOnlyTheNamespacesItRefuses(t *testing.T) {
	email := readerEmail("atlas", "proj-test1")
	for _, ns := range []string{"kube-system", "kube-public", "kube-node-lease"} {
		if _, err := renderReaderBinding(email, ns); err == nil {
			t.Errorf("renderReaderBinding binds the reader in %s", ns)
		}
		if _, err := renderReaderRBAC(email, []string{ns}); err == nil {
			t.Errorf("renderReaderRBAC binds the reader in %s", ns)
		}
	}
	var rendered []string
	for _, ns := range []string{"gke-managed-system", "gke-gmp-system", "gmp-system", "gmp-public"} {
		if _, err := renderReaderBinding(email, ns); err == nil {
			rendered = append(rendered, ns)
		}
	}
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	usage := strings.Join(strings.Fields((&readerGrantCommand{}).Usage()), " ")
	for what, text := range map[string]string{
		"reader grant's usage":   usage,
		"farsight/cli/README.md": strings.Join(strings.Fields(string(readme)), " "),
	} {
		if len(rendered) > 0 && strings.Contains(text, "GKE's managed namespaces") {
			t.Errorf("%s says the reader is kept out of GKE's managed namespaces, and it is bound in %q when they are metered", what, rendered)
		}
	}
	if !strings.Contains(usage, "never in a kube- namespace such as kube-system") {
		t.Errorf("reader grant's usage does not say the reader is never bound in a kube- namespace:\n%s", usage)
	}
}

// ADR 0023 M2.3: 'kernel meter --remove' deletes nothing, so a farcast-reader
// RoleBinding added there stays, and unlike the kernel's it still grants
// reads without the listing. On an instance that records a reader the result
// says so; on one with no reader it says nothing of one.
func TestKernelMeterRemoveSaysTheReaderBindingStays(t *testing.T) {
	const stays = "If 'reader grant' bound the reader there, its farcast-reader RoleBinding stays\n" +
		"too, and still lets the reader read that namespace's workloads, pods and logs\n" +
		"until the namespace is deleted.\n"
	for _, state := range []string{"metered", "recorded", "none"} {
		t.Run(state, func(t *testing.T) {
			dir := config.Dir(t.TempDir())
			meteredInstance(t, dir, "p42", tcdeploy.DefaultNamespace, "demo")
			withReader(t, dir, "p42", state)
			env, out := testEnv(dir, output.ModeHuman)
			fc := &fakeCluster{}
			c := meterCmd(fc)
			c.remove = true
			if err := c.Run(context.Background(), env, []string{"p42", "demo"}); err != nil {
				t.Fatal(err)
			}
			var applied []string
			for _, m := range fc.applied {
				applied = append(applied, string(m))
			}
			if got := readerBindingsIn(t, applied); len(got) != 0 {
				t.Errorf("a removal bound the reader in %q", got)
			}
			if !strings.Contains(out.String(), "The kernel's RoleBinding is still present in demo.") {
				t.Fatalf("the removal does not say the kernel's binding stays:\n%s", out)
			}
			if said := strings.Contains(out.String(), stays); said != (state != "none") {
				t.Errorf("with reader %s, the result says the reader's binding stays: %v; want %v:\n%s", state, said, state != "none", out)
			}
		})
	}
}
