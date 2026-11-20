package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/sofmon/farcast/datasphere"
	dsdeploy "github.com/sofmon/farcast/datasphere/deploy"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/manifest/parser"
	pbuild "github.com/sofmon/farcast/planck/build"
	pfetch "github.com/sofmon/farcast/planck/fetch"
	"github.com/sofmon/farcast/technocore/cost"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

// Every stream farcast applies must pass the checks the in-process client
// makes before it sends anything (ADR 0023 decision 2, Verification 1): one
// that does not is refused, since the client replaced kubectl in ADR 0023
// M2.7. So every
// renderer's output, and every stream a command composes from several
// renderers, goes through kube.SplitStream here, built by the same function
// the command calls. A rendered stringData, an unknown kind, a missing
// namespace or a YAML anchor fails the build.
//
// Fourteen places apply a stream today, and this table covers each:
//   - connect and redeploy: renderWorkload, on both carriers, with and
//     without Shrike;
//   - kernel deploy: kernelManifests, TechnoCore's workload and the seed,
//     with and without a granted reader's bindings;
//   - kernel meter and run: meterManifest, with and without a granted
//     reader's bindings;
//   - reader grant: renderReaderRBAC, with no metered namespace and with two,
//     and renderReaderBinding, the binding the three commands above add;
//   - kernel confirm: the confirmations ConfigMap;
//   - storage deploy: the keyholder's workload;
//   - run: the egress policy, then the workloads with and without storage;
//   - run and build: the build Job; run: the fetch Job;
//   - git-credential set: the Git credential's Secret (ADR 0023 M2.8).
//
// Beside this table, every stream an existing command test applies through a
// fake cluster is checked too (checkApplied, and TestMain), so a composition
// the table missed is still caught.
func TestEveryRenderedStreamPassesTheApplyChecks(t *testing.T) {
	for _, s := range renderedStreams(t) {
		t.Run(s.name, func(t *testing.T) {
			docs, err := kube.SplitStream(s.stream)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if len(docs) == 0 {
				t.Fatal("the stream holds no document")
			}
			// A separator the client does not split on (a "--- ", say) needs
			// no count here: SplitStream refuses any line that starts with ---
			// and is not exactly ---, so such a stream fails above.
			for _, w := range s.want {
				if !holds(docs, w) {
					t.Errorf("no %s among %v", w, identities(docs))
				}
			}
		})
	}
}

// farcast's label, app.kubernetes.io/managed-by=farcast, is how farcast
// tells what it wrote: world lists the instance's namespaces by it
// (managedSelector), reader grant verifies the reader with the same
// selector (readerGrantSelector), and git-credential tells its own Secrets
// by it (gitCredentialManagedBy). ADR 0023 M2.7's migrate found what it
// rewrote by it too (design §6.2, A30-16), until M2.9a removed migrate
// (design A37-1). So every document of every rendered stream carries it,
// the kernel's seed technocore-namespaces and the confirmations ConfigMap
// among them.
func TestEveryRenderedDocumentIsManagedByFarcast(t *testing.T) {
	key, value, _ := strings.Cut(managedSelector, "=")
	seen := map[string]bool{}
	for _, s := range renderedStreams(t) {
		docs, err := kube.SplitStream(s.stream)
		if err != nil {
			t.Fatalf("%s: refused: %v", s.name, err)
		}
		for _, d := range docs {
			seen[docIdentity(d)] = true
			if got, ok := renderedObjectOf(t, d).Metadata.Labels[key]; !ok || got != value {
				t.Errorf("%s: %s carries %s %q (present %t), want %q", s.name, docIdentity(d), key, got, ok, value)
			}
		}
	}
	for _, want := range []string{
		"ConfigMap " + tcdeploy.DefaultNamespace + "/" + kernel.DefaultNamespacesName,
		"ConfigMap " + tcdeploy.DefaultNamespace + "/" + kernel.DefaultConfirmationsName,
	} {
		if !seen[want] {
			t.Errorf("no rendered stream holds %s, so its label goes unchecked", want)
		}
	}
}

// A stream is applied in order, and since ADR 0023 M2.7 the in-process apply
// stops at its first failing document (design D3). A NetworkPolicy rendered
// after the workload it selects would be left unapplied by a failure between
// the two, with the workload's pods running unrestricted by it (an
// application's egress not denied by default, the keyholder's ports reachable
// from any pod); kubectl, which carries on past a failure, hid this. So every
// NetworkPolicy comes before each Deployment, StatefulSet and Job in its
// namespace whose pods it selects, and in a stream that renders any
// NetworkPolicy, every such workload has one before it (A30-17).
func TestEveryNetworkPolicyPrecedesItsWorkload(t *testing.T) {
	checked := 0
	for _, s := range renderedStreams(t) {
		t.Run(s.name, func(t *testing.T) {
			docs, err := kube.SplitStream(s.stream)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			objs := make([]renderedObject, len(docs))
			policies := false
			for i, d := range docs {
				objs[i] = renderedObjectOf(t, d)
				if d.Kind.Kind != "NetworkPolicy" {
					continue
				}
				policies = true
				// Only matchLabels is read here, so a selector this test
				// cannot evaluate fails it rather than passing unread.
				if len(objs[i].Spec.PodSelector.MatchExpressions) != 0 {
					t.Errorf("%s selects by matchExpressions, which this test does not read", docIdentity(d))
				}
			}
			for i, w := range docs {
				switch w.Kind.Kind {
				case "Deployment", "StatefulSet", "Job":
				default:
					continue
				}
				pod := objs[i].Spec.Template.Metadata.Labels
				before := 0
				for j, p := range docs {
					if p.Kind.Kind != "NetworkPolicy" || p.Namespace != w.Namespace || !selectsPod(objs[j].Spec.PodSelector.MatchLabels, pod) {
						continue
					}
					if j > i {
						t.Errorf("%s selects the pods of %s and comes after it; the order is %v", docIdentity(p), docIdentity(w), identities(docs))
						continue
					}
					before++
				}
				if policies {
					checked++
					if before == 0 {
						t.Errorf("%s has no NetworkPolicy before it that selects its pods; the order is %v", docIdentity(w), identities(docs))
					}
				}
			}
		})
	}
	if checked == 0 {
		t.Error("no rendered stream holds both a NetworkPolicy and a workload, so nothing was checked")
	}
}

// The build and fetch policies' "ingress: []", applied server-side on a
// loopback envtest kube-apiserver 1.36.2, was not stored: the stored policy
// had no ingress field, and every apply of the unchanged stream moved the
// policy's generation (ADR 0023 M2.7, design §31 and A31-4). Why is
// inferred, not read: storage keeps no empty list, so each apply sets it
// again, and the update strategy counts that as a change. Only that one field
// was seen to do so; the guard is wider. So no document of any rendered
// stream carries an empty list, anywhere in it. An empty map is left alone, because
// "podSelector: {}" and "emptyDir: {}" carry meaning. The walk is first run
// over documents that hide an empty list where a shallow walk would not look.
func TestNoRenderedDocumentCarriesAnEmptyList(t *testing.T) {
	for _, c := range []struct {
		doc  string
		want []string
	}{
		{"spec:\n  ingress: []\n", []string{"spec.ingress"}},
		{"spec:\n  egress:\n    - to: []\n    - ports:\n        - port: 53\n", []string{"spec.egress[0].to"}},
		{"spec:\n  rules:\n    - - a\n    - []\n", []string{"spec.rules[1]"}},
		{"items: []\nspec:\n  podSelector: {}\n  volumes:\n    - emptyDir: {}\n", []string{"items"}},
	} {
		var v any
		if err := yaml.Unmarshal([]byte(c.doc), &v); err != nil {
			t.Fatal(err)
		}
		if got := emptyLists(v, ""); !slices.Equal(got, c.want) {
			t.Errorf("the walk of %q found %q, want %q", c.doc, got, c.want)
		}
	}
	for _, s := range renderedStreams(t) {
		docs, err := kube.SplitStream(s.stream)
		if err != nil {
			t.Fatalf("%s: refused: %v", s.name, err)
		}
		for _, d := range docs {
			var v any
			if err := yaml.Unmarshal(d.Raw, &v); err != nil {
				t.Fatalf("%s: %s does not decode: %v", s.name, docIdentity(d), err)
			}
			if got := emptyLists(v, ""); len(got) != 0 {
				t.Errorf("%s: %s carries an empty list at %s", s.name, docIdentity(d), strings.Join(got, ", "))
			}
		}
	}
}

// ADR 0023 M2.7 (A31-2): kube's real-API suite applies the egress policy
// from kube/testdata/realapi/egress-policy.yaml, because kube's tests may
// import nothing but the standard library, the package's four and kubetest
// (kube/doc_test.go). Below its --- line that file is RenderPolicyConfigMap's
// output at a resourceVersion and, with the resourceVersion line taken out,
// at none, byte for byte, so the suite's row applies the renderer's own
// document.
func TestTheRealAPIEgressPolicyIsTheRenderers(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "kube", "testdata", "realapi", "egress-policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	_, golden, ok := strings.Cut(string(b), "\n---\n")
	if !ok {
		t.Fatal("egress-policy.yaml holds no --- line")
	}
	const ns, rv, rvLine = "realapi-stale-0a1b2c3d", "41", "  resourceVersion: \"{rv}\"\n"
	credential := strings.Repeat("3", 64)
	doc := &policy.Document{Version: policy.Version, Apps: []policy.App{{Name: "api", Namespace: ns, CredentialSHA256: credential}}}
	fill := strings.NewReplacer("{ns}", ns, "{credential}", credential, "{rv}", rv)
	if strings.Count(golden, rvLine) != 1 {
		t.Fatalf("egress-policy.yaml carries the line %q %d times, want once", rvLine, strings.Count(golden, rvLine))
	}
	for _, at := range []string{rv, ""} {
		want, err := fldeploy.RenderPolicyConfigMap(ns, doc, at)
		if err != nil {
			t.Fatal(err)
		}
		got := golden
		if at == "" {
			got = strings.Replace(got, rvLine, "", 1)
		}
		if got = fill.Replace(got); got != string(want) {
			t.Errorf("at resourceVersion %q, egress-policy.yaml reads\n%s\nRenderPolicyConfigMap renders\n%s", at, got, want)
		}
	}
}

// emptyLists is the path of every empty list in a decoded document, map keys
// in sorted order. A container it cannot walk is reported as one, so nothing
// passes unread.
func emptyLists(v any, path string) []string {
	at := func(k string) string {
		if path == "" {
			return k
		}
		return path + "." + k
	}
	var out []string
	switch v := v.(type) {
	case nil, string, bool, int, int64, uint64, float64:
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(v)) {
			out = append(out, emptyLists(v[k], at(k))...)
		}
	case []any:
		if len(v) == 0 {
			return []string{path}
		}
		for i, e := range v {
			out = append(out, emptyLists(e, fmt.Sprintf("%s[%d]", path, i))...)
		}
	default:
		out = append(out, fmt.Sprintf("%s (a %T this walk does not read)", path, v))
	}
	return out
}

// renderedObject is the part of a rendered document these tests read: its
// labels, a NetworkPolicy's pod selector, and a workload's pod-template labels.
type renderedObject struct {
	Metadata struct {
		Labels map[string]string `yaml:"labels"`
	} `yaml:"metadata"`
	Spec struct {
		PodSelector struct {
			MatchLabels      map[string]string `yaml:"matchLabels"`
			MatchExpressions []any             `yaml:"matchExpressions"`
		} `yaml:"podSelector"`
		Template struct {
			Metadata struct {
				Labels map[string]string `yaml:"labels"`
			} `yaml:"metadata"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

func renderedObjectOf(t *testing.T, d kube.Document) renderedObject {
	t.Helper()
	var o renderedObject
	if err := yaml.Unmarshal(d.Raw, &o); err != nil {
		t.Fatalf("%s does not decode: %v", docIdentity(d), err)
	}
	return o
}

// selectsPod is whether a pod selector's matchLabels are all among a pod's
// labels. An empty selector selects every pod.
func selectsPod(selector, pod map[string]string) bool {
	for k, v := range selector {
		if got, ok := pod[k]; !ok || got != v {
			return false
		}
	}
	return true
}

type renderedStream struct {
	name   string
	stream []byte
	// want names documents the stream must hold, as "Kind namespace/name".
	want []string
}

func renderedStreams(t *testing.T) []renderedStream {
	t.Helper()
	ctx := context.Background()

	dir := config.Dir(t.TempDir())
	const instance = "p42"
	meta := runnableInstance(t, dir, instance)
	mat, err := identity.Mint(instance)
	if err != nil {
		t.Fatal(err)
	}
	mtls := toConfigMTLS(mat)
	if err := dir.SaveInstanceMTLS(instance, mtls); err != nil {
		t.Fatal(err)
	}

	var out []renderedStream
	add := func(name string, b []byte, err error, want ...string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out = append(out, renderedStream{name: name, stream: b, want: want})
	}

	// connect and redeploy.
	fatline := "registry.example/fatline@" + sha("a")
	shrike := "registry.example/shrike@" + sha("b")
	for _, carrier := range []fldeploy.Carrier{fldeploy.CarrierLoadBalancer, fldeploy.CarrierClusterIP} {
		for _, sh := range []string{shrike, ""} {
			b, err := renderWorkload(fatline, sh, carrier, mtls)
			add(fmt.Sprintf("renderWorkload %s shrike=%t", carrier, sh != ""), b, err,
				"Deployment "+fldeploy.DefaultNamespace+"/"+fldeploy.DefaultName)
		}
	}

	// kernel deploy, with adapting off and on.
	for _, adapt := range []bool{false, true} {
		b, err := kernelManifests(kernelConfig(instance, adapt, []string{"farcast-system", "my-platform"}), "")
		add(fmt.Sprintf("kernelManifests adapt=%t", adapt), b, err,
			"Deployment "+tcdeploy.DefaultNamespace+"/"+tcdeploy.DefaultName,
			"RoleBinding my-platform/"+tcdeploy.DefaultName,
			"ConfigMap "+tcdeploy.DefaultNamespace+"/"+kernel.DefaultNamespacesName)
	}

	// kernel meter and run.
	b, err := meterManifest([]string{"farcast-system", "alpha", "beta"}, []string{"alpha", "beta"}, "")
	add("meterManifest two added", b, err,
		"RoleBinding alpha/"+tcdeploy.DefaultName, "RoleBinding beta/"+tcdeploy.DefaultName,
		"ConfigMap "+tcdeploy.DefaultNamespace+"/"+kernel.DefaultNamespacesName)
	b, err = meterManifest([]string{"farcast-system"}, nil, "")
	add("meterManifest none added", b, err, "ConfigMap "+tcdeploy.DefaultNamespace+"/"+kernel.DefaultNamespacesName)

	// reader grant, and the reader's bindings the three commands above add
	// once it recorded the metered scope; in Google mode and in loopback mode.
	reader := readerEmail(instance, "proj-test1")
	loopback := readerName(instance) + "@kubetest.invalid"
	readerRBAC := []string{
		"ClusterRole /" + readerNamespacesRole, "ClusterRoleBinding /" + readerNamespacesRole,
		"ClusterRole /" + readerRole, "RoleBinding " + tcdeploy.DefaultNamespace + "/" + readerRole,
	}
	b, err = renderReaderRBAC(reader, nil)
	add("renderReaderRBAC no namespaces", b, err, readerRBAC...)
	b, err = renderReaderRBAC(loopback, []string{"farcast-system", "alpha", "beta"})
	add("renderReaderRBAC two namespaces", b, err,
		append(slices.Clone(readerRBAC), "RoleBinding alpha/"+readerRole, "RoleBinding beta/"+readerRole)...)
	b, err = renderReaderBinding(reader, "alpha")
	add("renderReaderBinding", b, err, "RoleBinding alpha/"+readerRole)
	b, err = meterManifest([]string{"farcast-system", "alpha", "beta"}, []string{"alpha", "beta"}, reader)
	add("meterManifest two added with a reader", b, err,
		"RoleBinding alpha/"+tcdeploy.DefaultName, "RoleBinding alpha/"+readerRole,
		"RoleBinding beta/"+tcdeploy.DefaultName, "RoleBinding beta/"+readerRole,
		"ConfigMap "+tcdeploy.DefaultNamespace+"/"+kernel.DefaultNamespacesName)
	b, err = kernelManifests(kernelConfig(instance, true, []string{"farcast-system", "my-platform"}), reader)
	add("kernelManifests with a reader", b, err,
		"Deployment "+tcdeploy.DefaultNamespace+"/"+tcdeploy.DefaultName,
		"RoleBinding my-platform/"+tcdeploy.DefaultName,
		"RoleBinding "+tcdeploy.DefaultNamespace+"/"+readerRole, "RoleBinding my-platform/"+readerRole,
		"ConfigMap "+tcdeploy.DefaultNamespace+"/"+kernel.DefaultNamespacesName)

	// kernel confirm, empty and holding a figure.
	day := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, cs := range [][]cost.Confirmation{nil, {{Start: day, End: day.AddDate(0, 0, 1), USD: 1.25, AsOf: day.AddDate(0, 0, 2)}}} {
		b, err := kernel.RenderConfigMap(tcdeploy.DefaultNamespace, kernel.DefaultConfirmationsName, cs)
		add(fmt.Sprintf("confirmations %d", len(cs)), b, err,
			"ConfigMap "+tcdeploy.DefaultNamespace+"/"+kernel.DefaultConfirmationsName)
	}

	// storage deploy.
	certPEM, keyPEM, err := identity.IssueKeyholderServer(mtls.CACertPEM, mtls.CAKeyPEM, instance)
	if err != nil {
		t.Fatal(err)
	}
	b, err = dsdeploy.Render(dsdeploy.Config{
		Image:    "registry.example/datasphered@" + sha("d"),
		Instance: instance, Bucket: "farcast-p42-data", Provider: "gcs",
		Project: "farcast-test", Location: "us-central1",
		CACertPEM: mtls.CACertPEM, ServerCertPEM: certPEM, ServerKeyPEM: keyPEM,
	})
	add("datasphere deploy", b, err, "StatefulSet "+dsdeploy.DefaultNamespace+"/"+dsdeploy.DefaultName)

	// run: the egress policy, as egressPolicy writes it over the policy
	// run read.
	m, err := parser.Parse([]byte(twoAppManifest))
	if err != nil {
		t.Fatal(err)
	}
	existing, _, err := readEgressPolicyAt(ctx, newFakeRun(twoAppManifest))
	if err != nil {
		t.Fatal(err)
	}
	doc, credentials, err := egressPolicy(existing, m.Name, *m, mintEgressCredential)
	if err != nil {
		t.Fatal(err)
	}
	b, err = fldeploy.RenderPolicyConfigMap(fldeploy.DefaultNamespace, doc, "")
	add("egress policy", b, err)

	// run: the workloads, through runCommand.translate, without and with a
	// keyholder to wire storage to, with the leaves a run issues.
	images := map[string]string{
		"api": "registry.example/app/my-platform/api@" + sha("e"),
		"web": "registry.example/app/my-platform/web@" + sha("f"),
	}
	rc := runCmd(newFakeRun(twoAppManifest))
	b, err = rc.translate(meta, m.Name, *m, images, credentials, nil, nil, nil)
	add("translate without storage", b, err,
		"Secret my-platform/api-egress", "Secret my-platform/web-egress", "Deployment my-platform/api")
	stored := *meta
	stored.Keyholder = &config.Keyholder{Deployed: true}
	scopes := map[string]datasphere.Scope{"api": {Name: "app-my-platform-api"}, "web": {Name: "app-my-platform-web"}}
	caCertPEM, issue, err := issueAppLeaves(dir, &stored)
	if err != nil {
		t.Fatal(err)
	}
	b, err = rc.translate(&stored, m.Name, *m, images, credentials, scopes, caCertPEM, issue)
	add("translate with storage", b, err,
		"Secret my-platform/api-egress", "Secret my-platform/web-egress", "Deployment my-platform/web")

	// run and build: the build Job, public and private repository.
	for _, secret := range []string{"", "git-credential"} {
		b, err := pbuild.Render(pbuild.Config{
			Instance: instance, Deployment: "my-platform", App: "api",
			Builder: builderDigest, Repo: "https://github.com/example/platform", Ref: "0123456789abcdef0123456789abcdef01234567",
			Containerfile: "services/api/Containerfile", ContextSubPath: "services/api",
			Destination: "registry.example/app/my-platform/api:0123456", GitSecret: secret,
			EgressHosts: []string{"github.com", "registry.example"},
		})
		add(fmt.Sprintf("build gitSecret=%t", secret != ""), b, err)
	}

	// run: the fetch Job, public and private repository.
	for _, secret := range []string{"", "git-credential"} {
		b, err := pfetch.Render(pfetch.Config{
			Instance: instance, Fetcher: fetcherDigest,
			Repo: "https://github.com/example/platform", Ref: "main",
			GitSecret: secret, EgressHosts: []string{"github.com"},
		})
		add(fmt.Sprintf("fetch gitSecret=%t", secret != ""), b, err)
	}

	// git-credential set: the Git credential's Secret, as its plan renders
	// it, from the placeholders (ADR 0023 M2.8, design §33, A33-29).
	user, token := gitCredentialPlaceholders("repo-git")
	b, err = renderGitCredential("repo-git", user, token)
	add("git-credential", b, err, "Secret "+gitCredentialNamespace+"/repo-git")
	return out
}

// kernelConfig is what 'kernel deploy' renders TechnoCore with, for these
// tests.
func kernelConfig(instance string, adapt bool, meter []string) tcdeploy.Config {
	return tcdeploy.Config{
		Image:    "registry.example/technocore@" + sha("c"),
		Instance: instance, Meter: meter,
		CostLimit: 50, CostCurrency: "USD", CostPeriod: "monthly",
		Adapt: adapt, AdaptCooldown: 10 * time.Minute, Interval: time.Minute,
	}
}

// The kernel learns what it meters from technocore-namespaces, and may read a
// namespace only through its RoleBinding there. A stream is applied in order,
// and stopped part-way it leaves what came before it: the in-process client
// stops at its first failure (ADR 0023 M2.7, design §5.3). So the list comes after every binding it names, in both streams that
// write it; before them, a stream stopped between the two would tell the
// kernel to meter a namespace it cannot read (kernelmeter.go's meterManifest,
// kernel.go's kernelManifests).
//
// The same holds for a granted reader's bindings, which both streams carry
// once 'reader grant' recorded the metered scope: world reads the list as the
// reader, so the list comes after the reader's binding in every namespace it
// names too.
func TestTheMeteredListIsAppliedAfterItsBindings(t *testing.T) {
	list := "ConfigMap " + tcdeploy.DefaultNamespace + "/" + kernel.DefaultNamespacesName
	all := []string{"farcast-system", "alpha", "beta"}
	reader := readerEmail("p42", "proj-test1")
	stream := func(b []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, s := range []struct {
		name   string
		stream []byte
		bound  []string
		reader []string // the namespaces whose reader binding must come first
	}{
		{"kernelManifests", stream(kernelManifests(kernelConfig("p42", true, all), "")), all, nil},
		{"meterManifest", stream(meterManifest(all, []string{"alpha", "beta"}, "")), []string{"alpha", "beta"}, nil},
		{"kernelManifests with a reader", stream(kernelManifests(kernelConfig("p42", true, all), reader)), all, all},
		{"meterManifest with a reader", stream(meterManifest(all, []string{"alpha", "beta"}, reader)), []string{"alpha", "beta"}, []string{"alpha", "beta"}},
	} {
		docs, err := kube.SplitStream(s.stream)
		if err != nil {
			t.Fatalf("%s: refused: %v", s.name, err)
		}
		ids := identities(docs)
		at := map[string]int{}
		for i, id := range ids {
			if _, seen := at[id]; seen {
				t.Errorf("%s: %s appears twice in %v", s.name, id, ids)
			}
			at[id] = i
		}
		if ids[len(ids)-1] != list {
			t.Errorf("%s: the last document is %s, not the list; the order is %v", s.name, ids[len(ids)-1], ids)
		}
		for _, ns := range s.bound {
			binding := "RoleBinding " + ns + "/" + tcdeploy.DefaultName
			if i, ok := at[binding]; !ok || i > at[list] {
				t.Errorf("%s: %s does not come before the list; the order is %v", s.name, binding, ids)
			}
		}
		for _, ns := range s.reader {
			binding := "RoleBinding " + ns + "/" + readerRole
			if i, ok := at[binding]; !ok || i > at[list] {
				t.Errorf("%s: %s does not come before the list; the order is %v", s.name, binding, ids)
			}
		}
		if s.reader == nil {
			for _, id := range ids {
				if strings.HasSuffix(id, "/"+readerRole) {
					t.Errorf("%s: with no reader the stream binds one: %v", s.name, ids)
				}
			}
		}
	}
}

// Three fields of a manifest, a repository's text, reach a stream farcast
// applies with the operator's credential: each containerfile and context, as
// the build Job's arguments, and each reason, inside the egress policy's
// JSON. A value that could add documents of its own (a newline, or a line
// break only the API server's reader sees), or that the client's checks would
// refuse, is refused by the parser, so run stops before anything is built;
// and planck/build refuses the same path where it writes the YAML. Every value
// the parser accepts renders streams the client accepts, holding exactly that
// value, so the build is the one the operator reviewed.
func TestManifestTextIsRefusedBeforeTheApplyChecks(t *testing.T) {
	ctx := context.Background()
	manifest := func(containerfile, context, reason string) []byte {
		y := "name: my-platform\napps:\n  - name: api\n    containerfile: " + strconv.QuoteToASCII(containerfile) + "\n"
		if context != "" {
			y += "    context: " + strconv.QuoteToASCII(context) + "\n"
		}
		y += "    external:\n      - host: api.stripe.com\n        reason: " + strconv.QuoteToASCII(reason) + "\n"
		return []byte(y)
	}
	build := func(containerfile, context string) pbuild.Config {
		return pbuild.Config{
			Instance: "p42", Deployment: "my-platform", App: "api",
			Builder: builderDigest, Repo: "https://github.com/example/platform", Ref: testCommit,
			Containerfile: containerfile, ContextSubPath: context,
			Destination: "registry.example/app/my-platform/api:4f2a9c1", EgressHosts: []string{"github.com", "registry.example"},
		}
	}

	breaks := map[string]string{
		"a document": "Containerfile\n---\napiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\n" +
			"metadata:\n  name: injected\n  namespace: farcast-system\n  annotations:\n    rest: |1",
		"U+0085":          "Containerfile\u0085",
		"U+2028":          "Containerfile\u2028",
		"U+2029":          "Containerfile\u2029",
		"a byte order":    "Containerfile\ufeff",
		"a return":        "Containerfile\r",
		"a tab":           "Contai\tnerfile",
		"an escape":       "Containerfile\x1b[2K",
		"a bidi override": "Containerfile\u202e",
	}
	paths := map[string]string{"a quote": `Contai"nerfile`, "a backslash": `services\Containerfile`}
	for what, v := range breaks {
		paths[what] = v
		if _, err := parser.Parse(manifest("Containerfile", "", "payments "+v)); err == nil ||
			!strings.Contains(err.Error(), "apps[0].external[0].reason") {
			t.Errorf("a reason holding %s: the parser did not refuse it by its rule: %v", what, err)
		}
	}
	for what, v := range paths {
		for _, field := range []struct {
			name                   string
			containerfile, context string
		}{
			{"containerfile", v, ""},
			{"context", v + "/Containerfile", v},
		} {
			if _, err := parser.Parse(manifest(field.containerfile, field.context, "payments")); err == nil ||
				!strings.Contains(err.Error(), "apps[0]."+field.name) {
				t.Errorf("a %s holding %s: the parser did not refuse it by its rule: %v", field.name, what, err)
			}
			if b, err := pbuild.Render(build(field.containerfile, field.context)); err == nil {
				t.Errorf("a %s holding %s: planck/build rendered it:\n%s", field.name, what, b)
			}
		}
	}

	for _, v := range []string{"a #b", "a: b", "c:", "- x", "&a *b !c |d >e @f `g %h {i} [j] 'k'", "сервис", " spaced "} {
		reason := `say "` + v + `" \ — 支付`
		m, err := parser.Parse(manifest(v+"/Containerfile", v, reason))
		if err != nil {
			t.Errorf("%q: the parser refused text that prints: %v", v, err)
			continue
		}
		app := m.Apps[0]
		for _, c := range []pbuild.Config{build(app.Containerfile, ""), build(app.Containerfile, app.Context)} {
			b, err := pbuild.Render(c)
			if err != nil {
				t.Errorf("%q: planck/build refused what the parser accepted: %v", v, err)
				continue
			}
			docs, err := kube.SplitStream(b)
			if err != nil {
				t.Errorf("%q: the build stream would be refused at apply time: %v", v, err)
				continue
			}
			want := []string{"--dockerfile=" + app.Containerfile}
			if c.ContextSubPath != "" {
				want = []string{"--context-sub-path=" + v, "--dockerfile=Containerfile"}
			}
			got := kanikoArgs(t, docs)
			for _, w := range want {
				if !slices.Contains(got, w) {
					t.Errorf("%q: the build was given %q, not %q", v, got, w)
				}
			}
		}
		existing, _, err := readEgressPolicyAt(ctx, newFakeRun(twoAppManifest))
		if err != nil {
			t.Fatal(err)
		}
		doc, _, err := egressPolicy(existing, m.Name, *m, mintEgressCredential)
		if err != nil {
			t.Fatal(err)
		}
		b, err := fldeploy.RenderPolicyConfigMap(fldeploy.DefaultNamespace, doc, "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := kube.SplitStream(b); err != nil {
			t.Errorf("%q: the egress policy would be refused at apply time: %v", reason, err)
		}
	}
}

// kanikoArgs are the build Job's container arguments, as the API server's
// reader would decode them from the stream.
func kanikoArgs(t *testing.T, docs []kube.Document) []string {
	t.Helper()
	for _, d := range docs {
		if d.Kind.Kind != "Job" {
			continue
		}
		var job struct {
			Spec struct {
				Template struct {
					Spec struct {
						Containers []struct {
							Args []string `yaml:"args"`
						} `yaml:"containers"`
					} `yaml:"spec"`
				} `yaml:"template"`
			} `yaml:"spec"`
		}
		if err := yaml.Unmarshal(d.Raw, &job); err != nil {
			t.Fatalf("the build Job does not decode: %v", err)
		}
		if cs := job.Spec.Template.Spec.Containers; len(cs) == 1 {
			return cs[0].Args
		}
	}
	t.Fatal("no build Job with one container in the stream")
	return nil
}

func docIdentity(d kube.Document) string {
	return d.Kind.Kind + " " + d.Namespace + "/" + d.Name
}

func identities(docs []kube.Document) []string {
	out := make([]string, 0, len(docs))
	for _, d := range docs {
		out = append(out, docIdentity(d))
	}
	return out
}

func holds(docs []kube.Document, want string) bool {
	for _, d := range docs {
		if docIdentity(d) == want {
			return true
		}
	}
	return false
}

// appliedRefusals collects every stream a fake cluster was asked to apply that
// kube.SplitStream refuses. TestMain fails the package if any arrived, so
// every command test in this package checks what its command composed, exactly
// as it composed it, without each test having to ask.
var appliedRefusals struct {
	sync.Mutex
	errs []string
}

// checkApplied is called by every fake cluster's Apply, and by run's fake's
// ApplyAt with the resourceVersion it was given allowed (opts, as
// cluster.ApplyAt splits its manifest). A refusal is kept with where its
// stream came from: the test that was running, and the line that called the
// fake's Apply, which for a command is the command's own apply.
func checkApplied(m []byte, opts ...kube.SplitOption) {
	if _, err := kube.SplitStream(m, opts...); err != nil {
		test, site := applyCaller()
		appliedRefusals.Lock()
		defer appliedRefusals.Unlock()
		appliedRefusals.errs = append(appliedRefusals.errs, fmt.Sprintf("%s, applied at %s: %v", test, site, err))
	}
}

// applyCaller names the test on the stack, and the frame two above
// checkApplied: the caller of the fake's Apply.
func applyCaller() (test, site string) {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(1, pcs)])
	above := -1 // frames since checkApplied; -1 until it is met
	for {
		f, more := frames.Next()
		name := f.Function[strings.LastIndex(f.Function, "/")+1:] // cli.TestX.func1
		switch {
		case strings.HasSuffix(name, ".checkApplied"):
			above = 0
		case above >= 0:
			above++
			if above == 2 {
				site = fmt.Sprintf("%s:%d (%s)", filepath.Base(f.File), f.Line, name)
			}
		}
		if _, short, ok := strings.Cut(name, "."); ok && strings.HasPrefix(short, "Test") {
			test, _, _ = strings.Cut(short, ".")
		}
		if !more {
			break
		}
	}
	if test == "" {
		test = "no test"
	}
	if site == "" {
		site = "an unknown line"
	}
	return test, site
}

// reportAppliedRefusals writes what checkApplied collected to w and reports
// whether there was anything.
func reportAppliedRefusals(w io.Writer) bool {
	appliedRefusals.Lock()
	defer appliedRefusals.Unlock()
	if len(appliedRefusals.errs) == 0 {
		return false
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "FAIL: %d applied stream(s) would be refused by the in-process client:\n", len(appliedRefusals.errs))
	for _, e := range appliedRefusals.errs {
		fmt.Fprintf(&b, "  %s\n", e)
	}
	_, _ = w.Write(b.Bytes())
	return true
}

// finishTests is TestMain's verdict: the tests' own, failed as well when any
// applied stream was refused. The report is written whatever the tests
// decided, so a refused stream is named even when another test also failed.
func finishTests(code int, w io.Writer) int {
	if reportAppliedRefusals(w) && code == 0 {
		code = 1
	}
	return code
}

// swapAppliedRefusals replaces what checkApplied collected, for a test of the
// collection itself, and returns what was there.
func swapAppliedRefusals(errs []string) []string {
	appliedRefusals.Lock()
	defer appliedRefusals.Unlock()
	saved := appliedRefusals.errs
	appliedRefusals.errs = errs
	return saved
}

// The fakes' check must itself be able to fail, or TestMain's report proves
// nothing; and its report must say where the refused stream came from.
func TestCheckAppliedCollectsARefusal(t *testing.T) {
	saved := swapAppliedRefusals(nil)
	defer swapAppliedRefusals(saved)

	if err := (&fakeJobs{}).Apply(context.Background(), []byte(stringDataSecret)); err != nil {
		t.Fatal(err)
	}
	got := swapAppliedRefusals(nil)
	if len(got) != 1 {
		t.Fatalf("checkApplied collected %d refusals of a stringData Secret, want 1", len(got))
	}
	for _, want := range []string{"TestCheckAppliedCollectsARefusal, applied at manifests_test.go:", "stringData"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("the refusal does not say %q: %s", want, got[0])
		}
	}
}

// A refused stream is reported, and fails the package, whether or not another
// test failed too.
func TestARefusedStreamIsReportedWhateverElseFailed(t *testing.T) {
	saved := swapAppliedRefusals(nil)
	defer swapAppliedRefusals(saved)

	var quiet bytes.Buffer
	if code := finishTests(0, &quiet); code != 0 || quiet.Len() != 0 {
		t.Errorf("with nothing refused: code %d, report %q; want 0 and nothing", code, quiet.String())
	}
	checkApplied([]byte(stringDataSecret))
	for _, code := range []int{0, 1} {
		var b bytes.Buffer
		if got := finishTests(code, &b); got != 1 {
			t.Errorf("tests exiting %d with a refused stream: code %d, want 1", code, got)
		}
		if !strings.Contains(b.String(), "FAIL: 1 applied stream(s) would be refused") ||
			!strings.Contains(b.String(), "TestARefusedStreamIsReportedWhateverElseFailed") {
			t.Errorf("tests exiting %d: the report does not name the refused stream:\n%s", code, b.String())
		}
	}
}

const stringDataSecret = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: web\nstringData:\n  k: v\n"
