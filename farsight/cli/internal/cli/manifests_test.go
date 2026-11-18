package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
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
	"github.com/sofmon/farcast/manifest/parser"
	pbuild "github.com/sofmon/farcast/planck/build"
	pfetch "github.com/sofmon/farcast/planck/fetch"
	"github.com/sofmon/farcast/technocore/cost"
	tcdeploy "github.com/sofmon/farcast/technocore/deploy"
	"github.com/sofmon/farcast/technocore/kernel"
)

// Every stream farcast applies must pass the checks the in-process client
// makes before it sends anything (ADR 0023 decision 2, Verification 1): one
// that does not would be refused the day the client replaces kubectl. So every
// renderer's output, and every stream a command composes from several
// renderers, goes through kube.SplitStream here, built by the same function
// the command calls. A rendered stringData, an unknown kind, a missing
// namespace or a YAML anchor fails the build.
//
// Thirteen places apply a stream today, and this table covers each:
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
//   - run and build: the build Job; run: the fetch Job.
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
	b, err = fldeploy.RenderPolicyConfigMap(fldeploy.DefaultNamespace, doc)
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
// and stopped part-way it leaves what came before it: kubectl interrupted
// today, and the in-process client at its first failure (ADR 0023 M2, design
// §5.3). So the list comes after every binding it names, in both streams that
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
		b, err := fldeploy.RenderPolicyConfigMap(fldeploy.DefaultNamespace, doc)
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

// checkApplied is called by every fake cluster's Apply. A refusal is kept with
// where its stream came from: the test that was running, and the line that
// called the fake's Apply, which for a command is the command's own apply.
func checkApplied(m []byte) {
	if _, err := kube.SplitStream(m); err != nil {
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
