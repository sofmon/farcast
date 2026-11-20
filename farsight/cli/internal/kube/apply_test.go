package kube_test

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

func splitOne(t *testing.T, stream string) kube.Document {
	t.Helper()
	docs, err := kube.SplitStream([]byte(stream))
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 {
		t.Fatalf("%d documents", len(docs))
	}
	return docs[0]
}

const settingsV1 = `apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
  namespace: web
  labels:
    app.kubernetes.io/managed-by: farcast
data:
  mode: "on"
`

const settingsV2 = `apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
  namespace: web
  labels:
    app.kubernetes.io/managed-by: farcast
data:
  mode: "off"
`

// TestApplyIsOneServerSideApply: §5.3's request exactly, for a create and an
// update, with force on and off: PATCH to the document's path, the apply
// patch media type, the document's own bytes, and fieldManager=farcast,
// fieldValidation=Strict and force as given.
func TestApplyIsOneServerSideApply(t *testing.T) {
	s := kubetest.New(t)
	c, _ := connect(t, s, "writer")
	ctx := t.Context()

	created := splitOne(t, settingsV1)
	meta, err := c.Apply(ctx, created, true)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Name != "settings" || meta.Namespace != "web" || meta.UID == "" || meta.ResourceVersion == "" {
		t.Errorf("create answered %+v", meta)
	}
	if len(meta.ManagedFields) != 1 || meta.ManagedFields[0].Manager != "farcast" || meta.ManagedFields[0].Operation != "Apply" {
		t.Errorf("create's managed fields = %+v, want farcast/Apply", meta.ManagedFields)
	}
	r := last(t, s)
	if r.Method != http.MethodPatch || r.Path != "/api/v1/namespaces/web/configmaps/settings" ||
		r.RawQuery != "fieldManager=farcast&fieldValidation=Strict&force=true" ||
		r.ContentType != "application/apply-patch+yaml" || r.Accept != "application/json" || !bytes.Equal(r.Body, created.Raw) {
		t.Errorf("apply sent %s %s?%s (%s, Accept %s)\n%s", r.Method, r.Path, r.RawQuery, r.ContentType, r.Accept, r.Body)
	}

	updated := splitOne(t, settingsV2)
	meta2, err := c.Apply(ctx, updated, false)
	if err != nil {
		t.Fatal(err)
	}
	if meta2.UID != meta.UID || meta2.ResourceVersion == meta.ResourceVersion {
		t.Errorf("update answered uid %s rv %s; want the same object at a new resourceVersion", meta2.UID, meta2.ResourceVersion)
	}
	if r := last(t, s); r.RawQuery != "fieldManager=farcast&fieldValidation=Strict&force=false" || !bytes.Equal(r.Body, updated.Raw) {
		t.Errorf("a non-forced apply sent ?%s", r.RawQuery)
	}
	cm, err := c.GetConfigMap(ctx, "web", "settings")
	if err != nil || cm.Data["mode"] != "off" {
		t.Errorf("after the update: %+v, %v", cm, err)
	}
}

// TestEveryWriteNamesFarcast (design §1, A30-9, mutation rows 102 and 102b):
// every write the package makes names farcast's field manager explicitly, so
// the API server never derives one from the User-Agent: Apply, the pin's
// create and replace (CreateConfigMap, ReplaceConfigMap) and the migration's
// PatchJSON, each sent as the writer. DeleteSecret is exempt, for good (ADR
// 0023 M2.8, design §33, A33-31): a DELETE carries DeleteOptions, which has
// no field manager. Its exemption is pinned instead: one DELETE as the
// writer, with no query and exactly the uid-preconditioned DeleteOptions;
// and, by a scan of farsight/cli's source that counts every call, method
// value and method expression named DeleteSecret, in a function or in a
// package-level value, its one caller is cluster.Client.DeleteSecret, whose
// one caller is git-credential rm. The scan's root is checked to be all of
// farsight/cli, cmd/ included, by what it holds.
func TestEveryWriteNamesFarcast(t *testing.T) {
	s := kubetest.New(t)
	s.Put(clientSideApplied("v1", "ConfigMap", "web", "settings", nil))
	c, _ := connect(t, s, "writer")
	ctx := t.Context()
	configmaps := mustKind(t, "v1", "ConfigMap")

	o, err := c.GetObject(ctx, configmaps, "web", "settings")
	if err != nil {
		t.Fatal(err)
	}
	csa, err := kube.ClientSideManagers(o.Metadata.ManagedFields)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := kube.MigrationPatch(o, csa, kube.FieldManager)
	if err != nil || patch == nil {
		t.Fatalf("MigrationPatch = %s, %v", patch, err)
	}
	pin := func(rv string) []byte {
		md := `"name":"datasphered-pin","namespace":"farcast-system"`
		if rv != "" {
			md += `,"resourceVersion":"` + rv + `"`
		}
		return []byte(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{` + md + `},"data":{"pin":"1"}}`)
	}
	// The migration's patch is guarded on the resourceVersion it was read
	// at, so it goes first, and the apply last, as a later write would.
	writes := []struct {
		name   string
		method string
		path   string
		send   func() error
	}{
		{"PatchJSON", http.MethodPatch, "/api/v1/namespaces/web/configmaps/settings", func() error {
			_, err := c.PatchJSON(ctx, configmaps, "web", "settings", patch)
			return err
		}},
		{"CreateConfigMap", http.MethodPost, "/api/v1/namespaces/farcast-system/configmaps", func() error {
			return c.CreateConfigMap(ctx, pin(""))
		}},
		{"ReplaceConfigMap", http.MethodPut, "/api/v1/namespaces/farcast-system/configmaps/datasphered-pin", func() error {
			cm, err := c.GetConfigMap(ctx, "farcast-system", "datasphered-pin")
			if err != nil {
				return err
			}
			return c.ReplaceConfigMap(ctx, pin(cm.Metadata.ResourceVersion))
		}},
		{"Apply", http.MethodPatch, "/api/v1/namespaces/web/configmaps/settings", func() error {
			_, err := c.Apply(ctx, splitOne(t, settingsV2), true)
			return err
		}},
	}
	for _, w := range writes {
		before := len(s.Requests())
		if err := w.send(); err != nil {
			t.Fatalf("%s: %v", w.name, err)
		}
		var sent []kubetest.Request
		for _, r := range s.Requests()[before:] {
			if r.Method == w.method && r.Path == w.path {
				sent = append(sent, r)
			}
		}
		if len(sent) != 1 {
			t.Fatalf("%s: %d %s requests to %s, want 1", w.name, len(sent), w.method, w.path)
		}
		r := sent[0]
		if q := query(t, r); len(q["fieldManager"]) != 1 || q.Get("fieldManager") != kube.FieldManager || r.As != "writer" {
			t.Errorf("%s sent ?%s as %q; want exactly one fieldManager=farcast, as the writer", w.name, r.RawQuery, r.As)
		}
	}

	// The exemption: DeleteSecret's one DELETE.
	s.Put(obj("v1", "Secret", "farcast-system", "repo-git", map[string]any{"metadata": map[string]any{"uid": "00000000-0000-4000-8000-0000000000e1"}}))
	before := len(s.Requests())
	if err := c.DeleteSecret(ctx, "farcast-system", "repo-git", "00000000-0000-4000-8000-0000000000e1"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	var deletes []kubetest.Request
	for _, r := range s.Requests()[before:] {
		if r.Path != "/token" {
			deletes = append(deletes, r)
		}
	}
	const deleteBody = `{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":"00000000-0000-4000-8000-0000000000e1"}}`
	if len(deletes) != 1 || deletes[0].Method != http.MethodDelete || deletes[0].Path != "/api/v1/namespaces/farcast-system/secrets/repo-git" ||
		deletes[0].RawQuery != "" || string(deletes[0].Body) != deleteBody || deletes[0].As != "writer" {
		t.Errorf("DeleteSecret sent %+v; want one DELETE of the Secret as the writer, with no query and the body %s", deletes, deleteBody)
	}

	// Its callers, from the source: all of farsight/cli, its cmd/ as well as
	// its internal/. The root is told by what it holds, not by its name, so a
	// mutation run may point it at a copy of farsight/cli.
	for _, held := range []string{"cmd/farcast/main.go", "internal/cluster/open.go"} {
		if _, err := os.Stat(filepath.Join(deleteSecretScanRoot, filepath.FromSlash(held))); err != nil {
			t.Fatalf("the scan's root %s holds no %s; want farsight/cli, whose cmd/ and internal/ it scans", deleteSecretScanRoot, held)
		}
	}
	callers, err := deleteSecretCallers(deleteSecretScanRoot)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"cli:gitCredentialCommand.remove", "cluster:Client.DeleteSecret"}; !slices.Equal(callers, want) {
		t.Errorf("DeleteSecret is called from %q; want %q, git-credential rm's alone", callers, want)
	}
	t.Run("deleteSecretCallers", func(t *testing.T) {
		root := t.TempDir()
		files := map[string]string{
			"one/one.go": "package one\n\ntype c struct{}\n\nfunc (c) DeleteSecret() {}\nfunc (x *c) remove() { x.DeleteSecret() }\n" +
				"func free(x c) { x.DeleteSecret() }\nfunc (c) Run(d interface{ DeleteSecret() }) { d.DeleteSecret() }\n" +
				// A method value, called through a variable, and one returned.
				"func value(x c) { del := x.DeleteSecret; del() }\nfunc returned(x c) func() { return x.DeleteSecret }\n",
			"one/seams.go": "package one\n\n" +
				// A seam's default, a package-level func literal.
				"var writerDefault = func(x interface{ DeleteSecret() }) { x.DeleteSecret() }\n" +
				// A method expression, at package level.
				"var methodExpr = c.DeleteSecret\n" +
				// Two names, two values; and two names set by one value.
				"var plain, viaLiteral = 1, func(x c) { x.DeleteSecret() }\n" +
				"var both, ok = pair(func(x c) { x.DeleteSecret() })\nfunc pair(any) (int, bool) { return 0, true }\n" +
				"var unrelated = func(x interface{ Delete() }) { x.Delete() }\n",
			"one/one_test.go":  "package one\n\nfunc (x *c) tested() { x.DeleteSecret() }\nvar testSeam = c.DeleteSecret\n",
			"two/deep/deep.go": "package deep\n\nfunc g(x interface{ DeleteSecret() }) { x.DeleteSecret() }\n",
			"two/other.go":     "package two\n\nfunc h(x interface{ deleteSecret() }) { x.deleteSecret() }\n",
			// A command's main, as under farsight/cli/cmd.
			"cmd/tool/main.go": "package main\n\nfunc main() { var x interface{ DeleteSecret() }; x.DeleteSecret() }\n",
		}
		for name, src := range files {
			if err := os.MkdirAll(filepath.Join(root, filepath.Dir(name)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, name), []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		got, err := deleteSecretCallers(root)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"deep:g", "one:both,ok", "one:c.Run", "one:c.remove", "one:free", "one:methodExpr", "one:returned", "one:value", "one:viaLiteral", "one:writerDefault", "tool:main"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("deleteSecretCallers = %q; want %q", got, want)
		}
	})
}

// deleteSecretScanRoot is farsight/cli, whose source, internal/ and cmd/,
// TestEveryWriteNamesFarcast scans for DeleteSecret's callers.
var deleteSecretScanRoot = "../.."

// deleteSecretCallers is every place in the non-test Go source below root
// that names a method DeleteSecret, called or not: a call, a method value
// and a method expression alike, in a function's body or in a package-level
// value such as a seam's default func literal. Each is "<its package's
// directory>:<receiver type>.<method>" or "<directory>:<function>" inside a
// function, and "<directory>:<variable>" in a package-level value (its
// names joined by "," where one value sets several), sorted, once each. It
// reads the files from disk, so a mutation made through go test -overlay is
// not in what it reads.
func deleteSecretCallers(root string) ([]string, error) {
	var found []string
	note := func(caller string, n ast.Node) {
		ast.Inspect(n, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "DeleteSecret" && !slices.Contains(found, caller) {
				found = append(found, caller)
			}
			return true
		})
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		dir := filepath.Base(filepath.Dir(path))
		for _, decl := range f.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Body == nil {
					continue
				}
				name := decl.Name.Name
				if decl.Recv != nil && len(decl.Recv.List) == 1 {
					rt := decl.Recv.List[0].Type
					if star, ok := rt.(*ast.StarExpr); ok {
						rt = star.X
					}
					if id, ok := rt.(*ast.Ident); ok {
						name = id.Name + "." + name
					}
				}
				note(dir+":"+name, decl.Body)
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					var names []string
					for _, n := range vs.Names {
						names = append(names, n.Name)
					}
					for i, v := range vs.Values {
						name := strings.Join(names, ",")
						if len(vs.Values) == len(vs.Names) {
							name = names[i]
						}
						note(dir+":"+name, v)
					}
				}
			}
		}
		return nil
	})
	slices.Sort(found)
	return found, err
}

// TestApplyConflictSurfacesFieldConflicts: a 409 whose causes are
// FieldManagerConflict comes back as an APIError FieldConflicts reads, and
// is not retried.
func TestApplyConflictSurfacesFieldConflicts(t *testing.T) {
	s := kubetest.New(t)
	c, _ := connect(t, s, "writer")
	path := "/api/v1/namespaces/web/configmaps/settings"
	s.Fail(http.MethodPatch, path, http.StatusConflict, kube.Status{
		Status: tkube.Status{Reason: "Conflict", Message: `Apply failed with 1 conflict: conflict with "technocore": .data.mode`},
		Details: &kube.StatusDetails{Name: "settings", Kind: "configmaps", Causes: []kube.StatusCause{
			{Type: "FieldManagerConflict", Message: `conflict with "technocore"`, Field: ".data.mode"},
		}},
	})
	_, err := c.Apply(t.Context(), splitOne(t, settingsV1), false)
	causes, ok := kube.FieldConflicts(err)
	if !ok || len(causes) != 1 || causes[0].Field != ".data.mode" || causes[0].Message != `conflict with "technocore"` {
		t.Fatalf("FieldConflicts(%v) = %+v, %v", err, causes, ok)
	}
	if !errors.Is(err, tkube.ErrConflict) {
		t.Errorf("a conflict does not unwrap to tkube.ErrConflict: %v", err)
	}
	if n := len(requestsTo(s, http.MethodPatch, path)); n != 1 {
		t.Errorf("%d PATCHes; a conflict is not retried", n)
	}
}

// settingsAt is settingsV1 with mode and, unless rv is "", the
// metadata.resourceVersion line `resourceVersion: <rv>`, rv written as given
// (quote it for a YAML string).
func settingsAt(mode, rv string) string {
	s := strings.Replace(settingsV1, `mode: "on"`, "mode: "+mode, 1)
	if rv != "" {
		s = strings.Replace(s, "  namespace: web\n", "  namespace: web\n  resourceVersion: "+rv+"\n", 1)
	}
	return s
}

// TestAllowResourceVersion (design §2.1, A30-40 as A31-2 amends it, §10.5
// row 88c): AllowResourceVersion(rv) lets exactly one document of a stream
// carry metadata.resourceVersion, a YAML string equal to rv. Another value, a
// value that is not a string, and a second document carrying it are each
// refused, and AllowResourceVersion("") allows nothing. Apply accepts the
// document it let through and sends its bytes as they are, so the API server
// holds the apply to that resourceVersion: at the stored one it applies, and
// at a stale one it is a 409 that unwraps to tkube.ErrConflict, with nothing
// written. A Document built by hand from the same bytes never carries the
// allowance, so Apply refuses it and sends nothing.
func TestAllowResourceVersion(t *testing.T) {
	const notTheServers = "it carries metadata.resourceVersion, which only the API server sets"
	for _, row := range []struct {
		name, stream, rv string
		want             string // the refusal, "" for none
	}{
		{"a match", settingsAt("one", `"41"`), "41", ""},
		{"a match, single-quoted", settingsAt("one", `'41'`), "41", ""},
		{"a document that carries none", settingsAt("one", ""), "41", ""},
		{"one carrier among two documents", settingsAt("one", `"41"`) + "---\n" + strings.Replace(settingsAt("two", ""), "name: settings", "name: other", 1), "41", ""},
		{"another value", settingsAt("one", `"40"`), "41",
			`kube: document 0 (ConfigMap "settings") is refused: it carries metadata.resourceVersion "40", and only "41" is allowed`},
		{"a second carrier", settingsAt("one", `"41"`) + "---\n" + strings.Replace(settingsAt("two", `"41"`), "name: settings", "name: other", 1), "41",
			`kube: document 1 (ConfigMap "other") is refused: it carries metadata.resourceVersion, and so does an earlier document of the stream; only one may`},
		{"a number", settingsAt("one", "41"), "41", `kube: document 0 (ConfigMap "settings") is refused: its metadata.resourceVersion is not a YAML string`},
		{"a null", settingsAt("one", "null"), "41", `kube: document 0 (ConfigMap "settings") is refused: its metadata.resourceVersion is not a YAML string`},
		{"no rv to allow", settingsAt("one", `""`), "", `kube: document 0 (ConfigMap "settings") is refused: ` + notTheServers},
		{"no option", settingsAt("one", `"41"`), "-", `kube: document 0 (ConfigMap "settings") is refused: ` + notTheServers},
	} {
		t.Run(row.name, func(t *testing.T) {
			var opts []kube.SplitOption
			if row.rv != "-" {
				opts = append(opts, kube.AllowResourceVersion(row.rv))
			}
			docs, err := kube.SplitStream([]byte(row.stream), opts...)
			switch {
			case row.want == "" && err != nil:
				t.Errorf("SplitStream = %v; want the stream let through", err)
			case row.want != "" && (!errors.Is(err, kube.ErrRefusedDocument) || err.Error() != row.want):
				t.Errorf("SplitStream = %d documents, %v\nwant %q, wrapping ErrRefusedDocument", len(docs), err, row.want)
			}
		})
	}

	t.Run("Apply accepting the allowed document", func(t *testing.T) {
		s := kubetest.New(t)
		c, _ := connect(t, s, "writer")
		ctx := t.Context()
		created, err := c.Apply(ctx, splitOne(t, settingsAt("one", "")), true)
		if err != nil {
			t.Fatal(err)
		}
		stale := created.ResourceVersion
		updated, err := c.Apply(ctx, splitOne(t, settingsAt("two", "")), true)
		if err != nil {
			t.Fatal(err)
		}
		current := updated.ResourceVersion
		at := func(mode, rv string) kube.Document {
			t.Helper()
			docs, err := kube.SplitStream([]byte(settingsAt(mode, `"`+rv+`"`)), kube.AllowResourceVersion(rv))
			if err != nil || len(docs) != 1 {
				t.Fatalf("SplitStream at %s = %d documents, %v", rv, len(docs), err)
			}
			return docs[0]
		}

		// At a stale resourceVersion: 409, nothing written.
		_, err = c.Apply(ctx, at("three", stale), true)
		if !errors.Is(err, tkube.ErrConflict) {
			t.Errorf("an apply at a stale resourceVersion = %v; want a 409 unwrapping to tkube.ErrConflict", err)
		}
		if cm, err := c.GetConfigMap(ctx, "web", "settings"); err != nil || cm.Data["mode"] != "two" || cm.Metadata.ResourceVersion != current {
			t.Errorf("after the refused apply: %+v, %v; want it unwritten", cm, err)
		}

		// At the stored one: applied, the document's bytes sent as they are.
		d := at("four", current)
		md, err := c.Apply(ctx, d, true)
		if err != nil {
			t.Fatalf("an apply at the stored resourceVersion = %v", err)
		}
		if md.ResourceVersion == current {
			t.Errorf("the apply at the stored resourceVersion answered it unmoved")
		}
		if r := last(t, s); r.Method != http.MethodPatch || !bytes.Equal(r.Body, d.Raw) || !bytes.Contains(r.Body, []byte(`resourceVersion: "`+current+`"`)) {
			t.Errorf("the apply sent %s with\n%s\nwant the document's own bytes", r.Method, r.Body)
		}

		// The same bytes in a Document built by hand carry no allowance.
		before := len(s.Requests())
		byHand := kube.Document{Index: d.Index, Kind: d.Kind, Namespace: d.Namespace, Name: d.Name, Raw: d.Raw}
		_, err = c.Apply(ctx, byHand, true)
		if want := `kube: document 0 (ConfigMap "settings") is refused: ` + notTheServers + "; nothing was sent"; !errors.Is(err, kube.ErrRefusedDocument) || err.Error() != want {
			t.Errorf("Apply of a hand-built Document carrying a resourceVersion = %v\nwant %q", err, want)
		}
		if n := len(s.Requests()); n != before {
			t.Errorf("the refused hand-built Document sent %d requests", n-before)
		}
	})
}

// TestApplyRefusesADocumentSplitStreamWouldNot: a hand-built Document with a
// kind outside the table, a name that walks the path, or no bytes is
// refused, and nothing is sent. So is one SplitStream would refuse for what
// its bytes say (F-F3): Apply sends Raw, so it checks Raw again, and Raw must
// be the document the Document names.
func TestApplyRefusesADocumentSplitStreamWouldNot(t *testing.T) {
	s := kubetest.New(t)
	c, _ := connect(t, s, "writer")
	good := splitOne(t, settingsV1)
	crb := mustKind(t, "rbac.authorization.k8s.io/v1", "ClusterRoleBinding")
	crbBytes := func(name string) []byte {
		return []byte("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: " + name +
			"\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n- kind: User\n  name: reader@x.iam.gserviceaccount.com\n")
	}
	secretKind := mustKind(t, "v1", "Secret")
	deployment := mustKind(t, "apps/v1", "Deployment")
	const constructs = "which farcast's renderers never write; the API server reads YAML differently and could see keys this check does not"
	unnamed := crb
	unnamed.Names = nil
	bad := []struct {
		d    kube.Document
		want string // the refusal's reason, when the row pins it
	}{
		{kube.Document{Kind: kube.Kind{Kind: "Pod", APIVersion: "v1", Resource: "pods", Namespaced: true}, Namespace: "web", Name: "p", Raw: good.Raw}, ""},
		{kube.Document{Kind: kube.Kind{Kind: "ConfigMap", APIVersion: "v1", Resource: "secrets", Namespaced: true}, Namespace: "web", Name: "x", Raw: good.Raw}, ""},
		{kube.Document{Kind: good.Kind, Namespace: "web", Name: "..", Raw: good.Raw}, ""},
		{kube.Document{Kind: good.Kind, Namespace: "", Name: "settings", Raw: good.Raw}, ""},
		{kube.Document{Kind: good.Kind, Namespace: "web", Name: "settings"}, ""},
		// The ClusterRoleBinding row's one name: by the Kind's row, by
		// dropping the row's Names, and by bytes that name another.
		{kube.Document{Kind: crb, Name: "grant-everything", Raw: crbBytes("grant-everything")},
			"a ClusterRoleBinding may only be named farcast-reader-namespaces"},
		{kube.Document{Kind: unnamed, Name: "grant-everything", Raw: crbBytes("grant-everything")},
			"a ClusterRoleBinding may only be named farcast-reader-namespaces"},
		{kube.Document{Kind: crb, Name: "farcast-reader-namespaces", Raw: crbBytes("grant-everything")},
			"a ClusterRoleBinding may only be named farcast-reader-namespaces"},
		// Bytes another document's, or carrying what SplitStream refuses.
		{kube.Document{Kind: good.Kind, Namespace: "web", Name: "other", Raw: good.Raw},
			`its bytes are v1 ConfigMap "settings" in namespace "web", not the document it names`},
		{kube.Document{Kind: secretKind, Namespace: "web", Name: "settings", Raw: good.Raw},
			`its bytes are v1 ConfigMap "settings" in namespace "web", not the document it names`},
		{kube.Document{Kind: secretKind, Namespace: "web", Name: "s",
			Raw: []byte("apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: web\nstringData:\n  token: plain\n")},
			"a Secret's stringData does not work well with server-side apply (Kubernetes); render data: with base64 values"},
		{kube.Document{Kind: good.Kind, Namespace: "web", Name: "settings", Raw: append(append([]byte(nil), good.Raw...), "status: {}\n"...)},
			"it carries status, which only the API server sets"},
		{kube.Document{Kind: good.Kind, Namespace: "web", Name: "settings", Raw: append([]byte("---\n"), good.Raw...)},
			"its bytes hold a --- line, so they are more than one document"},
		{kube.Document{Kind: good.Kind, Namespace: "web", Name: "settings", Raw: []byte(strings.ReplaceAll(string(good.Raw), "\n", "\r\n"))},
			"it carries a carriage return, which farcast's renderers never write"},
		{kube.Document{Kind: good.Kind, Namespace: "web", Name: "settings", Raw: []byte("# only a comment\n")}, "its bytes hold no document"},
		// Bytes in which the API server's YAML reader sees a key go-yaml does
		// not (C-C2-1, C-C2-2): Apply checks them again by the same rules.
		{kube.Document{Kind: deployment, Namespace: "web", Name: "d", Raw: []byte(kube.FlowHidingStatus)},
			"it uses a YAML value written right after its colon, " + constructs},
		{kube.Document{Kind: secretKind, Namespace: "web", Name: "s", Raw: []byte(kube.QuestionHidingStringData)},
			"it uses a YAML plain scalar inside a flow collection that is not one word of [A-Za-z0-9._/-], " + constructs},
		{kube.Document{Kind: secretKind, Namespace: "web", Name: "s", Raw: []byte(kube.MultiLineHidingStringData)},
			"it uses a YAML plain scalar inside a flow collection that is not one word of [A-Za-z0-9._/-], " + constructs},
		{kube.Document{Kind: secretKind, Namespace: "web", Name: "s", Raw: []byte(kube.BareEntryHidingStringData)},
			"it uses a YAML sequence entry with nothing after its - on that line, " + constructs},
		{kube.Document{Kind: secretKind, Namespace: "web", Name: "s", Raw: []byte(kube.LoneQuestionHidingStatus)},
			"it uses a YAML plain scalar that starts with an indicator character, " + constructs},
		{kube.Document{Kind: secretKind, Namespace: "web", Name: "s", Raw: []byte(kube.UTF16Polyglot())},
			"it is not UTF-8; the API server's YAML reader decodes a body that starts with a UTF-16 byte order mark as UTF-16, and this check does not"},
		{kube.Document{Kind: good.Kind, Namespace: "web", Name: "settings", Raw: append([]byte("\xfe\xff"), good.Raw...)},
			"it is not UTF-8; the API server's YAML reader decodes a body that starts with a UTF-16 byte order mark as UTF-16, and this check does not"},
	}
	for i, b := range bad {
		_, err := c.Apply(t.Context(), b.d, true)
		if !errors.Is(err, kube.ErrRefusedDocument) {
			t.Errorf("document %d: err = %v, want ErrRefusedDocument", i, err)
			continue
		}
		msg := err.Error()
		if !strings.HasPrefix(msg, "kube: document 0 (") || strings.Count(msg, "kube:") != 1 || !strings.HasSuffix(msg, "; nothing was sent") {
			t.Errorf("document %d: refusal %q is not one framed sentence", i, msg)
		}
		if want := fmt.Sprintf("kube: document 0 (%s %q) is refused: %s; nothing was sent", b.d.Kind.Kind, b.d.Name, b.want); b.want != "" && msg != want {
			t.Errorf("document %d: refusal = %q\nwant          %q", i, msg, want)
		}
	}
	if n := len(s.Requests()); n != 0 {
		t.Errorf("%d requests for refused documents", n)
	}

	// The one name the row allows is applied.
	if _, err := c.Apply(t.Context(), kube.Document{Kind: crb, Name: "farcast-reader-namespaces", Raw: crbBytes("farcast-reader-namespaces")}, true); err != nil {
		t.Errorf("the reader's ClusterRoleBinding: %v", err)
	}
}

// TestDeleteSecretIsPreconditionedOnItsUID: the one delete carries the
// Secret's uid as its precondition; another uid is a 409, an absent Secret a
// 404, and no uid sends nothing.
func TestDeleteSecretIsPreconditionedOnItsUID(t *testing.T) {
	s := kubetest.New(t)
	s.Put(obj("v1", "Secret", "web", "git-credential", map[string]any{"metadata": map[string]any{"uid": "uid-1"}}))
	c, _ := connect(t, s, "writer")
	ctx := t.Context()

	if err := c.DeleteSecret(ctx, "web", "git-credential", ""); !errors.Is(err, kube.ErrRefusedDocument) {
		t.Errorf("no uid: err = %v, want ErrRefusedDocument", err)
	}
	if n := len(s.Requests()); n != 0 {
		t.Errorf("a delete without a uid sent %d requests", n)
	}
	if err := c.DeleteSecret(ctx, "web", "git-credential", "uid-2"); !errors.Is(err, tkube.ErrConflict) {
		t.Errorf("another uid: err = %v, want tkube.ErrConflict", err)
	}
	if err := c.DeleteSecret(ctx, "web", "git-credential", "uid-1"); err != nil {
		t.Fatalf("its own uid: %v", err)
	}
	r := last(t, s)
	// The body is compared byte for byte, never decoded into a struct:
	// encoding/json would read "Preconditions" or "UID" too, and the API
	// server, which decodes case-sensitively and drops an unknown key from a
	// DELETE body, would delete without the precondition.
	const wantBody = `{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":"uid-1"}}`
	if r.Method != http.MethodDelete || r.Path != "/api/v1/namespaces/web/secrets/git-credential" || r.ContentType != "application/json" ||
		string(r.Body) != wantBody {
		t.Errorf("delete sent %s %s (%s) %s\nwant body %s", r.Method, r.Path, r.ContentType, r.Body, wantBody)
	}
	if err := c.DeleteSecret(ctx, "web", "git-credential", "uid-1"); !errors.Is(err, tkube.ErrNotFound) {
		t.Errorf("an absent Secret: err = %v, want tkube.ErrNotFound", err)
	}
}
