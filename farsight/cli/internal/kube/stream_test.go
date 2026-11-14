package kube

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

// The documents the two YAML readers disagree about (C-C2-1, C-C2-2). In each,
// the API server's reader (sigs.k8s.io/yaml v1.6.0 over go.yaml.in/yaml/v2
// v2.4.4, as apimachinery v0.37.2 util/yaml.Unmarshal reads an apply body)
// sees a key that SplitStream refuses, and go-yaml does not.
const (
	// A value written right after its colon: yaml.v2 reads a:"x as one plain
	// scalar and closes the collections after it; go-yaml opens a string at
	// the quote and reads on to the z key's closing quote. The server then
	// reads a top-level status, metadata.resourceVersion, or the last-applied
	// annotation.
	flowHidingStatus          = `{apiVersion: apps/v1, kind: Deployment, metadata: {name: d, namespace: web}, spec: {selector: {matchLabels: {app: d}}, template: {metadata: {labels: {app: d}}, spec: {containers: [{name: c, image: i, args: [a:"x]}]}}}, status: {replicas: 1}}, z: "]}]}}}}` + "\n"
	flowHidingResourceVersion = `{apiVersion: apps/v1, kind: Deployment, spec: {selector: {matchLabels: {app: d}}, template: {metadata: {labels: {app: d}}, spec: {containers: [{name: c, image: i, args: [a:"x]}]}}}, metadata: {name: d, namespace: web, resourceVersion: '1'}}, z: "]}]}}}, metadata: {name: d, namespace: web}}` + "\n"
	flowHidingLastApplied     = `{apiVersion: apps/v1, kind: Deployment, spec: {selector: {matchLabels: {app: d}}, template: {metadata: {labels: {app: d}}, spec: {containers: [{name: c, image: i, args: [a:"x]}]}}}, metadata: {name: d, namespace: web, annotations: {kubectl.kubernetes.io/last-applied-configuration: '{}'}}}, z: "]}]}}}, metadata: {name: d, namespace: web}}` + "\n"
	// A '?' in a flow collection is an explicit key to yaml.v2 and part of a
	// plain scalar to go-yaml.
	questionHidingStringData      = "{apiVersion: v1, kind: Secret, metadata: {name: s, namespace: web}, ?stringData: {k: smuggled}}\n"
	questionHidingStatus          = "{apiVersion: apps/v1, kind: Deployment, metadata: {name: d, namespace: web}, spec: {selector: {matchLabels: {app: d}}, template: {metadata: {labels: {app: d}}, spec: {containers: [{name: c, image: i}]}}}, ?status: {replicas: 1}}\n"
	questionHidingResourceVersion = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: web, ?resourceVersion: \"1\", annotations: {?kubectl.kubernetes.io/last-applied-configuration: x}}\n"
	// A plain scalar over several lines of a flow mapping: go-yaml reads type
	// as "a -, stringData: {k: v}", yaml.v2 a type and a stringData.
	multiLineHidingStringData = "{type: a\n  -, stringData: {k: v}\n , apiVersion: v1, kind: Secret, metadata: {name: s, namespace: web}}\n"
	// An empty entry of a block sequence at its key's column: go-yaml reads
	// the next key into the entry, yaml.v2 as the parent's next key.
	bareEntryHidingStringData      = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: web\ndata:\n-\nstringData:\n  token: smuggled\n"
	bareEntryHidingStatus          = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  namespace: web\ndata:\n- # note\nstatus: {}\n"
	bareEntryHidingResourceVersion = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  namespace: web\n  finalizers:\n  - a\n  - \n  resourceVersion: \"1\"\n"
	// After an empty block scalar, go-yaml reads a quoted key as a plain
	// string, quotes and all; and it folds a lone ? with the line after it
	// into one plain string, where yaml.v2 reads an explicit key.
	quotedKeyAfterFoldedHidingStatus  = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  namespace: web\ndata:\n  k: >\n   \n  \n'status': x\n"
	quotedKeyAfterLiteralHidingStatus = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  namespace: web\ndata:\n  k: |\t\n    \n\"status\" : x\n"
	loneQuestionHidingStatus          = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: web\ndata: \n?\n    status\n"
	loneQuestionHidingResourceVersion = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: web\n  finalizers:\n  ?\n \n   resourceVersion\ndata:\n  k: dg==\n"
)

// utf16Polyglot is a Secret that the API server's YAML reader decodes as
// UTF-16LE, from its byte order mark, with stringData {k: smuggled}, and that
// go-yaml reads as one odd first line followed by a plain Secret with data
// (C-C2-2). The server's lines are separated by U+2028, bytes 28 20, so no
// byte is \n; its last line ends in a comment whose UTF-16 bytes read, to
// go-yaml, as ": zz #", so go-yaml's first line is one key and a comment.
func utf16Polyglot() string {
	const ls = "\u2028"
	server := "apiVersion: v1" + ls + "kind: Secret" + ls + "metadata:" + ls + "  name: s" + ls + "  namespace: web" + ls +
		"stringData:" + ls + "  k: smuggled #\u203a\u7a7a\u2320"
	b := []byte{0xff, 0xfe}
	for _, u := range utf16.Encode([]rune(server)) {
		b = append(b, byte(u), byte(u>>8))
	}
	b = append(b, "\napiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: web\ndata:\n  k: dg==\n"...)
	if len(b)%2 == 1 {
		b = append(b, ' ')
	}
	return string(b)
}

// docFor renders one plain document of kind k, as farcast's templates write
// them: a namespace for a namespaced kind, none for a cluster-scoped one.
func docFor(k Kind, name string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: %s\nkind: %s\nmetadata:\n  name: %s\n", k.APIVersion, k.Kind, name)
	if k.Namespaced {
		b.WriteString("  namespace: web\n")
	}
	b.WriteString("  labels:\n    app.kubernetes.io/managed-by: farcast\n")
	return b.String()
}

func nameFor(k Kind) string {
	if k.Names != nil {
		return k.Names[0]
	}
	return strings.ToLower(k.Kind) + "-1"
}

// TestSplitStreamIdentifiesEveryKind: one document of every kind in the
// table is identified by its apiVersion, kind, namespace and name, in stream
// order, and Raw is the document's own bytes.
func TestSplitStreamIdentifiesEveryKind(t *testing.T) {
	var raws []string
	for _, k := range Kinds {
		raws = append(raws, docFor(k, nameFor(k)))
	}
	stream := "---\n" + strings.Join(raws, "---\n")
	docs, err := SplitStream([]byte(stream))
	if err != nil {
		t.Fatalf("SplitStream: %v", err)
	}
	if len(docs) != len(Kinds) {
		t.Fatalf("got %d documents, want %d", len(docs), len(Kinds))
	}
	for i, d := range docs {
		k := Kinds[i]
		if d.Index != i {
			t.Errorf("document %d has Index %d", i, d.Index)
		}
		if !reflect.DeepEqual(d.Kind, k) {
			t.Errorf("document %d is kind %+v, want %+v", i, d.Kind, k)
		}
		wantNS := ""
		if k.Namespaced {
			wantNS = "web"
		}
		if d.Namespace != wantNS || d.Name != nameFor(k) {
			t.Errorf("document %d is %q/%q, want %q/%q", i, d.Namespace, d.Name, wantNS, nameFor(k))
		}
		if string(d.Raw) != raws[i] {
			t.Errorf("document %d's Raw = %q, want its own bytes %q", i, d.Raw, raws[i])
		}
	}

	// Raw is a copy: editing the stream afterwards changes no document.
	buf := []byte(docFor(Kinds[3], "c"))
	docs, err = SplitStream(buf)
	if err != nil {
		t.Fatal(err)
	}
	buf[0] = 'X'
	if docs[0].Raw[0] != 'a' {
		t.Error("Document.Raw aliases the stream it was split from")
	}
}

// TestSplitStreamSkipsEmptyDocuments: a chunk of blank and comment lines is
// no document, wherever it sits, and does not take an index.
func TestSplitStreamSkipsEmptyDocuments(t *testing.T) {
	first := docFor(Kinds[3], "first")
	second := docFor(Kinds[5], "second")
	stream := "---\n# a comment\n   # an indented one\n\n---\n\n\t\n---\n" + first + "---\n# between\n---\n" + second + "---\n# trailing\n"
	docs, err := SplitStream([]byte(stream))
	if err != nil {
		t.Fatalf("SplitStream: %v", err)
	}
	if len(docs) != 2 {
		t.Fatalf("got %d documents, want 2", len(docs))
	}
	if docs[0].Index != 0 || docs[0].Name != "first" || string(docs[0].Raw) != first {
		t.Errorf("first document = %d %q %q", docs[0].Index, docs[0].Name, docs[0].Raw)
	}
	if docs[1].Index != 1 || docs[1].Name != "second" || string(docs[1].Raw) != second {
		t.Errorf("second document = %d %q %q", docs[1].Index, docs[1].Name, docs[1].Raw)
	}

	for _, empty := range []string{"", "\n", "---\n", "---\n---\n", "# only\n# comments\n", "---\n  \n---\n# x\n"} {
		docs, err := SplitStream([]byte(empty))
		if err != nil || len(docs) != 0 {
			t.Errorf("SplitStream(%q) = %d documents, %v; want none and no error", empty, len(docs), err)
		}
	}

	// A last line without its newline is still the document's.
	last := strings.TrimSuffix(docFor(Kinds[3], "last"), "\n")
	docs, err = SplitStream([]byte(first + "---\n" + last))
	if err != nil || len(docs) != 2 || string(docs[1].Raw) != last {
		t.Errorf("a stream without a final newline: %d documents, %v", len(docs), err)
	}
}

// TestSplitStreamRefuses has one row per reason of §5.2, and one per
// server-set key, so each check fails on its own.
func TestSplitStreamRefuses(t *testing.T) {
	const cm = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  namespace: web\n"
	const secret = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: web\n"
	good := docFor(Kinds[3], "good")
	ident := func(index int, kind, name, reason string) string {
		return fmt.Sprintf("kube: document %d (%s %q) is refused: %s", index, kind, name, reason)
	}
	unident := func(index int, reason string) string {
		return fmt.Sprintf("kube: document %d is refused: %s", index, reason)
	}
	const constructs = "which farcast's renderers never write; the API server reads YAML differently and could see keys this check does not"
	const unicodeBreak = "a line break to the API server's YAML reader and not to this check, which farcast's renderers never write"
	const byteOrderMarkReason = "it carries U+FEFF (BYTE ORDER MARK), which the API server's YAML reader drops at the start of a document and this check does not, and which farcast's renderers never write"
	const notUTF8 = "it is not UTF-8; the API server's YAML reader decodes a body that starts with a UTF-16 byte order mark as UTF-16, and this check does not"
	const flowPlainReason = "it uses a YAML plain scalar inside a flow collection that is not one word of [A-Za-z0-9._/-], " + constructs
	const bareEntryReason = "it uses a YAML sequence entry with nothing after its - on that line, " + constructs
	const indicatorReason = "it uses a YAML plain scalar that starts with an indicator character, " + constructs
	cases := []struct {
		name, stream, want string
	}{
		// Step 1: lines.
		{"a separator with a comment", cm + "--- # x\n" + good,
			unident(0, `a line "--- # x" starts a document separator but is not exactly ---`)},
		{"a separator with a trailing space", good + "--- \n" + cm,
			unident(0, `a line "--- " starts a document separator but is not exactly ---`)},
		{"a separator carrying a document", "--- " + cm,
			unident(0, `a line "--- apiVersion: v1" starts a document separator but is not exactly ---`)},
		{"a carriage return", strings.ReplaceAll(cm, "\n", "\r\n"),
			unident(0, "it carries a carriage return, which farcast's renderers never write")},
		{"a carriage return in a comment-only chunk", "# x\r\n---\n" + cm,
			unident(0, "it carries a carriage return, which farcast's renderers never write")},
		{"a directive", "%YAML 1.2\n---\n" + cm,
			unident(0, "a line at column 0 begins with %, a YAML directive, which farcast's renderers never write")},
		{"a document end", cm + "...\n",
			unident(0, "a line ... ends a YAML document, which farcast's renderers never write")},
		{"the line names the document it is in", good + "---\n# c\n---\n" + cm + "...\n",
			unident(1, "a line ... ends a YAML document, which farcast's renderers never write")},

		// The Unicode line breaks the API server's YAML reader honours and
		// go-yaml does not: behind a comment, each hides a key from every
		// check below while the server applies it (S-F2). One row per
		// character hides a Secret's stringData, one a ConfigMap's
		// metadata.resourceVersion.
		{"NEL hiding stringData", secret + "data: {}  # note\u0085stringData: {token: smuggled}\n",
			unident(0, "it carries U+0085 (NEXT LINE), "+unicodeBreak)},
		{"LS hiding stringData", secret + "data: {}  # note\u2028stringData: {token: smuggled}\n",
			unident(0, "it carries U+2028 (LINE SEPARATOR), "+unicodeBreak)},
		{"PS hiding stringData", secret + "data: {}  # note\u2029stringData: {token: smuggled}\n",
			unident(0, "it carries U+2029 (PARAGRAPH SEPARATOR), "+unicodeBreak)},
		{"NEL hiding resourceVersion", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c  # x\u0085  resourceVersion: \"1\"\n  namespace: web\n",
			unident(0, "it carries U+0085 (NEXT LINE), "+unicodeBreak)},
		{"LS hiding resourceVersion", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c  # x\u2028  resourceVersion: \"1\"\n  namespace: web\n",
			unident(0, "it carries U+2028 (LINE SEPARATOR), "+unicodeBreak)},
		{"PS hiding resourceVersion", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c  # x\u2029  resourceVersion: \"1\"\n  namespace: web\n",
			unident(0, "it carries U+2029 (PARAGRAPH SEPARATOR), "+unicodeBreak)},
		// A byte order mark the API server drops at the start of a body, where
		// go-yaml reads it as part of the first key: "\ufeffstringData" to
		// go-yaml, stringData to the server.
		{"a byte order mark hiding stringData", "\ufeffstringData: {token: smuggled}\n" + secret, unident(0, byteOrderMarkReason)},
		{"a byte order mark in a later document", good + "---\n\ufeff" + cm, unident(1, byteOrderMarkReason)},
		// A UTF-16 byte order mark, which the API server's reader honours and
		// go-yaml does not (C-C2-2): a polyglot hiding stringData, alone and
		// as a later document, and a body that starts FE FF.
		{"a UTF-16LE polyglot hiding stringData", utf16Polyglot(), unident(0, notUTF8)},
		{"a UTF-16LE polyglot in a later document", good + "---\n" + utf16Polyglot(), unident(1, notUTF8)},
		{"a UTF-16BE byte order mark", "\xfe\xff" + cm, unident(0, notUTF8)},

		// Step 3: one mapping, no YAML constructs.
		{"a duplicate key", cm + "kind: Secret\n", unident(0, "it does not parse as YAML (duplicate keys included)")},
		{"a duplicate metadata key", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  name: d\n  namespace: web\n",
			unident(0, "it does not parse as YAML (duplicate keys included)")},
		{"a sequence", "- a\n- b\n", unident(0, "its top level is not a mapping")},
		{"a scalar", "just text\n", unident(0, "its top level is not a mapping")},
		{"an anchor and its alias", cm + "data:\n  a: &x one\n  b: *x\n", ident(0, "ConfigMap", "c", "it uses a YAML anchor, "+constructs)},
		{"a merge key hiding stringData", secret + "<<: {stringData: {token: plain}}\n", ident(0, "Secret", "s", "it uses a YAML merge key, "+constructs)},
		{"a merge key in a nested mapping", cm + "data:\n  <<: {a: b}\n", ident(0, "ConfigMap", "c", "it uses a YAML merge key, "+constructs)},
		{"an explicit tag", cm + "data:\n  a: !!str 1\n", ident(0, "ConfigMap", "c", "it uses a YAML tag, "+constructs)},
		{"a tag on the kind", "apiVersion: v1\nkind: !!str ConfigMap\nmetadata:\n  name: c\n  namespace: web\n",
			unident(0, "it uses a YAML tag, "+constructs)},
		// The constructs the two readers tokenize differently (C-C2-1). Each
		// row hides from go-yaml a key the API server's reader sees.
		{"a value right after its colon hiding status", flowHidingStatus, ident(0, "Deployment", "d", "it uses a YAML value written right after its colon, "+constructs)},
		{"a value right after its colon hiding resourceVersion", flowHidingResourceVersion, ident(0, "Deployment", "d", "it uses a YAML value written right after its colon, "+constructs)},
		{"a value right after its colon hiding the last-applied annotation", flowHidingLastApplied, ident(0, "Deployment", "d", "it uses a YAML value written right after its colon, "+constructs)},
		{"a ? hiding stringData", questionHidingStringData, ident(0, "Secret", "s", flowPlainReason)},
		{"a ? hiding status", questionHidingStatus, ident(0, "Deployment", "d", flowPlainReason)},
		{"a ? hiding resourceVersion", questionHidingResourceVersion, ident(0, "ConfigMap", "c", flowPlainReason)},
		{"a multi-line flow scalar hiding stringData", multiLineHidingStringData, ident(0, "Secret", "s", flowPlainReason)},
		{"a bare sequence entry hiding stringData", bareEntryHidingStringData, ident(0, "Secret", "s", bareEntryReason)},
		{"a bare sequence entry with a comment hiding status", bareEntryHidingStatus, ident(0, "ConfigMap", "c", bareEntryReason)},
		{"a bare sequence entry hiding resourceVersion", bareEntryHidingResourceVersion, ident(0, "ConfigMap", "c", bareEntryReason)},
		{"a single-quoted key after an empty folded scalar hiding status", quotedKeyAfterFoldedHidingStatus, ident(0, "ConfigMap", "c", indicatorReason)},
		{"a double-quoted key after an empty literal scalar hiding status", quotedKeyAfterLiteralHidingStatus, ident(0, "ConfigMap", "c", indicatorReason)},
		{"a lone ? hiding status", loneQuestionHidingStatus, ident(0, "Secret", "s", indicatorReason)},
		{"a lone ? hiding resourceVersion", loneQuestionHidingResourceVersion, ident(0, "Secret", "s", indicatorReason)},

		// Step 4: the header.
		{"metadata that is not a mapping", "apiVersion: v1\nkind: ConfigMap\nmetadata: 5\n",
			unident(0, "its apiVersion, kind and metadata do not decode")},
		{"a name that is not a string", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: 123\n  namespace: web\n",
			ident(0, "ConfigMap", "", "its metadata.name is not a string")},
		{"a namespace that is not a string", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  namespace: [web]\n",
			ident(0, "ConfigMap", "c", "its metadata.namespace is not a string")},
		{"annotations that are not a mapping", cm + "  annotations: [a]\n",
			ident(0, "ConfigMap", "c", "its metadata.annotations is not a mapping")},

		// Step 5, in order.
		{"a kind not in the table", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  namespace: web\n",
			ident(0, "Pod", "p", "kind v1 Pod is not one farcast applies (ADR 0023 decision 2's table)")},
		{"a known kind at another apiVersion", "apiVersion: extensions/v1beta1\nkind: Deployment\nmetadata:\n  name: d\n  namespace: web\n",
			ident(0, "Deployment", "d", "kind extensions/v1beta1 Deployment is not one farcast applies (ADR 0023 decision 2's table)")},
		{"a ClusterRoleBinding of another name", "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n  name: cluster-admin-2\n",
			ident(0, "ClusterRoleBinding", "cluster-admin-2", "a ClusterRoleBinding may only be named farcast-reader-namespaces")},
		{"no name", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  namespace: web\n",
			ident(0, "ConfigMap", "", `its name "" is not 1 to 253 characters of [a-z0-9.-]`)},
		{"no metadata", "apiVersion: v1\nkind: ConfigMap\ndata: {}\n",
			ident(0, "ConfigMap", "", `its name "" is not 1 to 253 characters of [a-z0-9.-]`)},
		{"an upper-case name", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: Web\n  namespace: web\n",
			ident(0, "ConfigMap", "Web", `its name "Web" is not 1 to 253 characters of [a-z0-9.-]`)},
		{"a name with a slash", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a/b\n  namespace: web\n",
			ident(0, "ConfigMap", "a/b", `its name "a/b" is not 1 to 253 characters of [a-z0-9.-]`)},
		{"a name of 254 characters", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + strings.Repeat("a", 254) + "\n  namespace: web\n",
			ident(0, "ConfigMap", strings.Repeat("a", 254), fmt.Sprintf("its name %q is not 1 to 253 characters of [a-z0-9.-]", strings.Repeat("a", 254)))},
		{"a name of ..", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ..\n  namespace: web\n",
			ident(0, "ConfigMap", "..", `its name ".." is not 1 to 253 characters of [a-z0-9.-]`)},
		{"a namespaced kind without a namespace", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n",
			ident(0, "ConfigMap", "c", "a namespaced ConfigMap names no namespace")},
		{"a namespace outside the name rule", "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  namespace: Web_1\n",
			ident(0, "ConfigMap", "c", `its namespace "Web_1" is not 1 to 253 characters of [a-z0-9.-]`)},
		{"a cluster-scoped kind with a namespace", "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: web\n  namespace: other\n",
			ident(0, "Namespace", "web", `a cluster-scoped Namespace names namespace "other"`)},
		{"a Secret's stringData", secret + "stringData:\n  token: plain\n",
			ident(0, "Secret", "s", "a Secret's stringData does not work well with server-side apply (Kubernetes); render data: with base64 values")},
		{"a Secret's empty stringData", secret + "stringData:\n",
			ident(0, "Secret", "s", "a Secret's stringData does not work well with server-side apply (Kubernetes); render data: with base64 values")},
		{"a quoted stringData key", secret + "\"stringData\": {token: plain}\n",
			ident(0, "Secret", "s", "a Secret's stringData does not work well with server-side apply (Kubernetes); render data: with base64 values")},
		{"status", cm + "status: {}\n", ident(0, "ConfigMap", "c", "it carries status, which only the API server sets")},
		{"resourceVersion", cm + "  resourceVersion: \"42\"\n", ident(0, "ConfigMap", "c", "it carries metadata.resourceVersion, which only the API server sets")},
		{`resourceVersion: ""`, cm + "  resourceVersion: \"\"\n", ident(0, "ConfigMap", "c", "it carries metadata.resourceVersion, which only the API server sets")},
		{"a null resourceVersion", cm + "  resourceVersion:\n", ident(0, "ConfigMap", "c", "it carries metadata.resourceVersion, which only the API server sets")},
		{"uid", cm + "  uid: 0b6a\n", ident(0, "ConfigMap", "c", "it carries metadata.uid, which only the API server sets")},
		{"creationTimestamp", cm + "  creationTimestamp: null\n", ident(0, "ConfigMap", "c", "it carries metadata.creationTimestamp, which only the API server sets")},
		{"managedFields", cm + "  managedFields: []\n", ident(0, "ConfigMap", "c", "it carries metadata.managedFields, which only the API server sets")},
		{"the last-applied annotation", cm + "  annotations:\n    kubectl.kubernetes.io/last-applied-configuration: \"{}\"\n",
			ident(0, "ConfigMap", "c", "it carries kubectl's last-applied annotation")},

		// The index counts non-empty documents only.
		{"the second document", "---\n# c\n---\n" + good + "---\n" + cm + "status: {}\n",
			ident(1, "ConfigMap", "c", "it carries status, which only the API server sets")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			docs, err := SplitStream([]byte(tc.stream))
			if err == nil {
				t.Fatalf("SplitStream accepted it: %d documents", len(docs))
			}
			if docs != nil {
				t.Errorf("a refusal returned %d documents", len(docs))
			}
			if !errors.Is(err, ErrRefusedDocument) {
				t.Errorf("error %v does not wrap ErrRefusedDocument", err)
			}
			if err.Error() != tc.want {
				t.Errorf("error = %q\nwant    %q", err.Error(), tc.want)
			}
		})
	}
}

// TestSplitStreamRefusalCarriesNoSecretValue: go-yaml's own errors quote the
// source, so a Secret that fails to parse must not reach the error text.
func TestSplitStreamRefusalCarriesNoSecretValue(t *testing.T) {
	const marker = "c2VjcmV0LW1hcmtlcg=="
	stream := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: web\ndata:\n  token: " + marker + "\n  token: " + marker + "\n"
	_, err := SplitStream([]byte(stream))
	if err == nil {
		t.Fatal("a duplicate key was accepted")
	}
	if strings.Contains(err.Error(), marker) {
		t.Errorf("the refusal carries the Secret's value: %q", err.Error())
	}
}

// TestSplitStreamAcceptsTheShapesRenderersWrite: block scalars holding ---
// or JSON, comments, flow mappings of plain words, flow sequences of quoted
// strings, sequence entries indented or not, plain values holding a colon,
// and plain values starting with - or / are ordinary YAML and pass.
func TestSplitStreamAcceptsTheShapesRenderersWrite(t *testing.T) {
	stream := `# a leading comment
apiVersion: v1
kind: Secret
metadata:
  name: egress # trailing comment
  namespace: web
  labels: {app.kubernetes.io/managed-by: farcast}
  annotations:
    farcast.sofmon.com/note: "--- not a separator"
type: Opaque
data:
  FARCAST_STORAGE_CLIENT_CERT: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg==
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ca
  namespace: web
data:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    MIIB
    -----END CERTIFICATE-----
  namespaces.json: |
    {"version":1,"meter":["farcast-system","web"]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ledger
  namespace: farcast-system
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["technocore-ledger"]
    verbs: ["get", "update", "patch"]
  - apiGroups: ['apps']
    resources: [deployments/scale]
    verbs: [patch]
---
apiVersion: batch/v1
kind: Job
metadata:
  name: fetch
  namespace: web
spec:
  template:
    spec:
      containers:
      - name: fetch
        image: registry.example/fetch@sha256:0123abcd
        command: ["/bin/sh", "-c"]
        args: ["git clone https://example.invalid/repo.git && echo done: ok"]
        ports:
        - containerPort: 8443
      - name: proxy
        image: registry.example/proxy:1.2
        args:
          - --listen=:8443
          - /etc/proxy/config.yaml
        env:
          - {name: MODE, value: "a:b"}
          - name: URL
            value: https://example.invalid:8443/path
`
	docs, err := SplitStream([]byte(stream))
	if err != nil {
		t.Fatalf("SplitStream: %v", err)
	}
	if len(docs) != 4 || docs[0].Kind.Kind != "Secret" || docs[1].Kind.Kind != "ConfigMap" || docs[2].Kind.Kind != "Role" || docs[3].Kind.Kind != "Job" {
		t.Fatalf("got %+v", docs)
	}
}
