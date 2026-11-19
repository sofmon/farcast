package kube

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// Document is one checked document of a rendered stream.
type Document struct {
	Index     int // position among the non-empty documents, from 0
	Kind      Kind
	Namespace string // "" for cluster-scoped
	Name      string
	Raw       []byte // the document's own bytes, sent unchanged as the apply body

	// allowedResourceVersion is the metadata.resourceVersion Raw carries
	// because AllowResourceVersion let it, "" when it carries none. Only
	// SplitStream sets it, and Apply's rawFault honours it, so a Document
	// built by hand never carries one.
	allowedResourceVersion string
}

// SplitOption adjusts SplitStream.
type SplitOption func(*splitOptions)

type splitOptions struct {
	// resourceVersion is the one metadata.resourceVersion a document may
	// carry (AllowResourceVersion), "" for none.
	resourceVersion string
}

// AllowResourceVersion lets exactly one document of the stream carry
// metadata.resourceVersion, and only as a YAML string equal to rv (design
// §2.1, A30-40). Any other value, one that is not a string, and a second
// document that carries one are each refused. With rv "" it allows nothing.
//
// The API server holds an apply that carries a resourceVersion to it: one
// that is no longer the stored one is answered 409 and nothing is written
// (§31, A31-2). That is the egress policy's precondition. An object deleted
// since it was read is created again, so the precondition cannot tell it from
// one that was never there.
func AllowResourceVersion(rv string) SplitOption {
	return func(o *splitOptions) { o.resourceVersion = rv }
}

// resourceVersionAllowance is what inspectDocument lets a document's
// metadata.resourceVersion be: value ("" allows none), and only while no
// earlier document of the stream has carried it (carried).
type resourceVersionAllowance struct {
	value   string
	carried bool
}

// fault is why the value v of metadata.resourceVersion is refused under a,
// "" when a lets it through.
func (a resourceVersionAllowance) fault(v any) string {
	switch s, isString := v.(string); {
	case a.value == "":
		return "it carries metadata.resourceVersion, which only the API server sets"
	case a.carried:
		return "it carries metadata.resourceVersion, and so does an earlier document of the stream; only one may"
	case !isString:
		return "its metadata.resourceVersion is not a YAML string"
	case s != a.value:
		return fmt.Sprintf("it carries metadata.resourceVersion %q, and only %q is allowed", s, a.value)
	}
	return ""
}

// lastAppliedAnnotation is kubectl's client-side apply annotation
// (corev1.LastAppliedConfigAnnotation).
const lastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// serverSetMetadata are the metadata keys only the API server sets. A
// document carrying any of them is refused by presence, whatever the value.
var serverSetMetadata = [...]string{"resourceVersion", "uid", "creationTimestamp", "managedFields"}

// objectName is §5.2's name rule: 1 to 253 characters of [a-z0-9.-].
var objectName = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)

// SplitStream splits and checks a rendered multi-document stream (§5.2).
// Any refusal wraps ErrRefusedDocument and names the document's index, kind and name.
//
// The YAML library is used only to check and identify each document, never
// to re-encode it: Raw is the document's own bytes. A refusal met before a
// document could be identified (a forbidden line, or YAML that does not
// parse) names the index alone. A stream with no non-empty document yields
// no Document and no error.
func SplitStream(stream []byte, opts ...SplitOption) ([]Document, error) {
	var o splitOptions
	for _, opt := range opts {
		opt(&o)
	}

	chunks := splitChunks(stream)

	// 1. The lines no renderer writes, anywhere in the stream.
	index := 0
	for _, c := range chunks {
		for _, line := range c.lines {
			if reason := lineFault(line); reason != "" {
				return nil, refuseDocument(index, "", "", "%s", reason)
			}
		}
		if !c.empty() {
			index++
		}
	}

	// 2. Split on lines exactly ---, skipping chunks of blanks and comments.
	var docs []Document
	allow := resourceVersionAllowance{value: o.resourceVersion}
	for _, c := range chunks {
		if c.empty() {
			continue
		}
		d, err := checkDocument(len(docs), c.raw, allow)
		if err != nil {
			return nil, err
		}
		allow.carried = allow.carried || d.allowedResourceVersion != ""
		docs = append(docs, d)
	}
	return docs, nil
}

// chunk is the text between two separator lines.
type chunk struct {
	raw   []byte   // its bytes, each line with its own "\n"
	lines []string // its lines, without "\n"
}

// empty reports whether every line is blank or a comment (optional spaces,
// then #). go-yaml's decoder loops on an empty document, and its parser makes
// one with no body, so such a chunk is no document at all.
func (c chunk) empty() bool {
	for _, l := range c.lines {
		t := strings.TrimLeft(l, " \t")
		if t != "" && !strings.HasPrefix(t, "#") {
			return false
		}
	}
	return true
}

// splitChunks cuts stream at every line that is exactly ---.
func splitChunks(stream []byte) []chunk {
	var chunks []chunk
	var cur chunk
	for len(stream) > 0 {
		end := bytes.IndexByte(stream, '\n')
		var line, withNL []byte
		if end < 0 {
			line, withNL, stream = stream, stream, nil
		} else {
			line, withNL, stream = stream[:end], stream[:end+1], stream[end+1:]
		}
		if string(line) == "---" {
			chunks = append(chunks, cur)
			cur = chunk{}
			continue
		}
		cur.raw = append(cur.raw, withNL...)
		cur.lines = append(cur.lines, string(line))
	}
	return append(chunks, cur)
}

// unicodeBreaks are the line breaks other than \n and \r that the API
// server's YAML reader ends a line at, and go-yaml does not. The server decodes
// an apply body with k8s.io/apimachinery v0.37.2 pkg/util/yaml (apiserver
// v0.37.2 pkg/endpoints/handlers/patch.go, newApplyPatcher), which is
// sigs.k8s.io/yaml over go.yaml.in/yaml/v2, whose is_break counts NEL, LS and
// PS (go.yaml.in/yaml/v2 v2.4.2, yamlprivateh.go). go-yaml's scanner counts
// only \n and \r (vendor/github.com/goccy/go-yaml/scanner/scanner.go,
// isNewLineChar), so a key after one of these inside a comment is a key the
// server applies and this check never sees.
var unicodeBreaks = [...]struct {
	char string
	name string
}{
	{"\u0085", "U+0085 (NEXT LINE)"},
	{"\u2028", "U+2028 (LINE SEPARATOR)"},
	{"\u2029", "U+2029 (PARAGRAPH SEPARATOR)"},
}

// byteOrderMark is U+FEFF. The API server's YAML reader drops it at the start
// of a body (go.yaml.in/yaml/v2 v2.4.2, readerc.go,
// yaml_parser_determine_encoding), while go-yaml reads it as part of the first
// key, so the two would disagree about that key's name: "\ufeffstringData" to
// this check, stringData to the server. Each document is its own apply body,
// so the start of any document is the start of a body.
const byteOrderMark = "\ufeff"

// lineFault is step 1 of §5.2 for one line: the reason it is refused, or "".
//
// A line that is not UTF-8 is refused first. The API server's YAML reader
// decodes a body that starts with a UTF-16 byte order mark (FF FE or FE FF) as
// UTF-16 (go.yaml.in/yaml/v2 v2.4.4, readerc.go,
// yaml_parser_determine_encoding), while this check reads every body as
// UTF-8, so the two would read different keys from the same bytes. Valid
// UTF-8 never holds either mark. The reason never quotes the line.
func lineFault(line string) string {
	if !utf8.ValidString(line) {
		return "it is not UTF-8; the API server's YAML reader decodes a body that starts with a UTF-16 byte order mark as UTF-16, and this check does not"
	}
	if strings.Contains(line, "\r") {
		return "it carries a carriage return, which farcast's renderers never write"
	}
	for _, b := range unicodeBreaks {
		if strings.Contains(line, b.char) {
			return fmt.Sprintf("it carries %s, a line break to the API server's YAML reader and not to this check, which farcast's renderers never write", b.name)
		}
	}
	switch {
	case strings.Contains(line, byteOrderMark):
		return "it carries U+FEFF (BYTE ORDER MARK), which the API server's YAML reader drops at the start of a document and this check does not, and which farcast's renderers never write"
	case strings.HasPrefix(line, "%"):
		return "a line at column 0 begins with %, a YAML directive, which farcast's renderers never write"
	case line == "...":
		return "a line ... ends a YAML document, which farcast's renderers never write"
	case strings.HasPrefix(line, "---") && line != "---":
		return fmt.Sprintf("a line %q starts a document separator but is not exactly ---", line)
	}
	return ""
}

// refuseDocument is §5.2's refusal: "kube: document %d (%s %q) is refused:
// <reason>", or, before the document's kind is known, "kube: document %d is
// refused: <reason>".
func refuseDocument(index int, kind, name, reason string, a ...any) error {
	r := fmt.Sprintf(reason, a...)
	if kind == "" {
		return refuse(ErrRefusedDocument, "kube: document %d is refused: %s", index, r)
	}
	return refuse(ErrRefusedDocument, "kube: document %d (%s %q) is refused: %s", index, kind, name, r)
}

// header is the part of a document that identifies it. The tags are explicit:
// go-yaml lower-cases an untagged field's name, so an untagged APIVersion
// would read the key apiversion and never apiVersion.
type header struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Metadata   map[string]any `yaml:"metadata"`
}

// checkDocument is steps 3 to 5 of §5.2 for one non-empty chunk, with what
// allow lets its metadata.resourceVersion be.
func checkDocument(index int, raw []byte, allow resourceVersionAllowance) (Document, error) {
	d, f := inspectDocument(index, raw, allow)
	if f != nil {
		return Document{}, refuseDocument(index, f.kind, f.name, "%s", f.reason)
	}
	return d, nil
}

// documentFault is why inspectDocument refused a document: its kind and name
// as far as they were read ("" before they were), and the reason.
type documentFault struct{ kind, name, reason string }

// inspectDocument is checkDocument without the framing of the refusal, so
// Apply can give the reason in its own sentence. A metadata.resourceVersion
// allow lets through is the Document's allowedResourceVersion.
func inspectDocument(index int, raw []byte, allow resourceVersionAllowance) (Document, *documentFault) {
	unidentified := func(reason string, a ...any) (Document, *documentFault) {
		return Document{}, &documentFault{reason: fmt.Sprintf(reason, a...)}
	}

	// 3. Exactly one document whose body is a mapping, with no construct the
	// API server's YAML reader could read differently.
	f, err := parser.ParseBytes(raw, 0)
	if err != nil {
		// go-yaml's error quotes the source around the fault, which in a
		// Secret is key material, so only the fact is reported.
		return unidentified("it does not parse as YAML (duplicate keys included)")
	}
	if len(f.Docs) != 1 {
		return unidentified("it holds %d YAML documents, not one", len(f.Docs))
	}
	body, ok := f.Docs[0].Body.(*ast.MappingNode)
	if !ok {
		return unidentified("its top level is not a mapping")
	}
	if construct := findConstruct(f.Docs[0]); construct != "" {
		kind, name := identify(body)
		return Document{}, &documentFault{kind: kind, name: name, reason: fmt.Sprintf(
			"it uses a YAML %s, which farcast's renderers never write; the API server reads YAML differently and could see keys this check does not", construct)}
	}

	// 4. The header, and the top-level keys.
	var h header
	if err := yaml.Unmarshal(raw, &h); err != nil {
		return unidentified("its apiVersion, kind and metadata do not decode")
	}
	var top map[string]any
	if err := yaml.Unmarshal(raw, &top); err != nil {
		return unidentified("its top-level keys do not decode")
	}
	name, nameOK := h.Metadata["name"].(string)
	namespace, namespaceOK := h.Metadata["namespace"].(string)
	refuseHere := func(reason string, a ...any) (Document, *documentFault) {
		return Document{}, &documentFault{kind: h.Kind, name: name, reason: fmt.Sprintf(reason, a...)}
	}
	if v, present := h.Metadata["name"]; present && v != nil && !nameOK {
		return refuseHere("its metadata.name is not a string")
	}
	if v, present := h.Metadata["namespace"]; present && v != nil && !namespaceOK {
		return refuseHere("its metadata.namespace is not a string")
	}
	var annotations map[string]any
	if v, present := h.Metadata["annotations"]; present && v != nil {
		if annotations, ok = v.(map[string]any); !ok {
			return refuseHere("its metadata.annotations is not a mapping")
		}
	}

	// 5. The checks, in order.
	k, ok := KindOf(h.APIVersion, h.Kind)
	if !ok {
		return refuseHere("kind %s %s is not one farcast applies (ADR 0023 decision 2's table)", h.APIVersion, h.Kind)
	}
	if k.Names != nil && !containsString(k.Names, name) {
		return refuseHere("a %s may only be named %s", k.Kind, strings.Join(k.Names, " or "))
	}
	if !validObjectName(name) {
		return refuseHere("its name %q is not 1 to 253 characters of [a-z0-9.-]", name)
	}
	if k.Namespaced && namespace == "" {
		return refuseHere("a namespaced %s names no namespace", k.Kind)
	}
	if k.Namespaced && !validObjectName(namespace) {
		return refuseHere("its namespace %q is not 1 to 253 characters of [a-z0-9.-]", namespace)
	}
	if !k.Namespaced && namespace != "" {
		return refuseHere("a cluster-scoped %s names namespace %q", k.Kind, namespace)
	}
	if _, present := top["stringData"]; present && k.Kind == "Secret" {
		return refuseHere("a Secret's stringData does not work well with server-side apply (Kubernetes); render data: with base64 values")
	}
	if _, present := top["status"]; present {
		return refuseHere("it carries status, which only the API server sets")
	}
	var allowed string
	for _, key := range serverSetMetadata {
		v, present := h.Metadata[key]
		switch {
		case !present:
		case key == "resourceVersion":
			if reason := allow.fault(v); reason != "" {
				return refuseHere("%s", reason)
			}
			allowed = allow.value
		default:
			return refuseHere("it carries metadata.%s, which only the API server sets", key)
		}
	}
	if _, present := annotations[lastAppliedAnnotation]; present {
		return refuseHere("it carries kubectl's last-applied annotation")
	}
	if !k.Namespaced {
		namespace = ""
	}
	return Document{Index: index, Kind: k, Namespace: namespace, Name: name, Raw: bytes.Clone(raw), allowedResourceVersion: allowed}, nil
}

// rawFault is why d's bytes are not the document d says they are, "" when
// they are. Apply sends d.Raw, not d's fields, so a Document built by hand
// rather than by SplitStream is checked again here: §5.2's steps run on d.Raw
// alone, which must be exactly one non-empty document, and the kind, namespace
// and name they read must be d's. It runs with the allowance SplitStream gave
// d and no other: the metadata.resourceVersion AllowResourceVersion let
// through (d's allowedResourceVersion), which a Document built by hand never
// has, so its bytes may carry none.
func rawFault(d Document) string {
	chunks := splitChunks(d.Raw)
	if len(chunks) != 1 {
		return "its bytes hold a --- line, so they are more than one document"
	}
	c := chunks[0]
	for _, line := range c.lines {
		if reason := lineFault(line); reason != "" {
			return reason
		}
	}
	if c.empty() {
		return "its bytes hold no document"
	}
	got, f := inspectDocument(d.Index, d.Raw, resourceVersionAllowance{value: d.allowedResourceVersion})
	if f != nil {
		return f.reason
	}
	if got.Kind.APIVersion != d.Kind.APIVersion || got.Kind.Kind != d.Kind.Kind || got.Namespace != d.Namespace || got.Name != d.Name {
		return fmt.Sprintf("its bytes are %s %s %q in namespace %q, not the document it names", got.Kind.APIVersion, got.Kind.Kind, got.Name, got.Namespace)
	}
	return ""
}

// validObjectName is §5.2's name rule. "." and "..", which the rule's
// characters allow, are refused too: as a path segment either would walk the
// URL somewhere else.
func validObjectName(s string) bool {
	return objectName.MatchString(s) && s != "." && s != ".."
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// flowWord is the only plain scalar allowed inside a flow collection: one
// word of these characters, or nothing. Everything else there is quoted.
var flowWord = regexp.MustCompile(`^[A-Za-z0-9._/-]*$`)

// The constructs findConstruct names besides anchors, aliases, merge keys and
// tags. go-yaml and the API server's YAML reader (go.yaml.in/yaml/v2 v2.4.4,
// scannerc.go) end tokens in different places around them, so the two can
// disagree about which keys a document holds:
//   - a value written right after its colon: yaml.v2 ends a plain scalar at
//     ':' only when a blank follows, so `a:"x` is one scalar to it, while
//     go-yaml opens a quoted string after the colon and reads on past the
//     brackets that end the collection;
//   - inside a flow collection, a plain scalar with any other character:
//     yaml.v2 reads a '?' there as an explicit key, so `?stringData` is the
//     key stringData to it and the string "?stringData" to go-yaml, and the
//     two fold a plain scalar that runs over several lines differently;
//   - a block sequence entry with nothing after its dash on that line: when
//     the entry is empty and the next line is a key at the dash's own column,
//     go-yaml reads that key into the entry, and yaml.v2 reads it as the
//     entry's parent's next key, so `data:\n-\nstringData: …` hides
//     stringData from this check alone;
//   - outside a flow collection, a plain scalar that starts with an indicator
//     character: after an empty block scalar go-yaml can read a quoted key,
//     'status', as the plain string "'status'", and it folds a lone ? and the
//     line after it into the plain string "? status" where yaml.v2 reads an
//     explicit key.
//
// farcast's renderers quote every flow scalar that is not one plain word,
// start every sequence entry's value on its dash's line, and start every
// other plain scalar with a letter, a digit, or one of the few safe
// characters.
const (
	constructAdjacentValue = "value written right after its colon"
	constructFlowPlain     = "plain scalar inside a flow collection that is not one word of [A-Za-z0-9._/-]"
	constructBareEntry     = "sequence entry with nothing after its - on that line"
	constructIndicator     = "plain scalar that starts with an indicator character"
)

// plainIndicators are the characters YAML reserves at the start of a plain
// scalar (YAML 1.2.2 §5.3, c-indicator), but -, which starts many a command
// line flag: a plain scalar starting with any of them is refused.
const plainIndicators = "?:,[]{}#&*!|>'\"%@`"

// constructFinder records the first construct farcast's renderers never
// write: an anchor, alias, merge key or explicit tag, or one of the
// constructs above that the two readers tokenize differently. It is passed by
// value, so inFlow holds for the subtree below the flow collection that set
// it; found is shared by the whole walk.
type constructFinder struct {
	found  *string
	inFlow bool
}

func (c constructFinder) Visit(n ast.Node) ast.Visitor {
	if n == nil || *c.found != "" {
		return nil
	}
	switch n.Type() {
	case ast.AnchorType:
		*c.found = "anchor"
		return nil
	case ast.AliasType:
		*c.found = "alias"
		return nil
	case ast.MergeKeyType:
		*c.found = "merge key"
		return nil
	case ast.TagType:
		*c.found = "tag"
		return nil
	}
	switch v := n.(type) {
	case *ast.MappingNode:
		c.inFlow = c.inFlow || v.IsFlowStyle
	case *ast.SequenceNode:
		c.inFlow = c.inFlow || v.IsFlowStyle
		for _, e := range v.Entries {
			if !v.IsFlowStyle && bareEntry(e) {
				*c.found = constructBareEntry
				return nil
			}
		}
	case *ast.MappingValueNode:
		c.inFlow = c.inFlow || v.IsFlowStyle
		if colon := v.Start; colon != nil && colon.Next != nil && colon.Position != nil && colon.Next.Position != nil &&
			colon.Next.Position.Line == colon.Position.Line && colon.Next.Position.Column == colon.Position.Column+1 {
			*c.found = constructAdjacentValue
			return nil
		}
	case *ast.LiteralNode:
		// A block scalar's text is its own, to both readers: its lines are
		// not YAML, so the string below it is not walked.
		return nil
	case ast.ScalarNode:
		if construct := plainFault(v, c.inFlow); construct != "" {
			*c.found = construct
			return nil
		}
	}
	return c
}

// bareEntry reports whether a block sequence entry has nothing but blanks or
// a comment after its dash on the dash's line.
func bareEntry(e *ast.SequenceEntryNode) bool {
	dash := e.Start
	if dash == nil || dash.Position == nil {
		return false
	}
	next := dash.Next
	for next != nil && next.Type.String() == "Comment" {
		next = next.Next
	}
	return next == nil || next.Position == nil || next.Position.Line != dash.Position.Line
}

// plainFault names the construct a plain scalar (one that is not quoted) is
// refused as, or returns "": inside a flow collection, any that is not one
// word of flowWord; elsewhere, one that starts with an indicator character.
// Block scalars never reach it: their text is not walked.
func plainFault(n ast.ScalarNode, inFlow bool) string {
	tok := n.GetToken()
	if tok == nil {
		return ""
	}
	switch tok.Type.String() {
	case "SingleQuote", "DoubleQuote":
		return ""
	}
	switch {
	case inFlow && !flowWord.MatchString(tok.Value):
		return constructFlowPlain
	case !inFlow && tok.Value != "" && strings.ContainsRune(plainIndicators, rune(tok.Value[0])):
		return constructIndicator
	}
	return ""
}

// findConstruct walks the whole document and names the first construct
// farcast's renderers never write, or returns "".
func findConstruct(doc *ast.DocumentNode) string {
	var found string
	ast.Walk(constructFinder{found: &found}, doc)
	return found
}

// identify reads a document's kind and name from its parsed mapping, for a
// refusal's text only: plain string values, no alias followed.
func identify(m *ast.MappingNode) (kind, name string) {
	for _, mv := range m.Values {
		key, ok := mv.Key.(*ast.StringNode)
		if !ok {
			continue
		}
		switch key.Value {
		case "kind":
			if s, ok := mv.Value.(*ast.StringNode); ok {
				kind = s.Value
			}
		case "metadata":
			md, ok := mv.Value.(*ast.MappingNode)
			if !ok {
				continue
			}
			for _, f := range md.Values {
				if k, ok := f.Key.(*ast.StringNode); ok && k.Value == "name" {
					if s, ok := f.Value.(*ast.StringNode); ok {
						name = s.Value
					}
				}
			}
		}
	}
	return kind, name
}
