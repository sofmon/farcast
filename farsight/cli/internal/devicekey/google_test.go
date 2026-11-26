package devicekey

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// pemOneLine is der's PEM without its last newline: what a trust store holds.
func pemOneLine(der []byte) string {
	return strings.TrimSuffix(string(encodeCert(der)), "\n")
}

// mapKeys is m's keys, sorted, for a document parsed into any.
func mapKeys(t *testing.T, v any) []string {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%T is not a mapping with string keys", v)
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// testAnchorDER is a new anchor's DER and its ID.
func testAnchorDER(t *testing.T) (RoleID, []byte) {
	t.Helper()
	id, err := NewRoleID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _, err := newAnchor(rand.Reader, id, t0)
	if err != nil {
		t.Fatal(err)
	}
	return id, der
}

// trustStoreValue parses doc with go-yaml and returns its one pemCertificate.
func trustStoreValue(t *testing.T, doc []byte) string {
	t.Helper()
	var v any
	if err := yaml.Unmarshal(doc, &v); err != nil {
		t.Fatalf("go-yaml does not parse the trust store: %v", err)
	}
	if keys := mapKeys(t, v); !slices.Equal(keys, []string{"trustStore"}) {
		t.Fatalf("top-level keys %v, want only trustStore", keys)
	}
	ts := v.(map[string]any)["trustStore"]
	if keys := mapKeys(t, ts); !slices.Equal(keys, []string{"trustAnchors"}) {
		t.Fatalf("trustStore keys %v, want only trustAnchors", keys)
	}
	anchors, ok := ts.(map[string]any)["trustAnchors"].([]any)
	if !ok || len(anchors) != 1 {
		t.Fatalf("trustAnchors = %#v, want exactly one entry", ts.(map[string]any)["trustAnchors"])
	}
	if keys := mapKeys(t, anchors[0]); !slices.Equal(keys, []string{"pemCertificate"}) {
		t.Fatalf("the entry's keys %v, want only pemCertificate", keys)
	}
	s, ok := anchors[0].(map[string]any)["pemCertificate"].(string)
	if !ok {
		t.Fatal("pemCertificate is not a string")
	}
	return s
}

// TestTrustStoreYAMLParsesToExactlyOneAnchor: the document parses to one
// anchor whose PEM is the anchor, in Google's one-line form.
func TestTrustStoreYAMLParsesToExactlyOneAnchor(t *testing.T) {
	_, der := testAnchorDER(t)
	doc, err := TrustStoreYAML(der)
	if err != nil {
		t.Fatal(err)
	}
	value := trustStoreValue(t, doc)
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || string(block.Bytes) != string(der) {
		t.Fatal("the pemCertificate is not one CERTIFICATE block holding the anchor")
	}
	if len(rest) != 0 {
		t.Errorf("the pemCertificate has %d bytes after its block", len(rest))
	}
	raw := string(doc)
	if n := strings.Count(raw, "pemCertificate"); n != 1 || len(strings.Split(strings.TrimSuffix(raw, "\n"), "\n")) != 3 {
		t.Errorf("the document is not three lines with one pemCertificate:\n%s", raw)
	}
	if strings.Contains(raw, "intermediateCas") {
		t.Error("the document names intermediateCas")
	}
	if !strings.HasSuffix(raw, "\"\n") || strings.HasSuffix(raw, "\n\n") {
		t.Error("the document does not end with its closing quote and one newline")
	}
	want := "trustStore:\n  trustAnchors:\n  - pemCertificate: \"" + strings.ReplaceAll(pemOneLine(der), "\n", `\n`) + "\"\n"
	if raw != want {
		t.Errorf("the document is\n%s\nwant\n%s", raw, want)
	}
}

// TestTrustStoreYAMLRefusesANonAnchor: a leaf's DER and garbage are refused.
func TestTrustStoreYAMLRefusesANonAnchor(t *testing.T) {
	_, anchor, anchorKey := testAnchor(t, t0)
	leaf, _ := testLeaf(t, anchor, anchorKey, t0)
	for name, der := range map[string][]byte{
		"a leaf":         leaf.Raw,
		"garbage":        []byte("not a certificate"),
		"nothing":        nil,
		"trailing bytes": append(append([]byte(nil), anchor.Raw...), 0),
		"a PEM":          encodeCert(anchor.Raw),
	} {
		if doc, err := TrustStoreYAML(der); err == nil {
			t.Errorf("TrustStoreYAML(%s) = %q", name, doc)
		}
	}
}

// TestAMultiLinePEMInADoubleQuotedScalarIsFolded: the same PEM with real
// newlines inside double quotes parses to a string pem.Decode cannot read,
// which is why the trust store writes the one-line form.
func TestAMultiLinePEMInADoubleQuotedScalarIsFolded(t *testing.T) {
	_, der := testAnchorDER(t)
	multi := strings.ReplaceAll(pemOneLine(der), "\n", "\n      ")
	doc := "trustStore:\n  trustAnchors:\n  - pemCertificate: \"" + multi + "\"\n"
	value := trustStoreValue(t, []byte(doc))
	if strings.Contains(value, "\n") {
		t.Fatalf("go-yaml kept the newlines: %q", value)
	}
	if block, _ := pem.Decode([]byte(value)); block != nil {
		t.Error("pem.Decode read the folded PEM; the one-line form would not be needed")
	}
}

// TestAttributeMappingAndCondition: the exact strings for a fixed ID; the
// condition names that one ID twice and no other.
func TestAttributeMappingAndCondition(t *testing.T) {
	id, err := ParseRoleID("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	if AttributeMapping != "google.subject=assertion.issuer.dn.cn" {
		t.Errorf("AttributeMapping = %q", AttributeMapping)
	}
	cond := AttributeCondition(id)
	want := "assertion.issuer.dn.cn == '00112233445566778899aabbccddeeff' && assertion.subject.dn.cn == '00112233445566778899aabbccddeeff'"
	if cond != want {
		t.Errorf("AttributeCondition = %q, want %q", cond, want)
	}
	runs := regexp.MustCompile(`[0-9a-f]{32}`).FindAllString(cond, -1)
	if len(runs) != 2 || runs[0] != id.Hex() || runs[1] != id.Hex() {
		t.Errorf("the condition names %v; want the one ID, twice", runs)
	}
	if AttributeCondition(RoleID{}) != "" {
		t.Error("the zero ID has a condition")
	}
}

// TestPrincipalShape: the exact string; a bad number or pool is refused, and
// the error names neither.
func TestPrincipalShape(t *testing.T) {
	id, err := ParseRoleID("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	const pool = "k3v9q2m8x1w7z5t4r6y0u2i8o3p1a9s5"
	got, err := Principal("123456789012", pool, id)
	if err != nil {
		t.Fatal(err)
	}
	want := "principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/" + pool + "/subject/00112233445566778899aabbccddeeff"
	if got != want {
		t.Errorf("Principal = %q, want %q", got, want)
	}
	for _, c := range []struct{ number, pool string }{
		{"", pool}, {"12345x", pool}, {"123456789012345678901", pool}, {"-12345", pool}, {"my-project", pool}, {"1 2", pool},
		{"98765", "abc"}, {"98765", strings.Repeat("a", 33)}, {"98765", "gcp-poolname"}, {"98765", "Pool1234"},
		{"98765", "pool_1234"}, {"98765", "pool/1234"}, {"98765", ""},
	} {
		_, err := Principal(c.number, c.pool, id)
		if err == nil {
			t.Errorf("Principal(%q, %q) succeeded", c.number, c.pool)
			continue
		}
		msg := err.Error()
		if (c.number != "" && strings.Contains(msg, c.number)) || (c.pool != "" && strings.Contains(msg, c.pool)) || containsID(msg, id) {
			t.Errorf("the error %q names its input", msg)
		}
	}
	if _, err := Principal("98765", pool, RoleID{}); err == nil {
		t.Error("a principal for the zero ID")
	}
}

// providerRow is one providers.get answer that CheckProvider refuses, and the
// field its error names.
type providerRow struct {
	name, field string
	answer      []byte
}

// providerAnswer is a providers.get answer for id and anchorDER, as the
// device made them, with name and unknown fields; mutate edits it first.
func providerAnswer(t *testing.T, id RoleID, anchorDER []byte, mutate func(m map[string]any)) []byte {
	t.Helper()
	m := map[string]any{
		"name":               "projects/123456789012/locations/global/workloadIdentityPools/poolid/providers/providerid",
		"state":              "ACTIVE",
		"disabled":           false,
		"attributeMapping":   map[string]any{"google.subject": "assertion.issuer.dn.cn"},
		"attributeCondition": AttributeCondition(id),
		"x509": map[string]any{
			"trustStore": map[string]any{
				"trustAnchors": []any{map[string]any{"pemCertificate": pemOneLine(anchorDER)}},
			},
		},
		"expireTime":   "2026-12-22T00:00:00Z",
		"somethingNew": map[string]any{"x": 1},
	}
	if mutate != nil {
		mutate(m)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// trustStoreOf is m's trust store, for a mutation.
func trustStoreOf(m map[string]any) map[string]any {
	return m["x509"].(map[string]any)["trustStore"].(map[string]any)
}

// setPEM sets m's one anchor's pemCertificate.
func setPEM(m map[string]any, s string) {
	trustStoreOf(m)["trustAnchors"] = []any{map[string]any{"pemCertificate": s}}
}

// The coordinates the fixtures name: providerAnswer's, and a list's.
const (
	testNumber   = "123456789012"
	testPool     = "poolid"
	testProvider = "providerid"
	listPool     = "poolid1234"
	listProvider = "readerprovider"
)

// escapedKey is key as a JSON string whose byte at i is written as a \u
// escape, so a key given twice is the same only once decoded. The backslash
// is rune 92, so no escape sits in this source for an editor to decode.
func escapedKey(key string, i int) string {
	return `"` + key[:i] + string(rune(92)) + fmt.Sprintf("u%04x", key[i]) + key[i+1:] + `"`
}

// TestEscapedKeyIsAnEscape: escapedKey's rows hold an escape, not the plain
// key, and decode to the key.
func TestEscapedKeyIsAnEscape(t *testing.T) {
	for _, tc := range []struct {
		key string
		i   int
	}{{"attributeCondition", 9}, {"state", 2}, {"workloadIdentityPoolProviders", 28}} {
		raw := escapedKey(tc.key, tc.i)
		var got string
		if strings.Contains(raw, tc.key) || !strings.Contains(raw, string(rune(92))+"u00") ||
			json.Unmarshal([]byte(raw), &got) != nil || got != tc.key {
			t.Errorf("escapedKey(%q, %d) = %s, decoding to %q", tc.key, tc.i, raw, got)
		}
	}
}

// mustJSON is v as JSON.
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// providerRows are the answers CheckProvider must refuse for id and
// anchorDER, each with the field it names.
func providerRows(t *testing.T, id RoleID, anchorDER []byte) []providerRow {
	t.Helper()
	other, otherDER := testAnchorDER(t)
	own, otherPEM := pemOneLine(anchorDER), pemOneLine(otherDER)
	row := func(name, field string, mutate func(m map[string]any)) providerRow {
		return providerRow{name, field, providerAnswer(t, id, anchorDER, mutate)}
	}
	// twice replaces from, which must be in the answer as made, with to: a
	// key given twice, which a reader that keeps the last value would read as
	// the answer as made.
	twice := func(name, field, from, to string) providerRow {
		answer := providerAnswer(t, id, anchorDER, nil)
		if !bytes.Contains(answer, []byte(from)) {
			t.Fatalf("%s: %q is not in the answer", name, from)
		}
		return providerRow{name, field, bytes.Replace(answer, []byte(from), []byte(to), 1)}
	}
	named := func(project, pool, provider string) func(m map[string]any) {
		return func(m map[string]any) { m["name"] = providerNameOf(project, pool, provider) }
	}
	otherCond := mustJSON(t, AttributeCondition(other))
	return []providerRow{
		twice("the condition twice, another ID's first", "the answer",
			`{"attributeCondition":`, `{"attributeCondition":`+otherCond+`,"attributeCondition":`),
		twice("the condition twice, once escaped", "the answer",
			`{"attributeCondition":`, `{`+escapedKey("attributeCondition", 9)+`:`+otherCond+`,"attributeCondition":`),
		twice("the name twice, another provider's first", "the answer",
			`{"attributeCondition":`, `{"name":`+mustJSON(t, providerNameOf(testNumber, testPool, "otherprovider"))+`,"attributeCondition":`),
		twice("the mapping's key twice", "attribute mapping",
			`"attributeMapping":{"google.subject":`, `"attributeMapping":{"google.subject":"assertion.subject.dn.cn","google.subject":`),
		twice("x509's trust store twice", "trust store", `"x509":{`, `"x509":{"trustStore":{"trustAnchors":[]},`),
		twice("the trust store's anchors twice", "trust store", `"trustStore":{`, `"trustStore":{"trustAnchors":[],`),
		twice("the anchor's PEM twice", "trust store", `{"pemCertificate":`, `{"pemCertificate":"x","pemCertificate":`),
		row("a mapping that is a string", "attribute mapping", func(m map[string]any) { m["attributeMapping"] = AttributeMapping }),
		row("a null mapping", "attribute mapping", func(m map[string]any) { m["attributeMapping"] = nil }),
		row("a null description", "description", func(m map[string]any) { m["description"] = nil }),
		row("a name under folders/", "name", func(m map[string]any) {
			m["name"] = strings.Replace(providerNameOf(testNumber, testPool, testProvider), "projects/", "folders/", 1)
		}),
		row("a name with location/ for locations/", "name", func(m map[string]any) {
			m["name"] = strings.Replace(providerNameOf(testNumber, testPool, testProvider), "/locations/", "/location/", 1)
		}),
		row("a name with workloadIdentityPool/ for workloadIdentityPools/", "name", func(m map[string]any) {
			m["name"] = strings.Replace(providerNameOf(testNumber, testPool, testProvider), "/workloadIdentityPools/", "/workloadIdentityPool/", 1)
		}),
		row("a gcp- pool", "name", named(testNumber, "gcp-pool", testProvider)),
		row("a pool in uppercase", "name", named(testNumber, "Pool1", testProvider)),
		row("a pool of 3 characters", "name", named(testNumber, "abc", testProvider)),
		row("a pool of 33 characters", "name", named(testNumber, strings.Repeat("p", 33), testProvider)),
		row("a project ID ending in a hyphen", "name", named("my-project-", testPool, testProvider)),
		row("a project ID of 31 characters", "name", named("a"+strings.Repeat("b", 30), testPool, testProvider)),
		row("a project ID of 5 characters", "name", named("abcde", testPool, testProvider)),
		row("a project ID starting with a digit", "name", named("1abcdef", testPool, testProvider)),
		row("a project ID starting with a hyphen", "name", named("-abcdef", testPool, testProvider)),
		row("a project number of 21 digits", "name", named(strings.Repeat("1", 21), testPool, testProvider)),
		row("two anchors", "trust store", func(m map[string]any) {
			trustStoreOf(m)["trustAnchors"] = []any{map[string]any{"pemCertificate": own}, map[string]any{"pemCertificate": otherPEM}}
		}),
		row("the same anchor twice", "trust store", func(m map[string]any) {
			trustStoreOf(m)["trustAnchors"] = []any{map[string]any{"pemCertificate": own}, map[string]any{"pemCertificate": own}}
		}),
		row("no anchor", "trust store", func(m map[string]any) { trustStoreOf(m)["trustAnchors"] = []any{} }),
		row("an intermediate present", "intermediate certificates", func(m map[string]any) {
			trustStoreOf(m)["intermediateCas"] = []any{map[string]any{"pemCertificate": otherPEM}}
		}),
		row("another anchor's PEM", "trust store", func(m map[string]any) { setPEM(m, otherPEM) }),
		row("a second PEM block after the first", "trust store", func(m map[string]any) { setPEM(m, own+"\n"+otherPEM) }),
		row("non-space text after the PEM", "trust store", func(m map[string]any) { setPEM(m, own+"\nx") }),
		row("text before the PEM", "trust store", func(m map[string]any) { setPEM(m, "x\n"+own) }),
		row("a PEM with a header", "trust store", func(m map[string]any) {
			setPEM(m, strings.Replace(own, "-----\n", "-----\nX-Header: y\n\n", 1))
		}),
		row("a mapping with an extra key", "attribute mapping", func(m map[string]any) {
			m["attributeMapping"] = map[string]any{"google.subject": "assertion.issuer.dn.cn", "attribute.role": "assertion.subject.dn.cn"}
		}),
		row("a mapping to the subject CN", "attribute mapping", func(m map[string]any) {
			m["attributeMapping"] = map[string]any{"google.subject": "assertion.subject.dn.cn"}
		}),
		row("no mapping", "attribute mapping", func(m map[string]any) { delete(m, "attributeMapping") }),
		row("a condition naming another ID", "attribute condition", func(m map[string]any) { m["attributeCondition"] = AttributeCondition(other) }),
		row("a condition naming two IDs", "attribute condition", func(m map[string]any) {
			m["attributeCondition"] = "(" + AttributeCondition(id) + ") || (" + AttributeCondition(other) + ")"
		}),
		row("no condition", "attribute condition", func(m map[string]any) { delete(m, "attributeCondition") }),
		row("state DELETED", "state", func(m map[string]any) { m["state"] = "DELETED" }),
		row("no state", "state", func(m map[string]any) { delete(m, "state") }),
		row("State in another case", "state", func(m map[string]any) { delete(m, "state"); m["State"] = "ACTIVE" }),
		row("disabled true", "disabled", func(m map[string]any) { m["disabled"] = true }),
		row("disabled not a bool", "disabled", func(m map[string]any) { m["disabled"] = "false" }),
		row("no x509", "trust store", func(m map[string]any) { delete(m, "x509") }),
		row("no trust store", "trust store", func(m map[string]any) { m["x509"] = map[string]any{} }),
		row("a display name", "display name", func(m map[string]any) { m["displayName"] = "FarCast reader" }),
		row("an empty display name", "display name", func(m map[string]any) { m["displayName"] = "" }),
		row("a null display name", "display name", func(m map[string]any) { m["displayName"] = nil }),
		row("a description", "description", func(m map[string]any) { m["description"] = "instance one" }),
		row("an empty description", "description", func(m map[string]any) { m["description"] = "" }),
		row("no name", "name", func(m map[string]any) { delete(m, "name") }),
		row("a null name", "name", func(m map[string]any) { m["name"] = nil }),
		row("a name that is not a string", "name", func(m map[string]any) { m["name"] = 7 }),
		row("a name ending in /providers/", "name", func(m map[string]any) { m["name"] = providerNameOf("123456789012", "poolid", "") }),
		row("a name ending in a slash", "name", func(m map[string]any) { m["name"] = providerNameOf("123456789012", "poolid", "providerid") + "/" }),
		row("a name with an uppercase provider ID", "name", func(m map[string]any) { m["name"] = providerNameOf("123456789012", "poolid", "ProviderID") }),
		row("a name with a gcp- provider ID", "name", func(m map[string]any) { m["name"] = providerNameOf("123456789012", "poolid", "gcp-provider") }),
		row("a name with a 33-character provider ID", "name", func(m map[string]any) {
			m["name"] = providerNameOf("123456789012", "poolid", strings.Repeat("p", 33))
		}),
		row("a name in another location", "name", func(m map[string]any) {
			m["name"] = strings.Replace(providerNameOf("123456789012", "poolid", "providerid"), "/global/", "/us/", 1)
		}),
		row("a name with a part before it", "name", func(m map[string]any) { m["name"] = "x/" + providerNameOf("123456789012", "poolid", "providerid") }),
		row("a name of the provider ID alone", "name", func(m map[string]any) { m["name"] = "providerid" }),
		row("a name of an OIDC-style pool path", "name", func(m map[string]any) {
			m["name"] = "projects/123456789012/locations/global/workloadIdentityPools/poolid/subject/providerid"
		}),
		row("a name with a bad project", "name", func(m map[string]any) { m["name"] = providerNameOf("My_Project", "poolid", "providerid") }),
		{"not JSON", "the answer", []byte("not json")},
		{"a JSON array", "the answer", []byte("[]")},
		{"JSON null", "the answer", []byte("null")},
	}
}

// TestCheckProviderAcceptsWhatTheDeviceMade: the answer built from the
// anchor's trust store, the mapping and the condition passes, with name and
// unknown fields, and with any whitespace around the PEM.
func TestCheckProviderAcceptsWhatTheDeviceMade(t *testing.T) {
	id, der := testAnchorDER(t)
	doc, err := TrustStoreYAML(der)
	if err != nil {
		t.Fatal(err)
	}
	stored := trustStoreValue(t, doc)
	for name, mutate := range map[string]func(m map[string]any){
		"as made":            func(m map[string]any) { setPEM(m, stored) },
		"ending \\n":         func(m map[string]any) { setPEM(m, stored+"\n") },
		"ending \\n\\n":      func(m map[string]any) { setPEM(m, stored+"\n\n") },
		"ending \\r\\n":      func(m map[string]any) { setPEM(m, stored+"\r\n") },
		"leading spaces":     func(m map[string]any) { setPEM(m, "  "+stored) },
		"disabled absent":    func(m map[string]any) { setPEM(m, stored); delete(m, "disabled") },
		"no intermediates":   func(m map[string]any) { setPEM(m, stored); trustStoreOf(m)["intermediateCas"] = []any{} },
		"null intermediates": func(m map[string]any) { setPEM(m, stored); trustStoreOf(m)["intermediateCas"] = nil },
		"unknown in x509":    func(m map[string]any) { setPEM(m, stored); m["x509"].(map[string]any)["future"] = true },
		"unknown in an entry": func(m map[string]any) {
			trustStoreOf(m)["trustAnchors"] = []any{map[string]any{"pemCertificate": stored, "x": 1}}
		},
		"a project ID in the name": func(m map[string]any) {
			setPEM(m, stored)
			m["name"] = providerNameOf("my-project-1", "poolid", "providerid")
		},
		"a project ID of 6 characters": func(m map[string]any) {
			setPEM(m, stored)
			m["name"] = providerNameOf("abcdef", "poolid", "providerid")
		},
		"a project ID of 30 characters": func(m map[string]any) {
			setPEM(m, stored)
			m["name"] = providerNameOf("a"+strings.Repeat("b", 28)+"1", "poolid", "providerid")
		},
		"a project number of 20 digits": func(m map[string]any) {
			setPEM(m, stored)
			m["name"] = providerNameOf(strings.Repeat("9", 20), "poolid", "providerid")
		},
		"a pool of 4 and a provider of 32 characters": func(m map[string]any) {
			setPEM(m, stored)
			m["name"] = providerNameOf(testNumber, "abcd", strings.Repeat("p", 32))
		},
		"a pool of 32 with a hyphen": func(m map[string]any) {
			setPEM(m, stored)
			m["name"] = providerNameOf(testNumber, "pool-"+strings.Repeat("q", 27), "providerid")
		},
	} {
		if err := CheckProvider(providerAnswer(t, id, der, mutate), der, id); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestCheckProviderNamesTheFieldThatDiffers: each refused answer's error
// names its field, and neither ID nor any PEM line.
func TestCheckProviderNamesTheFieldThatDiffers(t *testing.T) {
	id, der := testAnchorDER(t)
	for _, row := range providerRows(t, id, der) {
		err := CheckProvider(row.answer, der, id)
		if err == nil {
			t.Errorf("%s: accepted", row.name)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, "provider's "+row.field+" is") {
			t.Errorf("%s: the error %q does not name %q", row.name, msg, row.field)
		}
		if containsID(msg, id) || strings.Contains(msg, "-----") {
			t.Errorf("%s: the error %q names the ID or a PEM line", row.name, msg)
		}
		var answer map[string]any
		if json.Unmarshal(row.answer, &answer) == nil {
			for _, line := range strings.Split(string(row.answer), `\n`) {
				if len(line) >= 16 && strings.Contains(msg, line) {
					t.Errorf("%s: the error carries a line of the answer", row.name)
				}
			}
		}
	}
	if err := CheckProvider(providerAnswer(t, id, der, nil), der, RoleID{}); err == nil {
		t.Error("a check against the zero ID passed")
	}
	if err := CheckProvider(providerAnswer(t, id, der, nil), nil, id); err == nil {
		t.Error("a check against no anchor passed")
	}
}

// providerNameOf is a provider's resource name.
func providerNameOf(project, pool, provider string) string {
	return "projects/" + project + "/locations/global/workloadIdentityPools/" + pool + "/providers/" + provider
}

// TestCheckNamedProvider: the answer for the provider the device made, in the
// instance's pool, passes; one whose name is another provider's, in this
// pool or another, or in another project, or names the project by its ID, or
// merely ends in this one's characters, is refused as "name"; arguments not
// in shape read nothing and are not quoted; and every answer CheckProvider
// refuses is refused for the same field.
func TestCheckNamedProvider(t *testing.T) {
	id, der := testAnchorDER(t)
	doc, err := TrustStoreYAML(der)
	if err != nil {
		t.Fatal(err)
	}
	stored := trustStoreValue(t, doc)
	as := func(name string) []byte {
		return providerAnswer(t, id, der, func(m map[string]any) {
			setPEM(m, stored)
			m["name"] = name
		})
	}
	const own = "k3v9q2m8x1w7z5t4r6y0u2i8o3p1a9s5"
	ownAnswer := as(providerNameOf(testNumber, testPool, own))
	if err := CheckNamedProvider(ownAnswer, testNumber, testPool, own, der, id); err != nil {
		t.Errorf("the device's own provider: %v", err)
	}
	for name, answer := range map[string][]byte{
		"another provider":                     as(providerNameOf(testNumber, testPool, "otherprovider")),
		"a provider whose ID ends in this one": as(providerNameOf(testNumber, testPool, "x"+own[1:])),
		"a provider whose ID starts with this": as(providerNameOf(testNumber, testPool, own[:31])),
		"this ID as the pool":                  as(providerNameOf(testNumber, own, "otherprovider")),
		"this provider in another pool":        as(providerNameOf(testNumber, "otherpool", own)),
		"this provider in another project":     as(providerNameOf("987654321098", testPool, own)),
		"the project named by its ID":          as(providerNameOf("my-project-1", testPool, own)),
	} {
		err := CheckNamedProvider(answer, testNumber, testPool, own, der, id)
		if err == nil || !strings.Contains(err.Error(), "provider's name is") {
			t.Errorf("%s: err = %v, want the name refused", name, err)
			continue
		}
		if strings.Contains(err.Error(), own) || strings.Contains(err.Error(), "otherprovider") || strings.Contains(err.Error(), "pool") {
			t.Errorf("%s: the error %q names a provider or a pool", name, err)
		}
	}
	for _, args := range [][3]string{
		{"", testPool, own}, {"12345x", testPool, own}, {strings.Repeat("1", 21), testPool, own},
		{testNumber, "", own}, {testNumber, "gcp-pool", own}, {testNumber, "Pool1", own}, {testNumber, "abc", own},
		{testNumber, testPool, ""}, {testNumber, testPool, "abc"}, {testNumber, testPool, "gcp-provider"},
		{testNumber, testPool, "Provider1"}, {testNumber, testPool, "prov_ider"}, {testNumber, testPool, "prov/ider"},
		{testNumber, testPool, strings.Repeat("a", 33)}, {testNumber, testPool, own + "\n"},
	} {
		err := CheckNamedProvider(ownAnswer, args[0], args[1], args[2], der, id)
		if err == nil {
			t.Errorf("CheckNamedProvider with %q passed", args)
			continue
		}
		// Refused for the argument, before the answer is read: an answer
		// refused as "name" would also refuse, having read it.
		if !strings.Contains(err.Error(), " is named with ") {
			t.Errorf("CheckNamedProvider with %q: err = %v, want the argument refused before the answer is read", args, err)
		}
		for _, a := range args {
			if a != "" && strings.Contains(err.Error(), a) {
				t.Errorf("the error %q quotes an argument", err)
			}
		}
	}
	for _, row := range providerRows(t, id, der) {
		err := CheckNamedProvider(row.answer, testNumber, testPool, testProvider, der, id)
		if err == nil || !strings.Contains(err.Error(), "provider's "+row.field+" is") {
			t.Errorf("%s: err = %v, want %q named", row.name, err, row.field)
		}
	}
}

// hostileConditions are conditions near D3's shape for id, each of which
// RoleIDFromCondition must refuse: other is a second role ID.
func hostileConditions(id, other RoleID) []string {
	h, o := id.Hex(), other.Hex()
	cond := AttributeCondition(id)
	return []string{
		"",
		cond + " ",
		" " + cond,
		cond + "\n",
		"\t" + cond,
		cond + "\x00",
		strings.Replace(cond, " == ", "==", 1),
		strings.Replace(cond, " && ", "  &&  ", 1),
		strings.ReplaceAll(cond, " ", "\t"),
		strings.ToUpper(cond),
		// Case changed only after the first ID, which still parses.
		conditionIssuer + h + strings.ToUpper(conditionSubject) + h + conditionEnd,
		strings.Replace(cond, "assertion.subject.dn.cn", "assertion.subject.dn.CN", 1),
		strings.Replace(cond, "assertion.subject", "Assertion.subject", 1),
		// Two IDs, in either place.
		conditionIssuer + h + conditionSubject + o + conditionEnd,
		conditionIssuer + o + conditionSubject + h + conditionEnd,
		// A clause removed, swapped or added.
		conditionIssuer + h + conditionEnd,
		"assertion.subject.dn.cn == '" + h + "'",
		"assertion.subject.dn.cn == '" + h + "' && assertion.issuer.dn.cn == '" + h + "'",
		cond + " && true",
		cond + " || true",
		"true || " + cond,
		"(" + cond + ")",
		cond + " || (" + AttributeCondition(other) + ")",
		"(" + cond + ") || (" + AttributeCondition(other) + ")",
		cond + " // " + o,
		// Other attributes.
		strings.Replace(cond, "assertion.subject.dn.cn", "assertion.subject.dn.o", 1),
		strings.Replace(cond, "assertion.issuer.dn.cn", "assertion.issuer.dn.ou", 1),
		conditionIssuer + h + "' && attribute.role == '" + h + conditionEnd,
		strings.Replace(cond, "assertion.", "attribute.", 2),
		// Quoting tricks.
		strings.ReplaceAll(cond, "'", `"`),
		strings.ReplaceAll(cond, "'", "’"),
		conditionIssuer + h + `\'` + conditionSubject + h + conditionEnd,
		conditionIssuer + h + "' + '" + conditionSubject + h + conditionEnd,
		conditionIssuer + h + conditionSubject + h + "' || '" + o + conditionEnd,
		conditionIssuer + h + conditionSubject + h + "'' ",
		conditionIssuer + h + "'' && assertion.subject.dn.cn == '" + h + conditionEnd,
		// IDs of the wrong length or alphabet.
		conditionIssuer + h[:31] + conditionSubject + h[:31] + conditionEnd,
		conditionIssuer + h + "0" + conditionSubject + h + "0" + conditionEnd,
		conditionIssuer + "0x" + h[2:] + conditionSubject + "0x" + h[2:] + conditionEnd,
		conditionIssuer + strings.Repeat("g", 32) + conditionSubject + strings.Repeat("g", 32) + conditionEnd,
		conditionIssuer,
		conditionIssuer + h,
	}
}

// TestRoleIDFromConditionAcceptsOnlyD3sShape: AttributeCondition's output
// gives its ID back, for many IDs; every hostile condition is refused with
// the one error, which quotes nothing.
func TestRoleIDFromConditionAcceptsOnlyD3sShape(t *testing.T) {
	fixed, err := ParseRoleID("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	got, err := RoleIDFromCondition("assertion.issuer.dn.cn == '00112233445566778899aabbccddeeff' && assertion.subject.dn.cn == '00112233445566778899aabbccddeeff'")
	if err != nil || !got.Equal(fixed) {
		t.Fatalf("RoleIDFromCondition of the fixed condition = %v, %v", got, err)
	}
	for range 200 {
		id, err := NewRoleID(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		got, err := RoleIDFromCondition(AttributeCondition(id))
		if err != nil || !got.Equal(id) {
			t.Fatalf("RoleIDFromCondition(AttributeCondition(id)) = %v, %v; want id", got, err)
		}
	}
	other, err := NewRoleID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The fixed ID has letters, so its hex in upper case is another string.
	upper := strings.ReplaceAll(AttributeCondition(fixed), fixed.Hex(), strings.ToUpper(fixed.Hex()))
	// The second place's ID alone in upper case: the first still parses.
	upperSecond := conditionIssuer + fixed.Hex() + conditionSubject + strings.ToUpper(fixed.Hex()) + conditionEnd
	for i, cond := range append(hostileConditions(fixed, other), upper, upperSecond) {
		got, err := RoleIDFromCondition(cond)
		if err == nil {
			t.Errorf("condition %d (%q) gave a role ID", i, cond)
			continue
		}
		if !got.IsZero() {
			t.Errorf("condition %d: a refusal with a role ID", i)
		}
		if err != errConditionShape {
			t.Errorf("condition %d: err = %v, want the one shape error", i, err)
		}
		if containsID(err.Error(), fixed) || containsID(err.Error(), other) {
			t.Errorf("condition %d: the error %q names an ID", i, err)
		}
	}
}

// listEntry is one provider, a list's entry or a get's whole answer, as
// Google would give it: a name, D3's mapping, a state, a condition, and
// fields the parsers ignore.
func listEntry(project, pool, provider, state, condition string) map[string]any {
	e := map[string]any{
		"name":             providerNameOf(project, pool, provider),
		"attributeMapping": map[string]any{"google.subject": "assertion.issuer.dn.cn"},
		"x509": map[string]any{"trustStore": map[string]any{
			"trustAnchors": []any{map[string]any{"pemCertificate": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}},
		}},
	}
	if state != "" {
		e["state"] = state
	}
	if condition != "" {
		e["attributeCondition"] = condition
	}
	return e
}

// providersList is a providers list answer of entries, and token when it is
// not nil.
func providersList(t *testing.T, token any, entries ...map[string]any) []byte {
	t.Helper()
	m := map[string]any{}
	if len(entries) > 0 {
		list := make([]any, len(entries))
		for i, e := range entries {
			list[i] = e
		}
		m["workloadIdentityPoolProviders"] = list
	}
	if token != nil {
		m["nextPageToken"] = token
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newRoleIDs draws n role IDs.
func newRoleIDs(t *testing.T, n int) []RoleID {
	t.Helper()
	ids := make([]RoleID, n)
	for i := range ids {
		var err error
		if ids[i], err = NewRoleID(rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	return ids
}

// TestParseProvidersReadsAPage: each entry in order with its ID, state,
// disabled and role ID; a DELETED provider with its state; a provider whose
// condition or mapping is not D3's, two IDs included, listed with no role ID;
// a copy of another provider's mapping and condition listed with that role
// ID; and the next page's token, "" on the last page.
func TestParseProvidersReadsAPage(t *testing.T) {
	ids := newRoleIDs(t, 6)
	twoIDs := "(" + AttributeCondition(ids[0]) + ") || (" + AttributeCondition(ids[3]) + ")"
	entry := func(provider, state string, id RoleID) map[string]any {
		return listEntry(testNumber, listPool, provider, state, AttributeCondition(id))
	}
	reader := entry("readerprovider", "ACTIVE", ids[0])
	writer := entry("writerprovider", "ACTIVE", ids[1])
	writer["disabled"] = true
	writer["displayName"] = "ignored"
	deleted := entry("deletedprovider", "DELETED", ids[2])
	deleted["expireTime"] = "2026-12-26T00:00:00Z"
	rogue := listEntry(testNumber, listPool, "rogue-provider", "ACTIVE", twoIDs)
	bare := listEntry(testNumber, listPool, "bareprovider", "", "")
	nulls := listEntry(testNumber, listPool, "nullprovider", "", "")
	nulls["state"], nulls["disabled"], nulls["attributeCondition"] = nil, nil, nil
	copied := entry("copiedprovider", "ACTIVE", ids[0])
	literal := entry("literalmapping", "ACTIVE", ids[3])
	literal["attributeMapping"] = map[string]any{"google.subject": "'" + ids[4].Hex() + "'"}
	unmapped := entry("unmapped", "ACTIVE", ids[3])
	delete(unmapped, "attributeMapping")
	nullMapping := entry("nullmapping", "ACTIVE", ids[3])
	nullMapping["attributeMapping"] = nil
	extraKey := entry("extrakey", "ACTIVE", ids[3])
	extraKey["attributeMapping"] = map[string]any{"google.subject": "assertion.issuer.dn.cn", "attribute.role": "assertion.subject.dn.cn"}
	subjectCN := entry("subjectcn", "ACTIVE", ids[3])
	subjectCN["attributeMapping"] = map[string]any{"google.subject": "assertion.subject.dn.cn"}
	emptyMapping := entry("emptymapping", "ACTIVE", ids[3])
	emptyMapping["attributeMapping"] = map[string]any{}
	longState := entry("longstate", strings.Repeat("A", 31)+"_", ids[5])

	page1 := providersList(t, "CiQ0-Zz_9+/=.~a", reader, writer, deleted)
	page2 := providersList(t, nil, rogue, bare, nulls, copied, literal, unmapped, nullMapping, extraKey, subjectCN, emptyMapping, longState)
	got1, token1, err := ParseProviders(page1, testNumber, listPool)
	if err != nil {
		t.Fatal(err)
	}
	if token1 != "CiQ0-Zz_9+/=.~a" {
		t.Errorf("the first page's token = %q", token1)
	}
	got2, token2, err := ParseProviders(page2, testNumber, listPool)
	if err != nil {
		t.Fatal(err)
	}
	if token2 != "" {
		t.Errorf("the last page's token = %q, want none", token2)
	}
	all := append(got1, got2...)
	want := []struct {
		id, state string
		disabled  bool
		role      RoleID
	}{
		{"readerprovider", ProviderActive, false, ids[0]},
		{"writerprovider", ProviderActive, true, ids[1]},
		{"deletedprovider", ProviderDeleted, false, ids[2]},
		{"rogue-provider", ProviderActive, false, RoleID{}},
		{"bareprovider", ProviderStateUnspecified, false, RoleID{}},
		{"nullprovider", ProviderStateUnspecified, false, RoleID{}},
		{"copiedprovider", ProviderActive, false, ids[0]},
		{"literalmapping", ProviderActive, false, RoleID{}},
		{"unmapped", ProviderActive, false, RoleID{}},
		{"nullmapping", ProviderActive, false, RoleID{}},
		{"extrakey", ProviderActive, false, RoleID{}},
		{"subjectcn", ProviderActive, false, RoleID{}},
		{"emptymapping", ProviderActive, false, RoleID{}},
		{"longstate", strings.Repeat("A", 31) + "_", false, ids[5]},
	}
	if len(all) != len(want) {
		t.Fatalf("read %d providers, want %d", len(all), len(want))
	}
	for i, w := range want {
		p := all[i]
		if p.ID != w.id || p.State != w.state || p.Disabled != w.disabled || !p.RoleID.Equal(w.role) {
			t.Errorf("provider %d = {%s %s %v zero-role:%v}, want {%s %s %v zero-role:%v}",
				i, p.ID, p.State, p.Disabled, p.RoleID.IsZero(), w.id, w.state, w.disabled, w.role.IsZero())
		}
	}
	if _, err := RoleIDFromCondition(twoIDs); err == nil {
		t.Error("RoleIDFromCondition read a role ID from a two-ID condition")
	}
	// A listed provider prints its ID and state, never its role ID.
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(verb, all[0])
		if containsID(out, ids[0]) || !strings.Contains(out, "readerprovider") {
			t.Errorf("%s of a ListedProvider = %q", verb, out)
		}
	}

	for name, tc := range map[string]struct {
		list  []byte
		n     int
		token string
	}{
		"an empty answer":   {[]byte("{}"), 0, ""},
		"a token alone":     {providersList(t, "next"), 0, "next"},
		"a null token":      {[]byte(`{"nextPageToken":null}`), 0, ""},
		"an empty token":    {[]byte(`{"nextPageToken":""}`), 0, ""},
		"null providers":    {[]byte(`{"workloadIdentityPoolProviders":null}`), 0, ""},
		"no providers":      {[]byte(`{"workloadIdentityPoolProviders":[]}`), 0, ""},
		"whitespace around": {[]byte(" \n{\"nextPageToken\":\"t\"}\n "), 0, "t"},
	} {
		got, token, err := ParseProviders(tc.list, testNumber, listPool)
		if err != nil || len(got) != tc.n || token != tc.token {
			t.Errorf("%s: %d providers, token %q, %v; want %d, %q", name, len(got), token, err, tc.n, tc.token)
		}
	}
}

// TestParseProvidersReadNoRoleIDFromAnotherCondition: under D3's mapping,
// every condition RoleIDFromCondition refuses, those that begin with D3's
// exact text and go on included, gives its provider no role ID, in a list and
// in a get; D3's own condition gives its ID in both.
func TestParseProvidersReadNoRoleIDFromAnotherCondition(t *testing.T) {
	ids := newRoleIDs(t, 2)
	id, other := ids[0], ids[1]
	cond := AttributeCondition(id)
	conds := append(hostileConditions(id, other),
		cond+" || "+AttributeCondition(other),
		cond+" && true",
		cond+" ",
		cond+AttributeCondition(other),
		cond+cond,
	)
	read := func(e map[string]any) (fromList, fromGet ListedProvider, err error) {
		got, _, err := ParseProviders(providersList(t, nil, e), testNumber, listPool)
		if err != nil {
			return ListedProvider{}, ListedProvider{}, err
		}
		if len(got) != 1 {
			return ListedProvider{}, ListedProvider{}, fmt.Errorf("listed %d providers", len(got))
		}
		p, err := ParseProvider([]byte(mustJSON(t, e)), testNumber, listPool, listProvider)
		return got[0], p, err
	}
	for i, c := range conds {
		fromList, fromGet, err := read(listEntry(testNumber, listPool, listProvider, "ACTIVE", c))
		if err != nil {
			t.Errorf("condition %d: %v", i, err)
			continue
		}
		if !fromList.RoleID.IsZero() || !fromGet.RoleID.IsZero() {
			t.Errorf("condition %d (%q) read with a role ID", i, c)
		}
	}
	fromList, fromGet, err := read(listEntry(testNumber, listPool, listProvider, "ACTIVE", cond))
	if err != nil || !fromList.RoleID.Equal(id) || !fromGet.RoleID.Equal(id) {
		t.Errorf("D3's own condition: %v; a role ID in the list %v, in the get %v", err, !fromList.RoleID.IsZero(), !fromGet.RoleID.IsZero())
	}
}

// TestParseProvidersBoundsItsInput: an answer of MaxProvidersList bytes is
// read, and one byte more is refused before it is parsed. The bound is
// written out, so a changed constant fails here.
func TestParseProvidersBoundsItsInput(t *testing.T) {
	const limit = 1 << 20
	if MaxProvidersList != limit {
		t.Fatalf("MaxProvidersList = %d, want %d", MaxProvidersList, limit)
	}
	id, err := NewRoleID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := listEntry(testNumber, listPool, listProvider, "ACTIVE", AttributeCondition(id))
	pad := func(b []byte, n int) []byte { return append(bytes.Clone(b), bytes.Repeat([]byte(" "), n-len(b))...) }
	list, get := providersList(t, nil, e), []byte(mustJSON(t, e))
	if got, _, err := ParseProviders(pad(list, limit), testNumber, listPool); err != nil || len(got) != 1 {
		t.Errorf("a %d-byte list: %d providers, %v", limit, len(got), err)
	}
	if _, err := ParseProvider(pad(get, limit), testNumber, listPool, listProvider); err != nil {
		t.Errorf("a %d-byte provider: %v", limit, err)
	}
	_, _, err = ParseProviders(pad(list, limit+1), testNumber, listPool)
	if err == nil || !strings.Contains(err.Error(), "more than 1048576 bytes") {
		t.Errorf("a %d-byte list: err = %v, want the size refusal", limit+1, err)
	}
	_, err = ParseProvider(pad(get, limit+1), testNumber, listPool, listProvider)
	if err == nil || !strings.Contains(err.Error(), "more than 1048576 bytes") {
		t.Errorf("a %d-byte provider: err = %v, want the size refusal", limit+1, err)
	}
	// Refused by its size alone: the same oversized bytes are not JSON at all.
	if _, _, err := ParseProviders(bytes.Repeat([]byte("{"), limit+1), testNumber, listPool); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("an oversized non-JSON list: err = %v, want the size refusal", err)
	}
	if _, err := ParseProvider(bytes.Repeat([]byte("{"), limit+1), testNumber, listPool, listProvider); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("an oversized non-JSON provider: err = %v, want the size refusal", err)
	}
}

// listRow is one answer ParseProviders or ParseProvider refuses.
type listRow struct {
	name string
	list []byte
}

// entryRows are single providers, each as a list's entry or as a get's whole
// answer, that ParseProviders and ParseProvider must refuse for the provider
// (testNumber, listPool, listProvider). Each carries id in a condition, so an
// error that quoted the answer would carry it.
func entryRows(t *testing.T, id RoleID) []listRow {
	t.Helper()
	cond := AttributeCondition(id)
	with := func(f func(e map[string]any)) []byte {
		e := listEntry(testNumber, listPool, listProvider, "ACTIVE", cond)
		f(e)
		return []byte(mustJSON(t, e))
	}
	named := func(project, pool, provider string) func(e map[string]any) {
		return func(e map[string]any) { e["name"] = providerNameOf(project, pool, provider) }
	}
	condJSON := mustJSON(t, cond)
	name := `"name":` + mustJSON(t, providerNameOf(testNumber, listPool, listProvider))
	mapping := `"attributeMapping":{"google.subject":"assertion.issuer.dn.cn"}`
	return []listRow{
		{"an entry a number", []byte(`1`)},
		{"an entry null", []byte(`null`)},
		{"an entry a string", []byte(condJSON)},
		{"an entry an array", []byte(`[` + condJSON + `]`)},
		{"an entry with text after it", []byte(`{` + name + `} x`)},
		{"an entry's condition twice", []byte(`{` + name + `,` + mapping + `,"attributeCondition":` + condJSON + `,"attributeCondition":"true"}`)},
		{"an entry's condition twice, once escaped", []byte(`{` + name + `,` + mapping + `,"attributeCondition":"true",` + escapedKey("attributeCondition", 9) + `:` + condJSON + `}`)},
		{"an entry's name twice", []byte(`{` + name + `,` + name + `,"attributeCondition":` + condJSON + `}`)},
		{"an entry's state twice", []byte(`{` + name + `,"state":"ACTIVE","state":"DELETED"}`)},
		{"an entry's state twice, once escaped", []byte(`{` + name + `,"state":"ACTIVE",` + escapedKey("state", 2) + `:"DELETED"}`)},
		{"an entry's mapping key twice", []byte(`{` + name + `,"attributeMapping":{"google.subject":"'x'","google.subject":"assertion.issuer.dn.cn"},"attributeCondition":` + condJSON + `}`)},
		{"no name", with(func(e map[string]any) { delete(e, "name") })},
		{"a null name", with(func(e map[string]any) { e["name"] = nil })},
		{"a name in another case", with(func(e map[string]any) { e["Name"] = e["name"]; delete(e, "name") })},
		{"a name that is a number", with(func(e map[string]any) { e["name"] = 12 })},
		{"a name of the ID alone", with(func(e map[string]any) { e["name"] = listProvider })},
		{"a name with an escape sequence", with(named(testNumber, listPool, "reader\x1b[2Jprovider"))},
		{"a name with the ID in the subject's place", with(named(testNumber, listPool, id.Hex()+"x"))},
		{"a name in another pool", with(named(testNumber, "otherpool1", listProvider))},
		{"a name in another project", with(named("987654321098", listPool, listProvider))},
		{"a name with the project's ID", with(named("my-project-1", listPool, listProvider))},
		{"a state in lowercase", with(func(e map[string]any) { e["state"] = "active" })},
		{"a state with an escape sequence", with(func(e map[string]any) { e["state"] = "ACTIVE\x1b[31m" })},
		{"a state of 33 characters", with(func(e map[string]any) { e["state"] = strings.Repeat("A", 33) })},
		{"an empty state", with(func(e map[string]any) { e["state"] = "" })},
		{"a state that is a number", with(func(e map[string]any) { e["state"] = 1 })},
		{"disabled a string", with(func(e map[string]any) { e["disabled"] = "true" })},
		{"disabled a number", with(func(e map[string]any) { e["disabled"] = 0 })},
		{"a condition that is a number", with(func(e map[string]any) { e["attributeCondition"] = 1 })},
		{"a condition that is an object", with(func(e map[string]any) { e["attributeCondition"] = map[string]any{"c": cond} })},
		{"a mapping that is a string", with(func(e map[string]any) { e["attributeMapping"] = AttributeMapping })},
		{"a mapping that is an array", with(func(e map[string]any) { e["attributeMapping"] = []any{"google.subject"} })},
		{"a mapping with a number", with(func(e map[string]any) { e["attributeMapping"] = map[string]any{"google.subject": 1} })},
		{"a mapping with a null", with(func(e map[string]any) { e["attributeMapping"] = map[string]any{"google.subject": nil} })},
	}
}

// providerListRows are answers ParseProviders must refuse for the instance's
// pool (testNumber, listPool): the lists' own, and each of entryRows as a
// one-entry list. Each carries id in a condition. Each refused for what its
// providers hold carries a next page token beside them, so a refusal that
// handed the token back would be seen.
func providerListRows(t *testing.T, id RoleID) []listRow {
	t.Helper()
	cond := AttributeCondition(id)
	ok := func() map[string]any {
		return listEntry(testNumber, listPool, listProvider, "ACTIVE", cond)
	}
	condJSON := mustJSON(t, cond)
	name := `"name":` + mustJSON(t, providerNameOf(testNumber, listPool, listProvider))
	rows := []listRow{
		{"not JSON", []byte("not json " + cond)},
		{"a JSON array", []byte("[" + condJSON + "]")},
		{"JSON null", []byte("null")},
		{"a JSON string", []byte(condJSON)},
		{"two objects", append(providersList(t, nil, ok()), []byte("{}")...)},
		{"text after the object", append(providersList(t, nil, ok()), []byte(" x")...)},
		{"a trailing comma", []byte(`{"workloadIdentityPoolProviders":[],}`)},
		{"a key with no value", []byte(`{"nextPageToken"}`)},
		{"an unterminated object", []byte(`{"nextPageToken":"a"`)},
		{"the top-level key twice", []byte(`{"workloadIdentityPoolProviders":[],"workloadIdentityPoolProviders":[{` + name + `}]}`)},
		{"the top-level key twice, once escaped", []byte(`{"workloadIdentityPoolProviders":[],` + escapedKey("workloadIdentityPoolProviders", 28) + `:[{` + name + `}]}`)},
		{"the token twice", []byte(`{"nextPageToken":"a","nextPageToken":"b"}`)},
		{"the providers an object", []byte(`{"workloadIdentityPoolProviders":{` + name + `},"nextPageToken":"next"}`)},
		{"the providers' key in another case", []byte(`{"WorkloadIdentityPoolProviders":[{` + name + `}]}`)},
		{"the providers' key in lowercase", []byte(`{"workloadidentitypoolproviders":[]}`)},
		{"the token's key in another case", []byte(`{"NextPageToken":"next"}`)},
		{"an error's body", []byte(`{"error":{"code":403,"message":"denied","status":"PERMISSION_DENIED"}}`)},
		{"an error beside an empty page", []byte(`{"workloadIdentityPoolProviders":[],"error":{"code":403}}`)},
		{"an unreachable list", []byte(`{"unreachable":["x"]}`)},
		{"two pools", providersList(t, "next", ok(), listEntry(testNumber, "otherpool1", "writerprovider", "ACTIVE", cond))},
		{"two projects", providersList(t, "next", ok(), listEntry("987654321098", listPool, "writerprovider", "ACTIVE", cond))},
		{"an ID twice", providersList(t, "next", ok(), listEntry(testNumber, listPool, listProvider, "DELETED", cond))},
		{"a token with a space", providersList(t, "a b", ok())},
		{"a token with a newline", providersList(t, "a\nb", ok())},
		{"a token with a control character", providersList(t, "a\x00b", ok())},
		{"a token with a quote", providersList(t, `a"b`, ok())},
		{"a token with an ampersand", providersList(t, "a&pageSize=1000", ok())},
		{"a token of 4097 characters", providersList(t, strings.Repeat("a", 4097), ok())},
		{"a token that is a number", providersList(t, 5, ok())},
		{"a token that is the condition", providersList(t, cond, ok())},
	}
	for _, e := range entryRows(t, id) {
		rows = append(rows, listRow{"a list of " + e.name, []byte(`{"workloadIdentityPoolProviders":[` + string(e.list) + `],"nextPageToken":"next"}`)})
	}
	return rows
}

// providerGetRows are answers ParseProvider must refuse for the provider
// (testNumber, listPool, listProvider): each of entryRows, and a get's own.
// Each carries id in a condition.
func providerGetRows(t *testing.T, id RoleID) []listRow {
	t.Helper()
	cond := AttributeCondition(id)
	own := mustJSON(t, listEntry(testNumber, listPool, listProvider, "ACTIVE", cond))
	return append(entryRows(t, id),
		listRow{"not JSON", []byte("not json " + cond)},
		listRow{"an empty answer", []byte(`{}`)},
		listRow{"two objects", []byte(own + `{}`)},
		listRow{"another provider of the pool", []byte(mustJSON(t, listEntry(testNumber, listPool, "otherprovider", "ACTIVE", cond)))},
		listRow{"a list in place of a provider", providersList(t, nil, listEntry(testNumber, listPool, listProvider, "ACTIVE", cond))},
	)
}

// quotesTheAnswer names what of an answer an error carries, or "".
func quotesTheAnswer(msg string, id RoleID) string {
	switch {
	case containsID(msg, id):
		return "the role ID"
	case strings.ContainsAny(msg, "\x1b\x00\n\"&"):
		return "a control character, a quote or an ampersand"
	case strings.Contains(msg, listProvider), strings.Contains(msg, "otherprovider"):
		return "a provider ID"
	case strings.Contains(msg, listPool), strings.Contains(msg, "otherpool"):
		return "a pool ID"
	case strings.Contains(msg, testNumber), strings.Contains(msg, "assertion"):
		return "a number or the condition"
	}
	return ""
}

// TestParseProvidersRefusesWhatGoogleWouldNotSend: each row is refused whole,
// with an error that quotes nothing of the answer; and a pool out of shape
// reads nothing.
func TestParseProvidersRefusesWhatGoogleWouldNotSend(t *testing.T) {
	id, err := NewRoleID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range providerListRows(t, id) {
		got, token, err := ParseProviders(row.list, testNumber, listPool)
		if err == nil {
			t.Errorf("%s: read %d providers, token %q", row.name, len(got), token)
			continue
		}
		if got != nil || token != "" {
			t.Errorf("%s: a refusal with providers or a token", row.name)
		}
		if what := quotesTheAnswer(err.Error(), id); what != "" {
			t.Errorf("%s: the error %q quotes %s", row.name, err, what)
		}
	}
	// The token at its bound is read.
	if _, token, err := ParseProviders(providersList(t, strings.Repeat("a", 4096)), testNumber, listPool); err != nil || len(token) != 4096 {
		t.Errorf("a 4096-character token: %d characters, %v", len(token), err)
	}
	good := providersList(t, nil, listEntry(testNumber, listPool, listProvider, "ACTIVE", AttributeCondition(id)))
	for _, args := range [][2]string{
		{"", listPool}, {"12345x", listPool}, {strings.Repeat("1", 21), listPool}, {"my-project-1", listPool},
		{testNumber, ""}, {testNumber, "gcp-pool"}, {testNumber, "Pool1"}, {testNumber, "abc"}, {testNumber, listPool + "/providers/x"},
	} {
		got, token, err := ParseProviders(good, args[0], args[1])
		if err == nil || got != nil || token != "" {
			t.Errorf("ParseProviders for %q: %d providers, token %q, %v", args, len(got), token, err)
			continue
		}
		if !strings.Contains(err.Error(), " is named with ") {
			t.Errorf("ParseProviders for %q: err = %v, want the argument refused before the answer is read", args, err)
		}
		for _, a := range args {
			if a != "" && strings.Contains(err.Error(), a) {
				t.Errorf("the error %q quotes an argument", err)
			}
		}
	}
}

// TestParseProvider: a get's answer for the provider asked for, in the
// instance's pool, reads as a list's entry does, with its RoleID under D3's
// mapping and condition alone; every refused answer is refused with an error
// that quotes nothing; and arguments out of shape read nothing.
func TestParseProvider(t *testing.T) {
	id, err := NewRoleID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cond := AttributeCondition(id)
	get := func(e map[string]any) (ListedProvider, error) {
		return ParseProvider([]byte(mustJSON(t, e)), testNumber, listPool, listProvider)
	}
	own := listEntry(testNumber, listPool, listProvider, "ACTIVE", cond)
	own["displayName"], own["expireTime"] = "ignored", "2026-12-26T00:00:00Z"
	if p, err := get(own); err != nil || p.ID != listProvider || p.State != ProviderActive || p.Disabled || !p.RoleID.Equal(id) {
		t.Errorf("the provider asked for: {%s %s %v role:%v}, %v", p.ID, p.State, p.Disabled, p.RoleID.Equal(id), err)
	}
	deleted := listEntry(testNumber, listPool, listProvider, "DELETED", cond)
	deleted["disabled"] = true
	if p, err := get(deleted); err != nil || p.State != ProviderDeleted || !p.Disabled || !p.RoleID.Equal(id) {
		t.Errorf("a deleted, disabled provider: {%s %v role:%v}, %v", p.State, p.Disabled, p.RoleID.Equal(id), err)
	}
	literal := listEntry(testNumber, listPool, listProvider, "ACTIVE", cond)
	literal["attributeMapping"] = map[string]any{"google.subject": "'" + id.Hex() + "'"}
	if p, err := get(literal); err != nil || !p.RoleID.IsZero() {
		t.Errorf("a provider with another mapping: role ID %v, %v; want none", !p.RoleID.IsZero(), err)
	}
	bare := listEntry(testNumber, listPool, listProvider, "", "")
	if p, err := get(bare); err != nil || p.State != ProviderStateUnspecified || !p.RoleID.IsZero() {
		t.Errorf("a provider with no state or condition: {%s role:%v}, %v", p.State, !p.RoleID.IsZero(), err)
	}

	for _, row := range providerGetRows(t, id) {
		p, err := ParseProvider(row.list, testNumber, listPool, listProvider)
		if err == nil {
			t.Errorf("%s: read {%s %s}", row.name, p.ID, p.State)
			continue
		}
		if p.ID != "" || p.State != "" || p.Disabled || !p.RoleID.IsZero() {
			t.Errorf("%s: a refusal with a provider", row.name)
		}
		if what := quotesTheAnswer(err.Error(), id); what != "" {
			t.Errorf("%s: the error %q quotes %s", row.name, err, what)
		}
	}
	good := []byte(mustJSON(t, own))
	for _, args := range [][3]string{
		{"", listPool, listProvider}, {"12345x", listPool, listProvider}, {"my-project-1", listPool, listProvider},
		{testNumber, "", listProvider}, {testNumber, "gcp-pool", listProvider}, {testNumber, "Pool1", listProvider},
		{testNumber, listPool, ""}, {testNumber, listPool, "abc"}, {testNumber, listPool, "Reader"}, {testNumber, listPool, listProvider + "/x"},
	} {
		p, err := ParseProvider(good, args[0], args[1], args[2])
		if err == nil || p.ID != "" {
			t.Errorf("ParseProvider for %q: {%s}, %v", args, p.ID, err)
			continue
		}
		if !strings.Contains(err.Error(), " is named with ") {
			t.Errorf("ParseProvider for %q: err = %v, want the argument refused before the answer is read", args, err)
		}
		for _, a := range args {
			if a != "" && strings.Contains(err.Error(), a) {
				t.Errorf("the error %q quotes an argument", err)
			}
		}
	}
}
