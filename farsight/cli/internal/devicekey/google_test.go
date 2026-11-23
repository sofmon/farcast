package devicekey

import (
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
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

// providerRows are the answers CheckProvider must refuse for id and
// anchorDER, each with the field it names.
func providerRows(t *testing.T, id RoleID, anchorDER []byte) []providerRow {
	t.Helper()
	other, otherDER := testAnchorDER(t)
	own, otherPEM := pemOneLine(anchorDER), pemOneLine(otherDER)
	row := func(name, field string, mutate func(m map[string]any)) providerRow {
		return providerRow{name, field, providerAnswer(t, id, anchorDER, mutate)}
	}
	return []providerRow{
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
