package devicekey

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// AttributeMapping is D3's mapping: the issuer's CN is google.subject.
const AttributeMapping = "google.subject=assertion.issuer.dn.cn"

// AttributeCondition is D3's per-provider condition, naming one role ID:
//
//	assertion.issuer.dn.cn == '<hex>' && assertion.subject.dn.cn == '<hex>'
//
// It is "" for the zero RoleID, which names no role.
func AttributeCondition(id RoleID) string {
	if id.IsZero() {
		return ""
	}
	h := id.Hex()
	return "assertion.issuer.dn.cn == '" + h + "' && assertion.subject.dn.cn == '" + h + "'"
}

// Principal is the documented principal:// form for a pool subject [X509]:
//
//	principal://iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/subject/<hex>
//
// projectNumber must be ^[0-9]{1,20}$ and pool a pool ID's shape. The error
// names neither.
//
// A pool ID's shape is [MGMT]'s: 4 to 32 of [a-z0-9-], not starting gcp-.
func Principal(projectNumber, pool string, id RoleID) (string, error) {
	if !isProjectNumber(projectNumber) {
		return "", errors.New("devicekey: a principal needs a project number of 1 to 20 digits")
	}
	if !isPoolID(pool) {
		return "", errors.New("devicekey: a principal needs a pool ID of 4 to 32 lowercase letters, digits and hyphens, not starting gcp-")
	}
	if id.IsZero() {
		return "", errors.New("devicekey: a principal needs a role ID")
	}
	return "principal://iam.googleapis.com/projects/" + projectNumber +
		"/locations/global/workloadIdentityPools/" + pool + "/subject/" + id.Hex(), nil
}

// isProjectNumber is ^[0-9]{1,20}$.
func isProjectNumber(s string) bool {
	if len(s) < 1 || len(s) > 20 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isPoolID is 4 to 32 of [a-z0-9-], not starting gcp-.
func isPoolID(s string) bool {
	if len(s) < 4 || len(s) > 32 || strings.HasPrefix(s, "gcp-") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// TrustStoreYAML is the YAML trust-store document Google's X509 provider
// reads [X509, G-CX509, TS], for exactly one anchor and no intermediate:
//
//	trustStore:
//	  trustAnchors:
//	  - pemCertificate: "-----BEGIN CERTIFICATE-----\nMIIB…\n…\n-----END CERTIFICATE-----"
//
// The PEM is in Google's one-line form: the PEM's own newlines are written as
// the two characters \n inside a double-quoted scalar, with no trailing \n
// (the X509 page's sed pipeline drops the last newline), and the document
// ends with one newline. A plain multi-line PEM in a double-quoted scalar
// would be folded, its newlines read as spaces [inf;
// TestAMultiLinePEMInADoubleQuotedScalarIsFolded shows it for go-yaml]. It
// refuses DER that is not a CA certificate.
//
// The PEM's lines contain only [A-Za-z0-9+/=-] and the spaces in the armour,
// so \n is the only escape the generator writes. It refuses any other byte,
// which it never meets.
func TrustStoreYAML(anchorDER []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(anchorDER)
	if err != nil {
		return nil, errors.New("devicekey: a trust store's anchor must be a certificate")
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, errors.New("devicekey: a trust store's anchor must be a CA certificate")
	}
	p := strings.TrimSuffix(string(encodeCert(anchorDER)), "\n")
	var b strings.Builder
	b.WriteString("trustStore:\n  trustAnchors:\n  - pemCertificate: \"")
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == '\n':
			b.WriteString(`\n`)
		case pemArmourByte(c):
			b.WriteByte(c)
		default:
			return nil, errors.New("devicekey: the anchor's PEM holds a byte the trust store does not write")
		}
	}
	b.WriteString("\"\n")
	return []byte(b.String()), nil
}

// pemArmourByte is a byte a PEM CERTIFICATE's lines hold: [A-Za-z0-9+/=-]
// and the armour's spaces.
func pemArmourByte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '=' || c == '-' || c == ' '
}

// providerFieldError names the first field of a providers.get answer that is
// not what the device made, and never a value.
func providerFieldError(field string) error {
	return fmt.Errorf("devicekey: the provider's %s is not what this device made", field)
}

// CheckProvider is D4's read-back for one provider: the JSON a providers.get
// returns [PROV-GET, PROV]. It accepts only:
//   - state "ACTIVE";
//   - disabled absent or false;
//   - attributeMapping exactly {"google.subject": "assertion.issuer.dn.cn"};
//   - attributeCondition exactly AttributeCondition(id);
//   - x509.trustStore with exactly one trustAnchors entry, whose
//     pemCertificate holds exactly one PEM CERTIFICATE block whose bytes equal
//     anchorDER, with nothing else around that block but whitespace;
//   - intermediateCas absent or empty.
//
// How Google stores a pemCertificate's trailing newlines is not documented
// [unverified], so whitespace is not a security fact. A second PEM block, or
// any rest that is not whitespace, is refused. Unknown fields are ignored. Its
// error names the first field that differs ("state", "disabled", "attribute
// mapping", "attribute condition", "trust store", "intermediate
// certificates", "the answer"), and never a value.
//
// Field names are matched exactly, not as encoding/json matches a struct's
// fields, without regard to case.
func CheckProvider(answer []byte, anchorDER []byte, id RoleID) error {
	if id.IsZero() || len(anchorDER) == 0 {
		return errors.New("devicekey: a provider is checked against a role ID and its anchor")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(answer, &top); err != nil || top == nil {
		return providerFieldError("the answer")
	}
	var state string
	if !decodeField(top, "state", &state) || state != "ACTIVE" {
		return providerFieldError("state")
	}
	if raw, ok := top["disabled"]; ok {
		var disabled bool
		if json.Unmarshal(raw, &disabled) != nil || disabled {
			return providerFieldError("disabled")
		}
	}
	var mapping map[string]string
	name, value, _ := strings.Cut(AttributeMapping, "=")
	if !decodeField(top, "attributeMapping", &mapping) || len(mapping) != 1 || mapping[name] != value {
		return providerFieldError("attribute mapping")
	}
	var condition string
	if !decodeField(top, "attributeCondition", &condition) || condition != AttributeCondition(id) {
		return providerFieldError("attribute condition")
	}
	var x509Field, trustStore map[string]json.RawMessage
	if !decodeField(top, "x509", &x509Field) || !decodeField(x509Field, "trustStore", &trustStore) {
		return providerFieldError("trust store")
	}
	var anchors []map[string]json.RawMessage
	if !decodeField(trustStore, "trustAnchors", &anchors) || len(anchors) != 1 {
		return providerFieldError("trust store")
	}
	var pemText string
	if !decodeField(anchors[0], "pemCertificate", &pemText) || !onePEMOf(pemText, anchorDER) {
		return providerFieldError("trust store")
	}
	if raw, ok := trustStore["intermediateCas"]; ok {
		var intermediates []json.RawMessage
		if json.Unmarshal(raw, &intermediates) != nil || len(intermediates) != 0 {
			return providerFieldError("intermediate certificates")
		}
	}
	return nil
}

// decodeField decodes m[key] into v; false when it is absent, null or not
// v's shape.
func decodeField(m map[string]json.RawMessage, key string, v any) bool {
	raw, ok := m[key]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	return json.Unmarshal(raw, v) == nil
}

// onePEMOf reports whether s is exactly one PEM CERTIFICATE block, with no
// headers, whose bytes equal der, and nothing around it but whitespace.
func onePEMOf(s string, der []byte) bool {
	got, ok := onlyBlock([]byte(s), pemCertificate)
	return ok && bytes.Equal(got, der)
}
