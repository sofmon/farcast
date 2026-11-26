package devicekey

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// AttributeMapping is D3's mapping: the issuer's CN is google.subject.
const AttributeMapping = "google.subject=assertion.issuer.dn.cn"

// The condition's three fixed parts, around the role ID's two places.
const (
	conditionIssuer  = "assertion.issuer.dn.cn == '"
	conditionSubject = "' && assertion.subject.dn.cn == '"
	conditionEnd     = "'"
)

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
	return conditionIssuer + h + conditionSubject + h + conditionEnd
}

// errConditionShape is RoleIDFromCondition's one error. It never quotes the
// condition.
var errConditionShape = errors.New("devicekey: the condition is not D3's shape: one role ID, as both the issuer's and the subject's CN, and nothing else")

// RoleIDFromCondition is the role ID a provider's condition names. It reads
// the condition alone, and a condition's ID is the principal's only under
// D3's mapping, so for a provider this machine did not make `device rm` takes
// the principal's role ID from ParseProvider or ParseProviders, which check
// the mapping too (ListedProvider.RoleID), never from this alone. It accepts
// exactly what
// AttributeCondition renders, byte for byte: one role ID, the same in both
// places. Anything else is refused, with an error that quotes nothing:
// another ID in the second place, whitespace or case changed anywhere, a
// clause added or removed, another attribute, other quotes, or anything
// before or after. It reads the first place's 32 characters as a role ID and
// then compares the whole condition with AttributeCondition of that ID, so
// no part of the condition is parsed beyond that one ID.
func RoleIDFromCondition(cond string) (RoleID, error) {
	rest, ok := strings.CutPrefix(cond, conditionIssuer)
	if !ok || len(rest) < 2*roleIDLen {
		return RoleID{}, errConditionShape
	}
	id, err := ParseRoleID(rest[:2*roleIDLen])
	if err != nil {
		return RoleID{}, errConditionShape
	}
	if AttributeCondition(id) != cond {
		return RoleID{}, errConditionShape
	}
	return id, nil
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

// isProviderID is a provider ID's shape, which is a pool ID's [MGMT]: 4 to 32
// of [a-z0-9-], not starting gcp-.
func isProviderID(s string) bool { return isPoolID(s) }

// poolResource is a pool's resource name, with its project's number:
//
//	projects/<number>/locations/global/workloadIdentityPools/<pool>
//
// projectNumber must be ^[0-9]{1,20}$ and pool a pool ID's shape. The error
// names neither.
func poolResource(projectNumber, pool string) (string, error) {
	if !isProjectNumber(projectNumber) {
		return "", errors.New("devicekey: a pool is named with a project number of 1 to 20 digits")
	}
	if !isPoolID(pool) {
		return "", errors.New("devicekey: a pool is named with a pool ID of 4 to 32 lowercase letters, digits and hyphens, not starting gcp-")
	}
	return "projects/" + projectNumber + "/locations/global/workloadIdentityPools/" + pool, nil
}

// providerResource is a provider's resource name: poolResource, then
// /providers/ and the provider's ID, which must be in shape. The error names
// no value.
func providerResource(projectNumber, pool, provider string) (string, error) {
	p, err := poolResource(projectNumber, pool)
	if err != nil {
		return "", err
	}
	if !isProviderID(provider) {
		return "", errors.New("devicekey: a provider is named with its ID: 4 to 32 lowercase letters, digits and hyphens, not starting gcp-")
	}
	return p + "/providers/" + provider, nil
}

// isProjectID is a project ID's shape: 6 to 30 of [a-z0-9-], a letter first,
// not ending in a hyphen.
func isProjectID(s string) bool {
	if len(s) < 6 || len(s) > 30 || s[0] < 'a' || s[0] > 'z' || s[len(s)-1] == '-' {
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

// providerName reads a provider's resource name [PROV-GET]:
//
//	projects/<number or ID>/locations/global/workloadIdentityPools/<pool>/providers/<provider>
//
// each part in its shape. pool is the name up to and not including
// "/providers/", and id the provider's ID. ok is false for any other shape.
func providerName(name string) (pool, id string, ok bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 8 || parts[0] != "projects" || parts[2] != "locations" || parts[3] != "global" ||
		parts[4] != "workloadIdentityPools" || parts[6] != "providers" {
		return "", "", false
	}
	if (!isProjectNumber(parts[1]) && !isProjectID(parts[1])) || !isPoolID(parts[5]) || !isProviderID(parts[7]) {
		return "", "", false
	}
	return strings.Join(parts[:6], "/"), parts[7], true
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
//   - name in a provider's resource name's shape (providerName), so ending in
//     /providers/ and a provider ID's shape; CheckNamedProvider requires the
//     whole name to be the device's provider's;
//   - state "ACTIVE";
//   - disabled absent or false;
//   - no displayName and no description, of any value: D3 sets neither, and
//     Google's JSON leaves an unset string out [inf];
//   - attributeMapping exactly {"google.subject": "assertion.issuer.dn.cn"};
//   - attributeCondition exactly AttributeCondition(id);
//   - x509.trustStore with exactly one trustAnchors entry, whose
//     pemCertificate holds exactly one PEM CERTIFICATE block whose bytes equal
//     anchorDER, with nothing else around that block but whitespace;
//   - intermediateCas absent or empty.
//
// How Google stores a pemCertificate's trailing newlines is not documented
// [unverified], so whitespace is not a security fact. A second PEM block, or
// any rest that is not whitespace, is refused. Its error names the first
// field that differs ("name", "state", "disabled", "display name",
// "description", "attribute mapping", "attribute condition", "trust store",
// "intermediate certificates", "the answer"), and never a value.
//
// Every object it reads (the answer, attributeMapping, x509, trustStore and
// the anchor's entry) is read strictly, as ParseProviders reads a list: no
// key twice, so a key given twice is refused, never read as its last value.
// Field names are matched exactly, not as encoding/json matches a struct's
// fields, without regard to case. Unknown fields are ignored.
//
// It is the M3a walk probe's, with M3a's signature. It does not know the
// provider's name, so it accepts an answer for any provider holding this
// anchor and condition. Product code calls CheckNamedProvider, and
// TestProbeOnlyFunctionsAreNotShipped refuses a shipped file that names
// CheckProvider.
func CheckProvider(answer []byte, anchorDER []byte, id RoleID) error {
	return checkProvider(answer, "", anchorDER, id)
}

// CheckNamedProvider is CheckProvider for the provider the device made, in the
// instance's pool: the answer's name must be exactly
//
//	projects/<projectNumber>/locations/global/workloadIdentityPools/<pool>/providers/<provider>
//
// so an answer for another provider, of this pool or of another, holding the
// same anchor or not, is refused as "name". Google names a provider with its
// project's number [inf: M3a's T4 read-back accepted either form, and M3b's
// walk settles it]. projectNumber, pool and provider must each be in shape,
// or nothing is read, and the error names none of them.
func CheckNamedProvider(answer []byte, projectNumber, pool, provider string, anchorDER []byte, id RoleID) error {
	name, err := providerResource(projectNumber, pool, provider)
	if err != nil {
		return err
	}
	return checkProvider(answer, name, anchorDER, id)
}

// checkProvider is CheckProvider's body; wantName is "" for any provider's
// name in shape, or the one resource name the answer must carry.
func checkProvider(answer []byte, wantName string, anchorDER []byte, id RoleID) error {
	if id.IsZero() || len(anchorDER) == 0 {
		return errors.New("devicekey: a provider is checked against a role ID and its anchor")
	}
	top, ok := strictObject(answer)
	if !ok {
		return providerFieldError("the answer")
	}
	var name string
	if !decodeField(top, "name", &name) {
		return providerFieldError("name")
	}
	if _, _, ok := providerName(name); !ok || (wantName != "" && name != wantName) {
		return providerFieldError("name")
	}
	var state string
	if !decodeField(top, "state", &state) || state != ProviderActive {
		return providerFieldError("state")
	}
	if raw, ok := top["disabled"]; ok {
		var disabled bool
		if json.Unmarshal(raw, &disabled) != nil || disabled {
			return providerFieldError("disabled")
		}
	}
	if _, ok := top["displayName"]; ok {
		return providerFieldError("display name")
	}
	if _, ok := top["description"]; ok {
		return providerFieldError("description")
	}
	if raw, ok := top["attributeMapping"]; !ok || !mappingIsD3(raw) {
		return providerFieldError("attribute mapping")
	}
	var condition string
	if !decodeField(top, "attributeCondition", &condition) || condition != AttributeCondition(id) {
		return providerFieldError("attribute condition")
	}
	x509Field, ok := objectField(top, "x509")
	if !ok {
		return providerFieldError("trust store")
	}
	trustStore, ok := objectField(x509Field, "trustStore")
	if !ok {
		return providerFieldError("trust store")
	}
	var anchors []json.RawMessage
	if !decodeField(trustStore, "trustAnchors", &anchors) || len(anchors) != 1 {
		return providerFieldError("trust store")
	}
	entry, ok := strictObject(anchors[0])
	if !ok {
		return providerFieldError("trust store")
	}
	var pemText string
	if !decodeField(entry, "pemCertificate", &pemText) || !onePEMOf(pemText, anchorDER) {
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

// objectField is m[key] read as a strict object (strictObject); false when it
// is absent, null or anything else.
func objectField(m map[string]json.RawMessage, key string) (map[string]json.RawMessage, bool) {
	raw, ok := m[key]
	if !ok {
		return nil, false
	}
	return strictObject(raw)
}

// mappingIsD3 reports whether raw is exactly D3's attributeMapping, read as a
// strict object: one key, google.subject, whose value is the string
// assertion.issuer.dn.cn.
func mappingIsD3(raw json.RawMessage) bool {
	m, ok := strictObject(raw)
	if !ok || len(m) != 1 {
		return false
	}
	key, value, _ := strings.Cut(AttributeMapping, "=")
	var got string
	return decodeField(m, key, &got) && got == value
}

// onePEMOf reports whether s is exactly one PEM CERTIFICATE block, with no
// headers, whose bytes equal der, and nothing around it but whitespace.
func onePEMOf(s string, der []byte) bool {
	got, ok := onlyBlock([]byte(s), pemCertificate)
	return ok && bytes.Equal(got, der)
}

// A provider's states as Google names them [PROV]. A deleted provider is kept
// for about 30 days in ProviderDeleted, and a list shows it only when asked
// to (showDeleted) [PROV; inf].
const (
	ProviderActive  = "ACTIVE"
	ProviderDeleted = "DELETED"
	// ProviderStateUnspecified is the state of an entry that names none:
	// Google's JSON leaves an enum's zero value out [inf].
	ProviderStateUnspecified = "STATE_UNSPECIFIED"
)

// MaxProvidersList is the most ParseProviders reads: a larger answer is
// refused, never truncated. A page of the device's own providers is about
// 1.3 KB per provider; a provider at Google's documented trust-store limits
// (3 anchors and 10 intermediates [doc: X509]) is some tens of KB, so the
// reader that fetches a list asks for pages small enough to fit (M3b.3), and
// reads at most MaxProvidersList+1 bytes.
const MaxProvidersList = 1 << 20

// maxPageToken bounds a next page token's length [inf: Google's are far
// shorter].
const maxPageToken = 4096

// ListedProvider is one provider as ParseProviders or ParseProvider reads it:
// what `device ls` labels and `device rm` names. The ID and the state are
// shape-checked, so either can be printed; the role ID formats as fixed text,
// as every RoleID does.
//
// A provider is labelled by its ID alone: this machine's own by the record's
// provider IDs, another device's by what `device known` was told. Never by
// its RoleID: a rogue provider can copy another's mapping and condition, so
// two providers may name one RoleID, which says nothing of whose either is.
type ListedProvider struct {
	ID       string // the provider's ID: the last part of its name
	State    string // ProviderActive, ProviderDeleted, ProviderStateUnspecified, or another [A-Z_] state Google names
	Disabled bool
	// RoleID is the role ID of the principal the provider maps every chain it
	// admits to, subject/<RoleID>. It is set only when the provider's
	// attributeMapping is exactly D3's (one key, google.subject, from
	// assertion.issuer.dn.cn) and its attributeCondition exactly
	// AttributeCondition's shape (RoleIDFromCondition): with any other
	// mapping the condition's ID need not be the principal's. Otherwise it is
	// the zero RoleID: no mapping or another, no condition or another, two
	// IDs included. Such a provider is still listed: it is one `device ls`
	// shows as unknown, and one whose principal `device rm` cannot name.
	RoleID RoleID
}

// listFieldError names a providers list's field that is not readable, and
// never a value.
func listFieldError(field string) error {
	return fmt.Errorf("devicekey: the providers list's %s is not readable", field)
}

// errNotAList refuses an answer that holds a field a providers list does
// not: an error's, or one this build does not know. It names no field.
var errNotAList = errors.New("devicekey: the answer holds a field a providers list does not; it is refused whole")

// ParseProviders reads one page of the instance's pool's providers list, the
// JSON a providers.list returns [PROV; the shape is inf: M3a's T4 read a
// provider with get only]:
//
//	{"workloadIdentityPoolProviders": [{"name": …, "state": …, "disabled": …, "attributeMapping": …, "attributeCondition": …, …}, …], "nextPageToken": …}
//
// projectNumber and pool name the instance's pool, as Principal takes them;
// either out of shape is refused before anything is read. It returns each
// entry in the answer's order, and the next page's token, "" on the last
// page. It reads only the fields it returns, and reads them strictly:
//   - the answer is at most MaxProvidersList bytes, refused before it is
//     parsed;
//   - every object, the answer's, each entry's and each entry's mapping, is
//     a JSON object with no key twice, keys matched exactly;
//   - the answer holds no field but workloadIdentityPoolProviders and
//     nextPageToken: an error's body, or a key in another case, is refused,
//     never read as an empty pool;
//   - workloadIdentityPoolProviders absent or null is an empty page; otherwise
//     an array of objects;
//   - each entry's name is a provider's resource name (providerName) in the
//     instance's pool (CheckNamedProvider's form), and no ID twice;
//   - state absent or null is ProviderStateUnspecified; otherwise 1 to 32 of
//     [A-Z_]. A DELETED provider is returned with its state;
//   - disabled absent or null is false; otherwise a boolean;
//   - attributeMapping absent or null is no mapping; otherwise an object of
//     strings;
//   - attributeCondition absent or null is no condition; otherwise a string;
//   - RoleID is the condition's, when the mapping and the condition are both
//     D3's (ListedProvider.RoleID);
//   - nextPageToken absent, null or "" is the last page; otherwise 1 to 4096
//     of [A-Za-z0-9+/=_.~-].
//
// Every other field of an entry, the trust store included, is ignored. An
// error names the field, and the entry's index, never a value.
//
// What it cannot check is the caller's (M3b.3's reader): it parses only an
// answer of status 200; it caps the pages it follows; and it refuses a token
// it was already given, because an empty page may carry a token, and a
// server that repeats one would make it loop. A role ID that more than one
// provider of the pool names is read as ListedProvider says.
func ParseProviders(listJSON []byte, projectNumber, pool string) (providers []ListedProvider, nextPageToken string, err error) {
	poolName, err := poolResource(projectNumber, pool)
	if err != nil {
		return nil, "", err
	}
	if len(listJSON) > MaxProvidersList {
		return nil, "", fmt.Errorf("devicekey: a providers list of more than %d bytes is refused", MaxProvidersList)
	}
	top, ok := strictObject(listJSON)
	if !ok {
		return nil, "", listFieldError("answer")
	}
	for key := range top {
		if key != "workloadIdentityPoolProviders" && key != "nextPageToken" {
			return nil, "", errNotAList
		}
	}
	if raw, ok := top["nextPageToken"]; ok && !isJSONNull(raw) {
		if json.Unmarshal(raw, &nextPageToken) != nil || (nextPageToken != "" && !isPageToken(nextPageToken)) {
			return nil, "", listFieldError("next page token")
		}
	}
	raw, ok := top["workloadIdentityPoolProviders"]
	if !ok || isJSONNull(raw) {
		return nil, nextPageToken, nil
	}
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return nil, "", listFieldError("providers")
	}
	seen := make(map[string]bool, len(entries))
	for i, e := range entries {
		p, entryPool, field := parseListedProvider(e)
		if field != "" {
			return nil, "", fmt.Errorf("devicekey: provider %d of the list: its %s is not readable", i, field)
		}
		if entryPool != poolName {
			return nil, "", fmt.Errorf("devicekey: provider %d of the list is not in the instance's pool", i)
		}
		if seen[p.ID] {
			return nil, "", fmt.Errorf("devicekey: provider %d of the list repeats an earlier provider's ID", i)
		}
		seen[p.ID] = true
		providers = append(providers, p)
	}
	return providers, nextPageToken, nil
}

// ParseProvider reads one provider, the JSON a providers.get returns, as
// ParseProviders reads a list's entry: for a provider this machine did not
// make, whose principal `device rm` names from its RoleID (D4). The answer's
// name must be exactly the provider's in the instance's pool, as
// CheckNamedProvider requires; projectNumber, pool and provider must each be
// in shape, or nothing is read. The answer is at most MaxProvidersList bytes
// and is read strictly, as ParseProviders reads an entry, and every other
// field is ignored. Its error names the field, never a value.
func ParseProvider(getJSON []byte, projectNumber, pool, provider string) (ListedProvider, error) {
	want, err := providerResource(projectNumber, pool, provider)
	if err != nil {
		return ListedProvider{}, err
	}
	if len(getJSON) > MaxProvidersList {
		return ListedProvider{}, fmt.Errorf("devicekey: a provider of more than %d bytes is refused", MaxProvidersList)
	}
	p, entryPool, field := parseListedProvider(getJSON)
	if field != "" {
		return ListedProvider{}, fmt.Errorf("devicekey: the provider's %s is not readable", field)
	}
	if entryPool+"/providers/"+p.ID != want {
		return ListedProvider{}, errors.New("devicekey: the answer is for another provider than the one asked for")
	}
	return p, nil
}

// parseListedProvider reads one provider, a list's entry or a get's answer,
// and its pool's part of the name. field names what is not readable, "" when
// all is.
func parseListedProvider(raw json.RawMessage) (p ListedProvider, pool, field string) {
	m, ok := strictObject(raw)
	if !ok {
		return ListedProvider{}, "", "entry"
	}
	var name string
	if !decodeField(m, "name", &name) {
		return ListedProvider{}, "", "name"
	}
	pool, p.ID, ok = providerName(name)
	if !ok {
		return ListedProvider{}, "", "name"
	}
	p.State = ProviderStateUnspecified
	if raw, ok := m["state"]; ok && !isJSONNull(raw) {
		if json.Unmarshal(raw, &p.State) != nil || !isStateName(p.State) {
			return ListedProvider{}, "", "state"
		}
	}
	if raw, ok := m["disabled"]; ok && !isJSONNull(raw) {
		if json.Unmarshal(raw, &p.Disabled) != nil {
			return ListedProvider{}, "", "disabled"
		}
	}
	d3Mapping := false
	if raw, ok := m["attributeMapping"]; ok && !isJSONNull(raw) {
		mapping, ok := strictObject(raw)
		if !ok || !allStrings(mapping) {
			return ListedProvider{}, "", "attribute mapping"
		}
		d3Mapping = mappingIsD3(raw)
	}
	if raw, ok := m["attributeCondition"]; ok && !isJSONNull(raw) {
		var cond string
		if json.Unmarshal(raw, &cond) != nil {
			return ListedProvider{}, "", "attribute condition"
		}
		if id, err := RoleIDFromCondition(cond); err == nil && d3Mapping {
			p.RoleID = id
		}
	}
	return p, pool, ""
}

// allStrings reports whether every value of m is a JSON string, null not
// included.
func allStrings(m map[string]json.RawMessage) bool {
	for _, v := range m {
		var s string
		if isJSONNull(v) || json.Unmarshal(v, &s) != nil {
			return false
		}
	}
	return true
}

// strictObject reads data as one JSON object: its keys matched exactly, none
// twice, and nothing after it but whitespace. ok is false for anything else,
// null included.
func strictObject(data []byte) (map[string]json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	m := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, ok := tok.(string)
		if !ok {
			return nil, false
		}
		if _, dup := m[key]; dup {
			return nil, false
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, false
		}
		m[key] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return m, true
}

// isJSONNull reports whether raw is JSON's null.
func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// isStateName is 1 to 32 of [A-Z_]: an enum value's shape, safe to print.
func isStateName(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 'A' || c > 'Z') && c != '_' {
			return false
		}
	}
	return true
}

// isPageToken is 1 to maxPageToken of [A-Za-z0-9+/=_.~-]: base64 in either
// alphabet, and the characters a URL leaves unreserved, so the reader can put
// it into a query once escaped and never meets a control character.
func isPageToken(s string) bool {
	if len(s) < 1 || len(s) > maxPageToken {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && !strings.ContainsRune("+/=_.~-", rune(c)) {
			return false
		}
	}
	return true
}
