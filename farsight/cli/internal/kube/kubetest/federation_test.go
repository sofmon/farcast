package kubetest_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
)

// The fakes' tests' coordinates.
const (
	fedProject = "123456789012"
	fedPool    = "pool1234"
	fedSA      = "reader-sa1@proj-01.iam.gserviceaccount.com"
	fedOtherSA = "writer-sa1@proj-01.iam.gserviceaccount.com"
)

// fedRole is a role's anchor and leaf: the anchor self-signed with CN
// anchorCN, a CA with path length 0, keyCertSign and clientAuth; the leaf
// issued by it with CN leafCN, digitalSignature and clientAuth. D2's shape
// has anchorCN == leafCN == the role ID.
type fedRole struct {
	id        string
	anchorKey *ecdsa.PrivateKey
	anchor    *x509.Certificate
	anchorDER []byte
	leafDER   []byte
	leafKey   *ecdsa.PrivateKey
}

func fedID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

func fedECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fedSerialNumber(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return n.Add(n, big.NewInt(1))
}

// newFedRole is D2's pair for a fresh role ID.
func newFedRole(t *testing.T) fedRole {
	t.Helper()
	id := fedID(t)
	return newFedPair(t, id, id)
}

// newFedPair is an anchor with CN anchorCN and a leaf with CN leafCN.
func newFedPair(t *testing.T, anchorCN, leafCN string) fedRole {
	t.Helper()
	r := fedRole{id: leafCN, anchorKey: fedECKey(t)}
	pub, err := r.anchorKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	skid := sha256.Sum256(pub)
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber:          fedSerialNumber(t),
		Subject:               pkix.Name{CommonName: anchorCN},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(390 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId:          skid[:20],
	}
	if r.anchorDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &r.anchorKey.PublicKey, r.anchorKey); err != nil {
		t.Fatal(err)
	}
	if r.anchor, err = x509.ParseCertificate(r.anchorDER); err != nil {
		t.Fatal(err)
	}
	r.leafDER, r.leafKey = r.issue(t, leafCN, notBefore, notBefore.Add(90*24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	return r
}

// issue is another leaf under r's anchor.
func (r fedRole) issue(t *testing.T, cn string, notBefore, notAfter time.Time, eku []x509.ExtKeyUsage) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key := fedECKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          fedSerialNumber(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           eku,
		AuthorityKeyId:        r.anchor.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, r.anchor, &key.PublicKey, r.anchorKey)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

// fedHTTP is a client of the fakes that presents chain with key (none when
// chain is nil), over HTTP/1.1, with a fresh connection per request.
func fedHTTP(fake *kubetest.Federation, chain [][]byte, key crypto.Signer, minTLS uint16) *http.Client {
	tc := &tls.Config{RootCAs: fake.Roots(), ServerName: "127.0.0.1", MinVersion: minTLS}
	if chain != nil {
		cert := &tls.Certificate{Certificate: chain, PrivateKey: key}
		tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tc, DisableKeepAlives: true},
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// fedForm is a well-formed exchange form for subject at aud.
func fedForm(t *testing.T, aud string, subject ...[]byte) url.Values {
	t.Helper()
	st, err := kube.SubjectToken(subject)
	if err != nil {
		t.Fatal(err)
	}
	v, err := url.ParseQuery(kube.ExchangeForm(aud, kube.TokenTypeMTLS, st, []string{kube.ScopeCloudPlatform}))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// fedPost posts body with contentType and returns the status and the
// decoded JSON answer.
func fedPost(t *testing.T, c *http.Client, target, contentType, bearer, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

// fedExchange posts form to the STS fake.
func fedExchange(t *testing.T, c *http.Client, fake *kubetest.Federation, form url.Values) (int, map[string]any) {
	t.Helper()
	return fedPost(t, c, "https://"+fake.STSAddr()+kube.STSTokenPath, "application/x-www-form-urlencoded", "", form.Encode())
}

// oauthCode is an STS answer's "error".
func oauthCode(m map[string]any) string {
	s, _ := m["error"].(string)
	return s
}

// googleStatus is an IAM answer's error.status.
func googleStatus(m map[string]any) string {
	e, _ := m["error"].(map[string]any)
	s, _ := e["status"].(string)
	return s
}

// fedAddRole adds r's provider and returns its audience.
func fedAddRole(t *testing.T, fake *kubetest.Federation, provider string, r fedRole, roleID string) string {
	t.Helper()
	fake.AddProvider(fedProject, fedPool, provider, r.anchorDER, roleID)
	aud, err := kube.Audience(fedProject, fedPool, provider)
	if err != nil {
		t.Fatal(err)
	}
	return aud
}

// TestFakeSTSRequiresTheHandshakeLeafFirst: the subject token's first
// certificate must be the very leaf the handshake presented.
func TestFakeSTSRequiresTheHandshakeLeafFirst(t *testing.T) {
	fake := kubetest.NewFederation(t)
	r := newFedRole(t)
	aud := fedAddRole(t, fake, "provreader1", r, r.id)
	sibling, _ := r.issue(t, r.id, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	for _, c := range []struct {
		name      string
		handshake [][]byte
		subject   [][]byte
		code      int
		oauth     string
	}{
		{"the handshake's leaf", [][]byte{r.leafDER}, [][]byte{r.leafDER}, http.StatusOK, ""},
		{"the handshake's leaf, with its anchor", [][]byte{r.leafDER, r.anchorDER}, [][]byte{r.leafDER, r.anchorDER}, http.StatusOK, ""},
		{"the handshake sends the anchor too", [][]byte{r.leafDER, r.anchorDER}, [][]byte{r.leafDER}, http.StatusOK, ""},
		{"another valid leaf of the same role", [][]byte{r.leafDER}, [][]byte{sibling}, http.StatusBadRequest, "invalid_grant"},
		{"the leaf, but not first", [][]byte{r.leafDER}, [][]byte{r.anchorDER, r.leafDER}, http.StatusBadRequest, "invalid_grant"},
	} {
		code, m := fedExchange(t, fedHTTP(fake, c.handshake, r.leafKey, tls.VersionTLS13), fake, fedForm(t, aud, c.subject...))
		if code != c.code || oauthCode(m) != c.oauth {
			t.Errorf("%s: %d %q, want %d %q", c.name, code, oauthCode(m), c.code, c.oauth)
		}
		if c.code == http.StatusOK {
			if tok, _ := m["access_token"].(string); !strings.HasPrefix(tok, "kubetest-federated-") || m["issued_token_type"] != kube.TokenTypeAccessToken || m["token_type"] != "Bearer" || m["expires_in"] != float64(3599) {
				t.Errorf("%s: the answer is not the fake's token: %v", c.name, m["issued_token_type"])
			}
		}
	}
	// A subject token that is not a chain of standard-base64 DER. (The URL
	// row needs a leaf whose two encodings differ, as nearly every one does.)
	if base64.RawURLEncoding.EncodeToString(r.leafDER) == base64.StdEncoding.EncodeToString(r.leafDER) {
		t.Fatal("this leaf's URL and standard base64 are the same; run again")
	}
	for name, st := range map[string]string{
		"not JSON":        "nope",
		"an empty array":  "[]",
		"URL base64":      `["` + base64.RawURLEncoding.EncodeToString(r.leafDER) + `"]`,
		"not certificate": `["bm90IGEgY2VydGlmaWNhdGU="]`,
	} {
		form := fedForm(t, aud, r.leafDER)
		form.Set("subject_token", st)
		if code, m := fedExchange(t, fedHTTP(fake, [][]byte{r.leafDER}, r.leafKey, tls.VersionTLS13), fake, form); code != http.StatusBadRequest || oauthCode(m) != "invalid_grant" {
			t.Errorf("subject token %s: %d %q, want 400 invalid_grant", name, code, oauthCode(m))
		}
	}
	// With the certificate optional, a request presenting none is refused.
	optional := kubetest.NewFederation(t, kubetest.WithClientCertificateOptional())
	aud = fedAddRole(t, optional, "provreader1", r, r.id)
	if code, m := fedExchange(t, fedHTTP(optional, nil, nil, tls.VersionTLS13), optional, fedForm(t, aud, r.leafDER)); code != http.StatusBadRequest || oauthCode(m) != "invalid_request" {
		t.Errorf("no certificate: %d %q, want 400 invalid_request", code, oauthCode(m))
	}
}

// TestFakeSTSAppliesTheTrustStoreAndTheCondition: a leaf must verify against
// the audience's provider's one anchor, for client authentication, now; and
// the provider's condition must hold: the issuer's CN and the leaf's CN both
// the provider's role ID (D3's
// assertion.issuer.dn.cn == '<id>' && assertion.subject.dn.cn == '<id>').
// The form's own rules come first.
func TestFakeSTSAppliesTheTrustStoreAndTheCondition(t *testing.T) {
	fake := kubetest.NewFederation(t)
	r := newFedRole(t)
	aud := fedAddRole(t, fake, "provreader1", r, r.id)
	foreign := newFedRole(t)
	foreignSameID := newFedPair(t, r.id, r.id) // another key, the same ID: another device's anchor
	otherCN := fedID(t)
	wrongIssuer := newFedPair(t, otherCN, r.id)
	audWrongIssuer := fedAddRole(t, fake, "provissuer1", wrongIssuer, r.id)
	wrongSubjectDER, wrongSubjectKey := r.issue(t, otherCN, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	expiredDER, expiredKey := r.issue(t, r.id, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	serverDER, serverKey := r.issue(t, r.id, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	unknownAud, err := kube.Audience(fedProject, fedPool, "provunknown")
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name  string
		chain [][]byte
		key   crypto.Signer
		aud   string
		code  int
		oauth string
	}{
		{"the role's own leaf", [][]byte{r.leafDER}, r.leafKey, aud, http.StatusOK, ""},
		{"a leaf under a foreign anchor", [][]byte{foreign.leafDER}, foreign.leafKey, aud, http.StatusBadRequest, "invalid_grant"},
		{"a leaf naming the ID under another anchor", [][]byte{foreignSameID.leafDER}, foreignSameID.leafKey, aud, http.StatusBadRequest, "invalid_grant"},
		{"a leaf whose CN is another ID", [][]byte{wrongSubjectDER}, wrongSubjectKey, aud, http.StatusBadRequest, "unauthorized_client"},
		{"an anchor whose CN is another ID", [][]byte{wrongIssuer.leafDER}, wrongIssuer.leafKey, audWrongIssuer, http.StatusBadRequest, "unauthorized_client"},
		{"an expired leaf", [][]byte{expiredDER}, expiredKey, aud, http.StatusBadRequest, "invalid_grant"},
		{"a leaf for server authentication", [][]byte{serverDER}, serverKey, aud, http.StatusBadRequest, "invalid_grant"},
		{"an audience naming no provider", [][]byte{r.leafDER}, r.leafKey, unknownAud, http.StatusBadRequest, "invalid_target"},
	} {
		code, m := fedExchange(t, fedHTTP(fake, c.chain, c.key, tls.VersionTLS13), fake, fedForm(t, c.aud, c.chain...))
		if code != c.code || oauthCode(m) != c.oauth {
			t.Errorf("%s: %d %q, want %d %q", c.name, code, oauthCode(m), c.code, c.oauth)
		}
	}

	// The form's rules.
	good := func() url.Values { return fedForm(t, aud, r.leafDER) }
	for _, c := range []struct {
		name  string
		edit  func(url.Values)
		oauth string
	}{
		{"a seventh key", func(v url.Values) { v.Set("client_id", "x") }, "invalid_request"},
		{"no scope", func(v url.Values) { v.Del("scope") }, "invalid_request"},
		{"a key twice", func(v url.Values) { v.Add("audience", aud) }, "invalid_request"},
		{"another grant type", func(v url.Values) { v.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer") }, "invalid_request"},
		{"another requested type", func(v url.Values) { v.Set("requested_token_type", "urn:ietf:params:oauth:token-type:id_token") }, "invalid_request"},
		{"another subject type", func(v url.Values) { v.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt") }, "invalid_request"},
		{"userinfo.email alone", func(v url.Values) { v.Set("scope", kube.ScopeUserinfoEmail) }, "invalid_scope"},
		{"an unknown scope", func(v url.Values) {
			v.Set("scope", kube.ScopeCloudPlatform+" https://www.googleapis.com/auth/devstorage.full_control")
		}, "invalid_scope"},
		{"two spaces", func(v url.Values) { v.Set("scope", kube.ScopeCloudPlatform+"  "+kube.ScopeUserinfoEmail) }, "invalid_scope"},
	} {
		v := good()
		c.edit(v)
		if code, m := fedExchange(t, fedHTTP(fake, [][]byte{r.leafDER}, r.leafKey, tls.VersionTLS13), fake, v); code != http.StatusBadRequest || oauthCode(m) != c.oauth {
			t.Errorf("%s: %d %q, want 400 %q", c.name, code, oauthCode(m), c.oauth)
		}
	}
	v := good()
	v.Set("scope", kube.ScopeCloudPlatform+" "+kube.ScopeUserinfoEmail)
	if code, _ := fedExchange(t, fedHTTP(fake, [][]byte{r.leafDER}, r.leafKey, tls.VersionTLS13), fake, v); code != http.StatusOK {
		t.Errorf("both scopes: %d, want 200", code)
	}
	if code, m := fedPost(t, fedHTTP(fake, [][]byte{r.leafDER}, r.leafKey, tls.VersionTLS13), "https://"+fake.STSAddr()+kube.STSTokenPath, "application/json", "", `{}`); code != http.StatusBadRequest || oauthCode(m) != "invalid_request" {
		t.Errorf("a JSON body: %d %q, want 400 invalid_request", code, oauthCode(m))
	}
}

// fedFederatedToken is a federated token for r from fake.
func fedFederatedToken(t *testing.T, fake *kubetest.Federation, r fedRole, aud string) string {
	t.Helper()
	code, m := fedExchange(t, fedHTTP(fake, [][]byte{r.leafDER}, r.leafKey, tls.VersionTLS13), fake, fedForm(t, aud, r.leafDER))
	tok, _ := m["access_token"].(string)
	if code != http.StatusOK || tok == "" {
		t.Fatalf("the exchange answered %d", code)
	}
	return tok
}

// TestFakeIAMCredentialsChecksBearerBodyAndBinding: generateAccessToken needs
// a federated token the STS fake issued, a body of exactly scope and lifetime
// read by their exact keys, and a binding of the token's role ID to the
// account.
func TestFakeIAMCredentialsChecksBearerBodyAndBinding(t *testing.T) {
	fake := kubetest.NewFederation(t)
	r := newFedRole(t)
	aud := fedAddRole(t, fake, "provreader1", r, r.id)
	fake.Bind(r.id, fedSA)
	tok := fedFederatedToken(t, fake, r, aud)
	c := fedHTTP(fake, nil, nil, tls.VersionTLS12)
	gat := func(email string) string {
		return "https://" + fake.IAMAddr() + "/v1/projects/-/serviceAccounts/" + email + ":generateAccessToken"
	}
	body := string(kube.ImpersonationBody())
	for _, row := range []struct {
		name, target, bearer, body string
		code                       int
		status, as                 string
	}{
		{"no bearer", gat(fedSA), "", body, http.StatusUnauthorized, "UNAUTHENTICATED", ""},
		{"a bearer STS never issued", gat(fedSA), "kubetest-federated-0-0000000000000000", body, http.StatusUnauthorized, "UNAUTHENTICATED", "?"},
		{"a capitalised Scope key", gat(fedSA), tok, `{"Scope":["` + kube.ScopeCloudPlatform + `","` + kube.ScopeUserinfoEmail + `"],"lifetime":"3600s"}`, http.StatusBadRequest, "INVALID_ARGUMENT", r.id},
		{"a capitalised Lifetime key", gat(fedSA), tok, `{"scope":["` + kube.ScopeCloudPlatform + `","` + kube.ScopeUserinfoEmail + `"],"Lifetime":"3600s"}`, http.StatusBadRequest, "INVALID_ARGUMENT", r.id},
		{"delegates", gat(fedSA), tok, `{"delegates":[],"scope":["` + kube.ScopeCloudPlatform + `","` + kube.ScopeUserinfoEmail + `"],"lifetime":"3600s"}`, http.StatusBadRequest, "INVALID_ARGUMENT", r.id},
		{"no lifetime", gat(fedSA), tok, `{"scope":["` + kube.ScopeCloudPlatform + `","` + kube.ScopeUserinfoEmail + `"]}`, http.StatusBadRequest, "INVALID_ARGUMENT", r.id},
		{"a lifetime with no unit", gat(fedSA), tok, `{"scope":["` + kube.ScopeCloudPlatform + `","` + kube.ScopeUserinfoEmail + `"],"lifetime":"3600"}`, http.StatusBadRequest, "INVALID_ARGUMENT", r.id},
		{"the scopes reversed", gat(fedSA), tok, `{"scope":["` + kube.ScopeUserinfoEmail + `","` + kube.ScopeCloudPlatform + `"],"lifetime":"3600s"}`, http.StatusBadRequest, "INVALID_ARGUMENT", r.id},
		{"one scope", gat(fedSA), tok, `{"scope":["` + kube.ScopeCloudPlatform + `"],"lifetime":"3600s"}`, http.StatusBadRequest, "INVALID_ARGUMENT", r.id},
		{"not JSON", gat(fedSA), tok, `scope=x`, http.StatusBadRequest, "INVALID_ARGUMENT", r.id},
		{"an account the role is not bound to", gat(fedOtherSA), tok, body, http.StatusForbidden, "PERMISSION_DENIED", r.id},
		{"another path", "https://" + fake.IAMAddr() + "/v1/projects/-/serviceAccounts/" + fedSA, tok, body, http.StatusNotFound, "NOT_FOUND", r.id},
		{"the bound account", gat(fedSA), tok, body, http.StatusOK, "", r.id},
	} {
		before := len(fake.Requests())
		code, m := fedPost(t, c, row.target, "application/json", row.bearer, row.body)
		if code != row.code || googleStatus(m) != row.status {
			t.Errorf("%s: %d %q, want %d %q", row.name, code, googleStatus(m), row.code, row.status)
		}
		reqs := fake.Requests()
		if len(reqs) != before+1 || reqs[len(reqs)-1].As != row.as || reqs[len(reqs)-1].Server != "iam" {
			t.Errorf("%s: the request was not recorded, or not with the role it was authorised as", row.name)
		}
		if row.code == http.StatusOK {
			sa, _ := m["accessToken"].(string)
			exp, _ := m["expireTime"].(string)
			when, err := time.Parse(time.RFC3339Nano, exp)
			if !strings.HasPrefix(sa, "kubetest-sa-") || err != nil || time.Until(when) < 59*time.Minute || time.Until(when) > 61*time.Minute {
				t.Errorf("%s: accessToken prefix %v, expireTime %q", row.name, strings.HasPrefix(sa, "kubetest-sa-"), exp)
			}
		}
	}
}

// TestFakeFederationRecordsNoTokenValue: neither a federated nor a service
// account token, nor any Authorization value, is in what the fakes record;
// Authorization is recorded by name alone.
func TestFakeFederationRecordsNoTokenValue(t *testing.T) {
	fake := kubetest.NewFederation(t)
	r := newFedRole(t)
	aud := fedAddRole(t, fake, "provreader1", r, r.id)
	fake.Bind(r.id, fedSA)
	fedTok := fedFederatedToken(t, fake, r, aud)
	code, m := fedPost(t, fedHTTP(fake, nil, nil, tls.VersionTLS12),
		"https://"+fake.IAMAddr()+"/v1/projects/-/serviceAccounts/"+fedSA+":generateAccessToken", "application/json", fedTok, string(kube.ImpersonationBody()))
	saTok, _ := m["accessToken"].(string)
	if code != http.StatusOK || saTok == "" {
		t.Fatalf("the impersonation answered %d", code)
	}
	if !strings.HasPrefix(fedTok, "kubetest-federated-") || len(fedTok) < len("kubetest-federated-1-")+16 {
		t.Errorf("the federated token is not kubetest-federated-<n>-<16 hex>")
	}
	reqs := fake.Requests()
	all := fmt.Sprintf("%#v %#v", reqs, fake.Handshakes())
	for name, v := range map[string]string{"the federated token": fedTok, "the service account token": saTok} {
		if strings.Contains(all, v) {
			t.Errorf("%s is in the record", name)
		}
	}
	last := reqs[len(reqs)-1]
	if !slices.Contains(last.Headers, "Authorization") || last.As != r.id {
		t.Errorf("the IAM request's headers %q and As do not show its bearer by name", last.Headers)
	}
}

// TestFakeSTSDrainsAFailedHandshake: a client that presents no certificate
// reads the server's "certificate required" alert every time, never a reset
// that overtook it: the failed connection is half-closed and drained before
// it is closed. And a failed handshake whose client bytes the server never
// read still ends with the server's FIN, never a reset, which holds the
// drain on a host where the race above never shows (spec v2 §5 row 67).
func TestFakeSTSDrainsAFailedHandshake(t *testing.T) {
	fake := kubetest.NewFederation(t)
	r := newFedRole(t)
	aud := fedAddRole(t, fake, "provreader1", r, r.id)
	body := fedForm(t, aud, r.leafDER, r.anchorDER).Encode()
	for i := range 100 {
		c := fedHTTP(fake, nil, nil, tls.VersionTLS13)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+fake.STSAddr()+kube.STSTokenPath, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := c.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Op != "remote error" || opErr.Err == nil || opErr.Err.Error() != "tls: certificate required" {
			t.Fatalf("attempt %d: %v; want remote error: tls: certificate required", i+1, err)
		}
	}
	if n := len(fake.Requests()); n != 0 {
		t.Errorf("%d requests reached the handler", n)
	}

	// Whether a reset overtakes the alert above is a race this host may never
	// lose, so the drain is also held where no race is left: a failed
	// handshake with bytes the server never read still queued must end with
	// the server's FIN, read as EOF. A connection closed at once with unread
	// bytes sends a reset instead, on every TCP stack, and the read fails.
	// 64 KiB that is not a TLS record is far more than the server reads
	// before its handshake fails on the first record's header.
	junk := []byte(strings.Repeat("G", 64<<10))
	for i := range 5 {
		conn, err := net.Dial("tcp", fake.STSAddr())
		if err != nil {
			t.Fatal(err)
		}
		_, werr := conn.Write(junk)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, rerr := io.Copy(io.Discard, conn)
		_ = conn.Close()
		if werr != nil || rerr != nil {
			t.Fatalf("unread bytes, attempt %d: write %v, read %v; want the server's FIN (EOF), not a reset", i+1, werr, rerr)
		}
	}
	if n := len(fake.Requests()) + len(handshakesAt(fake, "sts")); n != 0 {
		t.Errorf("%d requests or completed handshakes for connections that sent no TLS", n)
	}
}

// handshakesAt are the fake's recorded handshakes at one server.
func handshakesAt(fake *kubetest.Federation, server string) []kubetest.FederationHandshake {
	var out []kubetest.FederationHandshake
	for _, h := range fake.Handshakes() {
		if h.Server == server {
			out = append(out, h)
		}
	}
	return out
}

// TestFakeHandshakesAreRecordedWithoutARequest: a handshake is recorded by
// itself, with what it presented and its version, though no request follows.
func TestFakeHandshakesAreRecordedWithoutARequest(t *testing.T) {
	fake := kubetest.NewFederation(t)
	r := newFedRole(t)
	for _, c := range []struct {
		server, addr string
		chain        [][]byte
	}{
		{"sts", fake.STSAddr(), [][]byte{r.leafDER, r.anchorDER}},
		{"iam", fake.IAMAddr(), nil},
	} {
		tc := &tls.Config{RootCAs: fake.Roots(), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS13}
		if c.chain != nil {
			tc.Certificates = []tls.Certificate{{Certificate: c.chain, PrivateKey: r.leafKey}}
		}
		conn, err := tls.Dial("tcp", c.addr, tc)
		if err != nil {
			t.Fatalf("%s: %v", c.server, err)
		}
		var got []kubetest.FederationHandshake
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			got = nil
			for _, h := range fake.Handshakes() {
				if h.Server == c.server {
					got = append(got, h)
				}
			}
			if len(got) > 0 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		_ = conn.Close()
		if len(got) != 1 {
			t.Fatalf("%s: %d handshakes recorded, want 1", c.server, len(got))
		}
		if got[0].Version != tls.VersionTLS13 || len(got[0].PeerCertificates) != len(c.chain) {
			t.Errorf("%s: version %s, %d certificates; want TLS 1.3 and %d", c.server, tls.VersionName(got[0].Version), len(got[0].PeerCertificates), len(c.chain))
		}
		for i := range c.chain {
			if string(got[0].PeerCertificates[i]) != string(c.chain[i]) {
				t.Errorf("%s: certificate %d is not what was presented", c.server, i)
			}
		}
	}
	if n := len(fake.Requests()); n != 0 {
		t.Errorf("%d requests were recorded", n)
	}
}
