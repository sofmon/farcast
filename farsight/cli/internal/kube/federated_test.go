package kube

import (
	"bytes"
	"context"
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
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/auth"
)

// The planted markers the identity path's errors and formatting must never
// carry: a secret's stand-in, a service account's email, and a 32-hex ID.
const (
	fedSecretMarker = "SECRET-MARKER"
	fedEmail        = "reader-sa1@proj-01.iam.gserviceaccount.com"
	fedHexID        = "0123456789abcdef0123456789abcdef"
	fedAudience     = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pool1234/providers/prov1234"
)

// fedIdentity is a role's anchor and leaf to D2's shape, made with
// crypto/x509 here (kube's tests do not import devicekey), and the leaf's key.
type fedIdentity struct {
	anchorDER, leafDER []byte
	leaf               *x509.Certificate
	key                *ecdsa.PrivateKey
}

func newFedIdentity(t *testing.T, cn string) fedIdentity {
	t.Helper()
	anchorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := anchorKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	skid := sha256.Sum256(pub)
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	anchorT := &x509.Certificate{
		SerialNumber:          fedSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(390 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId:          skid[:20],
	}
	anchorDER, err := x509.CreateCertificate(rand.Reader, anchorT, anchorT, &anchorKey.PublicKey, anchorKey)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := x509.ParseCertificate(anchorDER)
	if err != nil {
		t.Fatal(err)
	}
	leafT := &x509.Certificate{
		SerialNumber:          fedSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(90 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		AuthorityKeyId:        anchor.SubjectKeyId,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafT, anchor, &leafKey.PublicKey, anchorKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return fedIdentity{anchorDER: anchorDER, leafDER: leafDER, leaf: leaf, key: leafKey}
}

func fedSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return n.Add(n, big.NewInt(1))
}

// fedPool is a pool holding testCAPEM's one CA, for constructors that need
// roots and never dial.
func fedPool(t *testing.T) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(testCAPEM()) {
		t.Fatal("testCAPEM holds no certificate")
	}
	return p
}

// fedErrorTree is every error err's Unwrap reaches, err first.
func fedErrorTree(err error) []error {
	var out []error
	var walk func(error)
	walk = func(e error) {
		if e == nil {
			return
		}
		out = append(out, e)
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			for _, x := range u.Unwrap() {
				walk(x)
			}
		case interface{ Unwrap() error }:
			walk(u.Unwrap())
		}
	}
	walk(err)
	return out
}

// fedSentinels are the sentinels a federation error may unwrap to.
var fedSentinels = map[string]error{
	"ErrTokenRefused":      ErrTokenRefused,
	"ErrUnreachable":       ErrUnreachable,
	"ErrUnreadable":        ErrUnreadable,
	"ErrCredentialInvalid": ErrCredentialInvalid,
	"ErrEndpointRefused":   ErrEndpointRefused,
	"ErrUnsafeEnvironment": ErrUnsafeEnvironment,
	"ErrIAMRefused":        ErrIAMRefused,
}

// TestFederatedFixedValues pins the identity path's fixed values (spec v2
// §2.2): a change to any is a change to what Google is sent.
func TestFederatedFixedValues(t *testing.T) {
	form, _, err := exchangeRequestForm(NewExchangeRequest(fedAudience, ClientIdentity{}, [][]byte{newFedIdentity(t, fedHexID).leafDER}, nil))
	if err != nil {
		t.Fatal(err)
	}
	sent, err := url.ParseQuery(form)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, got, want string }{
		{"the STS token URL", "https://" + STSMTLSHost + STSTokenPath, "https://sts.mtls.googleapis.com/v1/token"},
		{"IAMCredentialsHost", IAMCredentialsHost, "iamcredentials.googleapis.com"},
		{"GrantTypeTokenExchange", GrantTypeTokenExchange, "urn:ietf:params:oauth:grant-type:token-exchange"},
		{"TokenTypeAccessToken", TokenTypeAccessToken, "urn:ietf:params:oauth:token-type:access_token"},
		{"TokenTypeMTLS", TokenTypeMTLS, "urn:ietf:params:oauth:token-type:mtls"},
		{"ImpersonationLifetime", ImpersonationLifetime.String(), "1h0m0s"},
		{"ImpersonationLifetime as sent", impersonationLifetimeText(), "3600s"},
		{"the exchange's default scopes", sent.Get("scope"), "https://www.googleapis.com/auth/cloud-platform"},
		{"maxFederationAnswer", strconv.Itoa(maxFederationAnswer), "65536"},
		{"maxFederatedToken", strconv.Itoa(maxFederatedToken), "12288"},
		{"maxServiceAccountToken", strconv.Itoa(maxServiceAccountToken), "8192"},
		{"federationTimeout", federationTimeout.String(), "30s"},
		{"exchangeMinTLS", tls.VersionName(exchangeMinTLS), "TLS 1.3"},
		{"UserAgent", UserAgent, "farcast"},
		{"IAMHost", IAMHost, "iam.googleapis.com"},
		{"ScopeDevstorageFullControl", ScopeDevstorageFullControl, "https://www.googleapis.com/auth/devstorage.full_control"},
		{"ScopesCluster", strings.Join(ScopesCluster.List(), " "), "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email"},
		{"ScopesStorage", strings.Join(ScopesStorage.List(), " "), "https://www.googleapis.com/auth/devstorage.full_control"},
		{"ScopesRegistry", strings.Join(ScopesRegistry.List(), " "), "https://www.googleapis.com/auth/cloud-platform"},
		{"the IAM reader's scopes", strings.Join(scopesIAM.List(), " "), "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email"},
		{"the provider list's query", providerListQuery, "pageSize=10&showDeleted=true"},
		{"maxProviderAnswer", strconv.Itoa(maxProviderAnswer), "1048576"},
		{"maxProviderPages", strconv.Itoa(maxProviderPages), "50"},
		{"maxPageToken", strconv.Itoa(maxPageToken), "4096"},
		{"federatedEarlyExpiry", federatedEarlyExpiry.String(), "3m45s"},
		{"the IAM reader's paths", providersPath("123456789012", "pool1234") + "/prov1234",
			"/v1/projects/123456789012/locations/global/workloadIdentityPools/pool1234/providers/prov1234"},
		{"StepProviderGet", string(StepProviderGet), "provider get"},
		{"StepProviderList", string(StepProviderList), "provider list"},
		{"ErrIAMRefused", ErrIAMRefused.Error(), "kube: IAM refused a read"},
		{"RoleTokens' fixed text", roleTokensText, "role tokens (not printed)"},
		{"IAMReader's fixed text", iamReaderText, "IAM reader (not printed)"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if exchangeMinTLS != tls.VersionTLS13 {
		t.Errorf("exchangeMinTLS = %#x, want TLS 1.3", exchangeMinTLS)
	}
	// The closed list: every value outside it lists nothing, and each list is
	// a fresh slice.
	for _, s := range []Scopes{0, scopesIAM + 1, 255} {
		if l := s.List(); l != nil {
			t.Errorf("Scopes(%d).List() = %q, want nil", s, l)
		}
	}
	for _, s := range []Scopes{ScopesCluster, ScopesStorage, ScopesRegistry, scopesIAM} {
		a := s.List()
		want := a[0]
		a[0] = "changed"
		if got := s.List()[0]; got != want {
			t.Errorf("Scopes(%d).List hands out a shared slice: %q after a caller's edit", s, got)
		}
	}
	if ScopesCluster != 1 || ScopesStorage != 2 || ScopesRegistry != 3 || scopesIAM != 4 {
		t.Errorf("the Scopes values moved: %d %d %d %d", ScopesCluster, ScopesStorage, ScopesRegistry, scopesIAM)
	}
}

// TestNewFederationRefusesUnderHTTP2Debug: while GODEBUG has turned on Go's
// HTTP/2 logging, which would print the bearer, NewFederation (and the test
// constructor) refuses first, with UnsafeEnvironment's whole text.
func TestNewFederationRefusesUnderHTTP2Debug(t *testing.T) {
	saved := http2Verbose
	t.Cleanup(func() { http2Verbose = saved })
	http2Verbose = true
	for name, build := range map[string]func() (*Federation, error){
		"NewFederation": NewFederation,
		"NewLoopbackFederation": func() (*Federation, error) {
			return NewLoopbackFederation("127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3", fedPool(t))
		},
		"NewLoopbackFederation with no roots": func() (*Federation, error) {
			return NewLoopbackFederation("127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3", nil)
		},
		"NewLoopbackFederation off the machine": func() (*Federation, error) {
			return NewLoopbackFederation("192.0.2.1:443", "127.0.0.1:2", "127.0.0.1:3", fedPool(t))
		},
	} {
		f, err := build()
		if f != nil || !errors.Is(err, ErrUnsafeEnvironment) || err.Error() != msgHTTP2Debug {
			t.Errorf("%s under http2debug: %v, %v; want nil and the GODEBUG refusal", name, f, err)
		}
	}
	http2Verbose = false
	if f, err := NewFederation(); f == nil || err != nil {
		t.Errorf("without the logging: %v, %v", f, err)
	}
}

// TestNewFederationURLsAreTheConstants: whatever the environment says, the
// product constructor's hosts are the constants, verified on the system
// roots under their own names, and nothing pins a dial. federated.go reads no
// environment variable and no file at all.
func TestNewFederationURLsAreTheConstants(t *testing.T) {
	for _, v := range []string{
		"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "https_proxy", "http_proxy",
		"SSL_CERT_FILE", "SSL_CERT_DIR",
		"GOOGLE_API_USE_CLIENT_CERTIFICATE", "GOOGLE_API_CERTIFICATE_CONFIG",
		"GOOGLE_CLOUD_UNIVERSE_DOMAIN", "GOOGLE_API_GO_EXPERIMENTAL_ENABLE_NEW_AUTH_LIB",
		"STS_ENDPOINT", "STS_HOST", "GOOGLE_STS_ENDPOINT", "IAM_CREDENTIALS_ENDPOINT",
		"CLOUDSDK_API_ENDPOINT_OVERRIDES_STS", "CLOUDSDK_API_ENDPOINT_OVERRIDES_IAMCREDENTIALS",
		"CLOUDSDK_API_ENDPOINT_OVERRIDES_IAM", "IAM_ENDPOINT", "GOOGLE_IAM_ENDPOINT",
	} {
		t.Setenv(v, "https://192.0.2.1:8443")
	}
	f, err := NewFederation()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []struct {
		name string
		got  federationHost
		host string
	}{{"STS", f.sts, STSMTLSHost}, {"IAM Credentials", f.iam, IAMCredentialsHost}, {"IAM's API", f.iamAPI, IAMHost}} {
		want := federationHost{origin: "https://" + h.host, host: h.host, serverName: h.host}
		if h.got != want {
			t.Errorf("%s host = %+v, want %+v", h.name, h.got, want)
		}
	}
	if f.mode != ModeGoogle {
		t.Errorf("NewFederation's mode = %s, want Google", f.mode)
	}
	// A key's token source mints at GoogleTokenURL whatever the key file
	// names; one naming another is refused (TestTokenSourceForRefusesBeforeSending).
	if got := (Endpoint{Mode: ModeGoogle}).TokenURL(); got != GoogleTokenURL {
		t.Errorf("a key's token source mints at %q", got)
	}

	for _, name := range fedProductFiles {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "Getenv", "LookupEnv", "Environ", "ReadFile", "Open", "OpenFile", "ReadDir", "Args":
					t.Errorf("%s names %s at %s: it reads no environment, file or argument", name, sel.Sel.Name, fset.Position(sel.Pos()))
				}
			}
			return true
		})
		for _, imp := range file.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "os" || p == "flag" {
				t.Errorf("%s imports %s", name, p)
			}
		}
	}
}

// fedProductFiles are the identity path's product files: the wire code, the
// federated credential, the role token source and the IAM reader. Each reads
// no environment, file or argument, and holds no init-time state.
var fedProductFiles = []string{"federated.go", "credential.go", "tokensource.go", "iamread.go"}

// fedTransports are a Federation's two inner transports for one exchange:
// the exchange's (built for id) and the shared impersonation one.
func fedTransports(t *testing.T, f *Federation, id ClientIdentity, leaf *x509.Certificate) (*http.Client, *identityTransport, *http.Transport, *identityTransport, *http.Transport) {
	t.Helper()
	hc, tr := f.exchangeClient(id, leaf)
	ex, ok := hc.Transport.(*identityTransport)
	if !ok {
		t.Fatalf("the exchange client's transport is %T", hc.Transport)
	}
	if ex.inner != http.RoundTripper(tr) {
		t.Fatal("the exchange client's identityTransport does not wrap the transport returned with it")
	}
	im, ok := f.impersonation.Transport.(*identityTransport)
	if !ok {
		t.Fatalf("the impersonation client's transport is %T", f.impersonation.Transport)
	}
	imTr, ok := im.inner.(*http.Transport)
	if !ok {
		t.Fatalf("the impersonation transport's inner is %T", im.inner)
	}
	return hc, ex, tr, im, imTr
}

// TestFederationTransportsHaveNoProxy holds §2.4's two transport shapes,
// structurally: a loopback wire test cannot see a proxy, because
// ProxyFromEnvironment never proxies a loopback host and reads the
// environment once per process.
func TestFederationTransportsHaveNoProxy(t *testing.T) {
	google, err := NewFederation()
	if err != nil {
		t.Fatal(err)
	}
	roots := fedPool(t)
	loop, err := NewLoopbackFederation("127.0.0.1:7001", "127.0.0.1:7002", "[::1]:7003", roots)
	if err != nil {
		t.Fatal(err)
	}
	// The proxy variables are set: a transport built from the environment
	// would carry a Proxy, and no transport here may.
	for _, v := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy"} {
		t.Setenv(v, "http://192.0.2.1:3128")
	}
	id := newFedIdentity(t, fedHexID)
	ci := NewClientIdentity([][]byte{id.leafDER, id.anchorDER}, id.key)
	for _, m := range []struct {
		name             string
		f                *Federation
		roots            *x509.CertPool
		sts, iam, iamAPI string // ServerName
	}{
		{"Google", google, nil, STSMTLSHost, IAMCredentialsHost, IAMHost},
		{"loopback", loop, roots, "127.0.0.1", "127.0.0.1", "::1"},
	} {
		t.Run(m.name, func(t *testing.T) {
			hc, ex, tr, im, imTr := fedTransports(t, m.f, ci, id.leaf)
			ac := m.f.iamAPIClient()
			api, ok := ac.Transport.(*identityTransport)
			if !ok {
				t.Fatalf("the IAM API client's transport is %T", ac.Transport)
			}
			apiTr, ok := api.inner.(*http.Transport)
			if !ok {
				t.Fatalf("the IAM API transport's inner is %T", api.inner)
			}
			if tr == imTr || apiTr == imTr || apiTr == tr {
				t.Fatal("two of the identity clients share one transport")
			}
			if _, tr2 := m.f.exchangeClient(ci, id.leaf); tr2 == tr {
				t.Error("two exchanges share one transport")
			}
			if ex.bearer != noBearer || im.bearer != federatedBearer || api.bearer != serviceAccountBearer {
				t.Errorf("bearer: exchange %v, impersonation %v, IAM API %v; want none, the federated token, the service account's", ex.bearer, im.bearer, api.bearer)
			}
			if ex.host != m.f.sts.host || im.host != m.f.iam.host || api.host != m.f.iamAPI.host {
				t.Errorf("hosts: exchange %q, impersonation %q, IAM API %q", ex.host, im.host, api.host)
			}
			for _, s := range []struct {
				name       string
				tr         *http.Transport
				min        uint16
				serverName string
			}{{"exchange", tr, tls.VersionTLS13, m.sts}, {"impersonation", imTr, tls.VersionTLS12, m.iam}, {"IAM API", apiTr, tls.VersionTLS12, m.iamAPI}} {
				if s.tr.Proxy != nil {
					t.Errorf("%s: Proxy is set; it must be nil so no proxy variable routes the identity path", s.name)
				}
				if s.tr.DialContext == nil {
					t.Errorf("%s: no dialer of its own", s.name)
				}
				tc := s.tr.TLSClientConfig
				if tc == nil {
					t.Fatalf("%s: no TLS config", s.name)
				}
				if tc.MinVersion != s.min {
					t.Errorf("%s: MinVersion = %s, want %s", s.name, tls.VersionName(tc.MinVersion), tls.VersionName(s.min))
				}
				if tc.RootCAs != m.roots {
					t.Errorf("%s: RootCAs is not the constructed roots (nil, the system's, in Google mode)", s.name)
				}
				if tc.ServerName != s.serverName {
					t.Errorf("%s: ServerName = %q, want %q", s.name, tc.ServerName, s.serverName)
				}
				if tc.InsecureSkipVerify || tc.VerifyPeerCertificate != nil || tc.VerifyConnection != nil || tc.KeyLogWriter != nil || tc.ClientSessionCache != nil {
					t.Errorf("%s: the TLS config skips or replaces verification, logs keys or caches sessions", s.name)
				}
				if tc.Certificates != nil {
					t.Errorf("%s: Certificates is set; the exchange presents through GetClientCertificate alone", s.name)
				}
				if s.tr.TLSHandshakeTimeout != 10*time.Second || s.tr.ResponseHeaderTimeout != 30*time.Second || s.tr.MaxResponseHeaderBytes != 64<<10 {
					t.Errorf("%s: handshake %s, header %s, header bytes %d", s.name, s.tr.TLSHandshakeTimeout, s.tr.ResponseHeaderTimeout, s.tr.MaxResponseHeaderBytes)
				}
			}
			// The exchange: HTTP/1.1 alone, no keep-alive, the identity's
			// certificate through GetClientCertificate.
			tc := tr.TLSClientConfig
			if tc.GetClientCertificate == nil {
				t.Fatal("the exchange has no GetClientCertificate")
			}
			cert, err := tc.GetClientCertificate(&tls.CertificateRequestInfo{AcceptableCAs: [][]byte{[]byte("unrelated")}})
			if err != nil || len(cert.Certificate) != 2 || !bytes.Equal(cert.Certificate[0], id.leafDER) || cert.PrivateKey != crypto.PrivateKey(id.key) {
				t.Errorf("GetClientCertificate = %v, %v; want the identity's chain and key, whatever CAs are acceptable", cert != nil, err)
			}
			if !slices.Equal(tc.NextProtos, []string{"http/1.1"}) || tr.TLSNextProto == nil || len(tr.TLSNextProto) != 0 || tr.ForceAttemptHTTP2 || !tr.DisableKeepAlives {
				t.Errorf("exchange: NextProtos %q, TLSNextProto %v, ForceAttemptHTTP2 %v, DisableKeepAlives %v; want HTTP/1.1 alone, no keep-alive",
					tc.NextProtos, tr.TLSNextProto, tr.ForceAttemptHTTP2, tr.DisableKeepAlives)
			}
			if _, none := m.f.exchangeClient(ClientIdentity{}, nil); none.TLSClientConfig.GetClientCertificate != nil {
				t.Error("an exchange with no identity still has GetClientCertificate")
			}
			// Impersonation and IAM's API: no certificate of any kind.
			for name, tr := range map[string]*http.Transport{"impersonation": imTr, "IAM API": apiTr} {
				itc := tr.TLSClientConfig
				if itc.GetClientCertificate != nil || itc.Certificates != nil || itc.NextProtos != nil {
					t.Errorf("the %s transport can present a certificate or overrides NextProtos", name)
				}
				if !tr.ForceAttemptHTTP2 || tr.DisableKeepAlives || tr.MaxIdleConnsPerHost != 2 || tr.IdleConnTimeout != 90*time.Second || tr.TLSNextProto != nil {
					t.Errorf("%s: %+v is not §2.4's shape", name, tr)
				}
			}
			for name, c := range map[string]*http.Client{"exchange": hc, "impersonation": m.f.impersonation, "IAM API": ac} {
				if c.CheckRedirect == nil || !errors.Is(c.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
					t.Errorf("the %s client follows redirects", name)
				}
				if c.Timeout != 30*time.Second {
					t.Errorf("the %s client's Timeout = %s, want 30s", name, c.Timeout)
				}
			}
		})
	}
}

// TestIdentityTransportSendsOnlyToItsHost: each identity transport refuses,
// before its inner RoundTripper sees anything, every request that is not
// https to its own host exactly.
func TestIdentityTransportSendsOnlyToItsHost(t *testing.T) {
	f, err := NewFederation()
	if err != nil {
		t.Fatal(err)
	}
	hc, _ := f.exchangeClient(ClientIdentity{}, nil)
	hosts := []string{STSMTLSHost, IAMCredentialsHost, IAMHost}
	for _, side := range []struct {
		name string
		it   identityTransport
		host string
	}{
		{"exchange", *hc.Transport.(*identityTransport), STSMTLSHost},
		{"impersonation", *f.impersonation.Transport.(*identityTransport), IAMCredentialsHost},
		{"IAM API", *f.iamAPIClient().Transport.(*identityTransport), IAMHost},
	} {
		t.Run(side.name, func(t *testing.T) {
			rec := &recordingRoundTripper{}
			side.it.inner = rec
			ctx := withServiceAccountBearer(withFederatedBearer(context.Background(), &auth.Token{Value: "federated-marker"}), "sa-marker")
			targets := []string{
				"https://evil.example/v1/token",
				"https://oauth2.googleapis.com/token",
				"https://iam.mtls.googleapis.com/v1/token",
				"https://iamcredentials.mtls.googleapis.com/v1/token",
			}
			for _, other := range hosts {
				if other != side.host {
					targets = append(targets, "https://"+other+"/v1/token")
				}
			}
			for _, target := range append(targets,
				"http://"+side.host+"/v1/token",
				"https://"+side.host+":8443/v1/token",
				"https://"+side.host+":443/v1/token",
				"https://"+side.host+"@evil.example/v1/token",
				"https://"+side.host+"./v1/token",
				"https://"+strings.ToUpper(side.host)+"/v1/token",
			) {
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader("x"))
				if err != nil {
					t.Fatal(err)
				}
				resp, err := side.it.RoundTrip(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
				if !errors.Is(err, ErrEndpointRefused) || err.Error() != msgFederationHost {
					t.Errorf("%s: %v; want the host guard's refusal", target, err)
				}
			}
			if len(rec.reqs) != 0 {
				t.Fatalf("%d requests reached the inner transport for other hosts", len(rec.reqs))
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+side.host+"/v1/token", strings.NewReader("x"))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := side.it.RoundTrip(req)
			if err != nil {
				t.Fatalf("the pinned host: %v", err)
			}
			_ = resp.Body.Close()
			if len(rec.reqs) != 1 {
				t.Errorf("the pinned host: %d requests reached the inner transport, want 1", len(rec.reqs))
			}
		})
	}
}

// fedSend sends one request through it with the caller's headers h, and
// returns what reached its inner recorder.
func fedSend(t *testing.T, it identityTransport, ctx context.Context, target string, h http.Header) (*http.Request, *http.Request) {
	t.Helper()
	rec := &recordingRoundTripper{}
	it.inner = rec
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header = h.Clone()
	resp, err := it.RoundTrip(req)
	if err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	_ = resp.Body.Close()
	if len(rec.reqs) != 1 {
		t.Fatalf("%s: %d requests reached the inner transport", target, len(rec.reqs))
	}
	return req, rec.reqs[0]
}

func fedHeaderNames(h http.Header) []string {
	var names []string
	for k := range h {
		names = append(names, k)
	}
	slices.Sort(names)
	return names
}

// TestBearerOnlyToIAMCredentialsHost is TestAuthorizationOnlyToTheEndpointHost
// for the identity path (R1): the impersonation transport sends the
// federated bearer, and only over https to its own host; IAM's API transport
// sends the service account's bearer, and only over https to IAMHost; the
// exchange transport never sends one; no transport sends another's token;
// no caller header but an allowed Content-Type survives.
func TestBearerOnlyToIAMCredentialsHost(t *testing.T) {
	f, err := NewFederation()
	if err != nil {
		t.Fatal(err)
	}
	im := *f.impersonation.Transport.(*identityTransport)
	hc, _ := f.exchangeClient(ClientIdentity{}, nil)
	ex := *hc.Transport.(*identityTransport)
	fed := &auth.Token{Value: "federated-marker", Type: "Bearer"}
	cluster := &auth.Token{Value: "cluster-marker", Type: "Bearer"}
	callerHeaders := func(contentType string) http.Header {
		return http.Header{
			"Authorization":       {"Bearer set-by-the-caller"},
			"X-Goog-Api-Client":   {"gl-go/1.27.4 gdcl/0.1"},
			"X-Goog-User-Project": {"proj-01"},
			"Cookie":              {"session=caller"},
			"Accept":              {"text/html"},
			"User-Agent":          {"Go-http-client/1.1"},
			"Content-Type":        {contentType},
		}
	}
	gat := "https://" + IAMCredentialsHost + "/v1/projects/-/serviceAccounts/" + fedEmail + ":generateAccessToken"

	// The impersonation transport, with the federated bearer.
	ctx := withFederatedBearer(withBearer(context.Background(), cluster), fed)
	orig, sent := fedSend(t, im, ctx, gat, callerHeaders(mediaJSON))
	if got := sent.Header.Get("Authorization"); got != "Bearer federated-marker" {
		t.Errorf("impersonation: Authorization = %q, want the federated bearer", got)
	}
	if got := fedHeaderNames(sent.Header); !slices.Equal(got, []string{"Accept", "Authorization", "Content-Type", "User-Agent"}) {
		t.Errorf("impersonation: header names %q, want exactly Accept, Authorization, Content-Type and User-Agent", got)
	}
	if sent.Header.Get("User-Agent") != "farcast" || sent.Header.Get("Accept") != "application/json" || sent.Header.Get("Content-Type") != "application/json" {
		t.Errorf("impersonation: User-Agent %q, Accept %q, Content-Type %q", sent.Header.Get("User-Agent"), sent.Header.Get("Accept"), sent.Header.Get("Content-Type"))
	}
	if orig.Header.Get("Authorization") != "Bearer set-by-the-caller" || orig.Header.Get("X-Goog-Api-Client") == "" || orig.Header.Get("Cookie") == "" {
		t.Error("the RoundTripper changed its caller's request")
	}
	if sent.Host != "" {
		t.Errorf("impersonation: the request names Host %q apart from its URL", sent.Host)
	}

	// A Content-Type that is neither the form's nor JSON's is dropped.
	_, sent = fedSend(t, im, ctx, gat, callerHeaders("text/plain"))
	if got := fedHeaderNames(sent.Header); !slices.Equal(got, []string{"Accept", "Authorization", "User-Agent"}) {
		t.Errorf("impersonation with text/plain: header names %q", got)
	}

	// Without a federated bearer, nothing; a cluster bearer is not one.
	_, sent = fedSend(t, im, withBearer(context.Background(), cluster), gat, callerHeaders(mediaJSON))
	if got := sent.Header.Get("Authorization"); got != "" {
		t.Errorf("impersonation with no federated bearer: Authorization = %q", got)
	}
	if got := fedHeaderNames(sent.Header); !slices.Equal(got, []string{"Accept", "Content-Type", "User-Agent"}) {
		t.Errorf("impersonation with no bearer: header names %q", got)
	}

	// Another host, or plain http, never gets it: the guard refuses first.
	for _, target := range []string{
		"http://" + IAMCredentialsHost + "/v1/projects/-/serviceAccounts/" + fedEmail + ":generateAccessToken",
		"https://" + STSMTLSHost + STSTokenPath,
		"https://iam.googleapis.com/v1/projects/p/locations/global/workloadIdentityPools/pool1234",
		"https://evil.example/collect",
	} {
		rec := &recordingRoundTripper{}
		it := im
		it.inner = rec
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader("{}"))
		if _, err := it.RoundTrip(req); !errors.Is(err, ErrEndpointRefused) || len(rec.reqs) != 0 {
			t.Errorf("impersonation to %s: %v, %d sent; want the guard's refusal and nothing sent", target, err, len(rec.reqs))
		}
	}

	// The exchange transport never sends one, whatever the context carries.
	orig, sent = fedSend(t, ex, ctx, "https://"+STSMTLSHost+STSTokenPath, callerHeaders(mediaForm))
	if got := sent.Header.Get("Authorization"); got != "" {
		t.Errorf("exchange: Authorization = %q; the exchange transport never sends one", got)
	}
	if got := fedHeaderNames(sent.Header); !slices.Equal(got, []string{"Accept", "Content-Type", "User-Agent"}) {
		t.Errorf("exchange: header names %q, want exactly Accept, Content-Type and User-Agent", got)
	}
	if sent.Header.Get("User-Agent") != "farcast" || sent.Header.Get("Content-Type") != mediaForm {
		t.Errorf("exchange: User-Agent %q, Content-Type %q", sent.Header.Get("User-Agent"), sent.Header.Get("Content-Type"))
	}
	if orig.Header.Get("Authorization") != "Bearer set-by-the-caller" {
		t.Error("the exchange RoundTripper changed its caller's request")
	}

	// The service account's bearer: IAM's API transport alone sends it, and
	// only to IAMHost; neither other transport sends it.
	api := *f.iamAPIClient().Transport.(*identityTransport)
	saCtx := withServiceAccountBearer(ctx, "sa-marker")
	read := "https://" + IAMHost + "/v1/projects/123456789012/locations/global/workloadIdentityPools/pool1234/providers"
	orig, sent = fedSend(t, api, saCtx, read, callerHeaders(""))
	if got := sent.Header.Get("Authorization"); got != "Bearer sa-marker" {
		t.Errorf("IAM API: Authorization = %q, want the service account's bearer", got)
	}
	if got := fedHeaderNames(sent.Header); !slices.Equal(got, []string{"Accept", "Authorization", "User-Agent"}) {
		t.Errorf("IAM API: header names %q, want exactly Accept, Authorization and User-Agent", got)
	}
	if sent.Header.Get("User-Agent") != "farcast" || sent.Header.Get("Accept") != "application/json" {
		t.Errorf("IAM API: User-Agent %q, Accept %q", sent.Header.Get("User-Agent"), sent.Header.Get("Accept"))
	}
	if orig.Header.Get("Authorization") != "Bearer set-by-the-caller" {
		t.Error("the IAM API RoundTripper changed its caller's request")
	}
	// Without the service account's token, IAM's API gets none: neither the
	// federated token nor the cluster's is one.
	_, sent = fedSend(t, api, ctx, read, callerHeaders(""))
	if got := sent.Header.Get("Authorization"); got != "" {
		t.Errorf("IAM API with a federated and a cluster bearer only: Authorization = %q", got)
	}
	for name, it := range map[string]identityTransport{"impersonation": im, "exchange": ex} {
		target := gat
		if name == "exchange" {
			target = "https://" + STSMTLSHost + STSTokenPath
		}
		_, sent = fedSend(t, it, withServiceAccountBearer(context.Background(), "sa-marker"), target, http.Header{})
		if got := sent.Header.Get("Authorization"); got != "" {
			t.Errorf("the %s transport sent the service account's bearer: %q", name, got)
		}
	}
	for _, target := range []string{
		"http://" + IAMHost + "/v1/projects/123456789012/locations/global/workloadIdentityPools/pool1234/providers",
		"https://" + IAMCredentialsHost + "/v1/projects/-/serviceAccounts/" + fedEmail + ":generateAccessToken",
		"https://" + STSMTLSHost + STSTokenPath,
		"https://iam.mtls.googleapis.com/v1/projects/123456789012/locations/global/workloadIdentityPools/pool1234/providers",
		"https://evil.example/collect",
	} {
		rec := &recordingRoundTripper{}
		it := api
		it.inner = rec
		req, _ := http.NewRequestWithContext(saCtx, http.MethodGet, target, nil)
		if _, err := it.RoundTrip(req); !errors.Is(err, ErrEndpointRefused) || len(rec.reqs) != 0 {
			t.Errorf("IAM API to %s: %v, %d sent; want the guard's refusal and nothing sent", target, err, len(rec.reqs))
		}
	}
}

// TestTheTwoBearerKeysDoNotCross: the cluster's bearer key, the federated
// one and IAM's API's are distinct, so the impersonation transport never
// sends a cluster token and the API transport never sends a federated or an
// IAM API one.
func TestTheTwoBearerKeysDoNotCross(t *testing.T) {
	f, err := NewFederation()
	if err != nil {
		t.Fatal(err)
	}
	im := *f.impersonation.Transport.(*identityTransport)
	gat := "https://" + IAMCredentialsHost + "/v1/projects/-/serviceAccounts/" + fedEmail + ":generateAccessToken"
	_, sent := fedSend(t, im, withBearer(context.Background(), &auth.Token{Value: "cluster-marker"}), gat, http.Header{})
	if got := sent.Header.Get("Authorization"); got != "" {
		t.Errorf("the impersonation transport sent the cluster bearer: %q", got)
	}

	ep, err := ParseEndpoint("127.0.0.1:6443", "", testCAPEM())
	if err != nil {
		t.Fatal(err)
	}
	c, err := newClient(Config{Endpoint: ep, Credential: Credential{Email: loopbackEmail}, Identity: Reader}, staticMint("unused"))
	if err != nil {
		t.Fatal(err)
	}
	at := *c.api.Transport.(*apiTransport)
	rec := &recordingRoundTripper{}
	at.inner = rec
	req, err := http.NewRequestWithContext(withServiceAccountBearer(withFederatedBearer(context.Background(), &auth.Token{Value: "federated-marker"}), "sa-marker"), http.MethodGet, ep.BaseURL()+"/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := at.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := rec.reqs[0].Header.Get("Authorization"); got != "" {
		t.Errorf("the API transport sent the federated or the IAM API's bearer: %q", got)
	}
}

// TestSubjectTokenEncoding: the subject token is a compact JSON array of
// padded standard base64, the leaf first, and nothing that is not a
// certificate gets in.
func TestSubjectTokenEncoding(t *testing.T) {
	id := newFedIdentity(t, fedHexID)
	leaf, anchor := id.leafDER, id.anchorDER
	want := `["` + base64.StdEncoding.EncodeToString(leaf) + `","` + base64.StdEncoding.EncodeToString(anchor) + `"]`
	if !strings.ContainsAny(want, "+/=") {
		t.Fatal("neither certificate's standard base64 holds +, / or =, so this draw cannot tell the alphabets apart; run again")
	}
	got, err := SubjectToken([][]byte{leaf, anchor})
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("SubjectToken = %s\nwant %s", got, want)
	}
	marshalled, err := json.Marshal([]string{base64.StdEncoding.EncodeToString(leaf), base64.StdEncoding.EncodeToString(anchor)})
	if err != nil {
		t.Fatal(err)
	}
	if got != string(marshalled) {
		t.Errorf("SubjectToken differs from json.Marshal of the base64 strings")
	}
	if one, err := SubjectToken([][]byte{leaf}); err != nil || one != `["`+base64.StdEncoding.EncodeToString(leaf)+`"]` {
		t.Errorf("SubjectToken of the leaf alone = %s, %v", one, err)
	}
	for name, chain := range map[string][][]byte{
		"nil":                  nil,
		"empty":                {},
		"not a certificate":    {[]byte("not a certificate")},
		"a second that is not": {leaf, []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
	} {
		if s, err := SubjectToken(chain); s != "" || !errors.Is(err, ErrCredentialInvalid) || err.Error() != fmt.Sprintf(msgFederationRequest, "subject token") {
			t.Errorf("%s: %q, %v; want the subject-token refusal", name, s, err)
		}
	}
}

// TestExchangeFormFields: the form has exactly six keys, each once; nil
// scopes in an exchange are cloud-platform alone; the subject token is
// TLS.Chain's unless Subject is set.
func TestExchangeFormFields(t *testing.T) {
	form := ExchangeForm("aud-value", TokenTypeMTLS, `["a+b/c="]`, []string{ScopeCloudPlatform, ScopeUserinfoEmail})
	v, err := url.ParseQuery(form)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"audience":             "aud-value",
		"grant_type":           GrantTypeTokenExchange,
		"requested_token_type": TokenTypeAccessToken,
		"subject_token_type":   TokenTypeMTLS,
		"subject_token":        `["a+b/c="]`,
		"scope":                ScopeCloudPlatform + " " + ScopeUserinfoEmail,
	}
	if len(v) != len(want) {
		t.Errorf("the form has %d keys %v, want six", len(v), fedHeaderNames(http.Header(v)))
	}
	for k, w := range want {
		if got := v[k]; len(got) != 1 || got[0] != w {
			t.Errorf("%s = %q, want exactly [%q]", k, got, w)
		}
	}

	a := newFedIdentity(t, fedHexID)
	b := newFedIdentity(t, fedHexID)
	tlsChain := NewClientIdentity([][]byte{a.leafDER, a.anchorDER}, a.key)
	for _, c := range []struct {
		name    string
		r       ExchangeRequest
		subject [][]byte
	}{
		{"nil scopes, the TLS chain", NewExchangeRequest(fedAudience, tlsChain, nil, nil), tlsChain.Chain()},
		{"empty scopes, a subject", NewExchangeRequest(fedAudience, ClientIdentity{}, [][]byte{b.leafDER}, []string{}), [][]byte{b.leafDER}},
		{"a subject beside a TLS chain", NewExchangeRequest(fedAudience, tlsChain, [][]byte{a.leafDER}, nil), [][]byte{a.leafDER}},
	} {
		form, _, err := exchangeRequestForm(c.r)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		v, err := url.ParseQuery(form)
		if err != nil {
			t.Fatal(err)
		}
		wantSubject, err := SubjectToken(c.subject)
		if err != nil {
			t.Fatal(err)
		}
		if v.Get("scope") != ScopeCloudPlatform {
			t.Errorf("%s: scope = %q, want cloud-platform alone (D5)", c.name, v.Get("scope"))
		}
		if v.Get("subject_token") != wantSubject || v.Get("subject_token_type") != TokenTypeMTLS || v.Get("audience") != fedAudience {
			t.Errorf("%s: subject_token, its type or the audience is not the request's", c.name)
		}
	}
}

// TestImpersonationBodyIsExact pins generateAccessToken's body for each
// consumer's scopes (N9), byte for byte, and nil outside the closed list.
func TestImpersonationBodyIsExact(t *testing.T) {
	for _, c := range []struct {
		name string
		s    Scopes
		want string
	}{
		{"ScopesCluster", ScopesCluster, `{"scope":["https://www.googleapis.com/auth/cloud-platform","https://www.googleapis.com/auth/userinfo.email"],"lifetime":"3600s"}`},
		{"ScopesStorage", ScopesStorage, `{"scope":["https://www.googleapis.com/auth/devstorage.full_control"],"lifetime":"3600s"}`},
		{"ScopesRegistry", ScopesRegistry, `{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}`},
		{"the IAM reader's", scopesIAM, `{"scope":["https://www.googleapis.com/auth/cloud-platform","https://www.googleapis.com/auth/userinfo.email"],"lifetime":"3600s"}`},
	} {
		got := ImpersonationBody(c.s)
		if string(got) != c.want {
			t.Errorf("ImpersonationBody(%s) = %s\nwant %s", c.name, got, c.want)
		}
		if !json.Valid(got) {
			t.Errorf("ImpersonationBody(%s) is not JSON", c.name)
		}
	}
	for _, s := range []Scopes{0, scopesIAM + 1, 255} {
		if got := ImpersonationBody(s); got != nil {
			t.Errorf("ImpersonationBody(%d) = %s, want nil", s, got)
		}
	}
}

// TestAudienceShapes: Audience takes a project number alone, and since
// M3b.3 so does Exchange's guard, which refuses the project-ID form M3a's I5
// sent; and every refusal names the part, never the value.
func TestAudienceShapes(t *testing.T) {
	got, err := Audience("123456789012", "pool1234", "prov1234")
	if err != nil || got != fedAudience {
		t.Fatalf("Audience = %q, %v; want %q", got, err, fedAudience)
	}
	if !checkAudience(fedAudience) {
		t.Error("checkAudience refuses the number form")
	}
	idForm := "//iam.googleapis.com/projects/my-project-1/locations/global/workloadIdentityPools/pool1234/providers/prov1234"
	if checkAudience(idForm) {
		t.Error("checkAudience admits the project-ID form I5 sends")
	}
	if _, err := Audience("my-project-1", "pool1234", "prov1234"); err == nil || err.Error() != fmt.Sprintf(msgFederationRequest, "audience (project number)") {
		t.Errorf("Audience took a project ID: %v", err)
	}

	type row struct{ name, value string }
	badIDs := []row{
		{"too short", "ab1"},
		{"too long", strings.Repeat("q", 33)},
		{"uppercase", "Qwerty12"},
		{"gcp- prefix", "gcp-qwerty"},
		{"a slash", "qwe/rty12"},
		{"a question mark", "qwe?rty12"},
		{"a newline", "qwerty12\n"},
		{"empty", ""},
		{"a dot", "qwe.rty12"},
	}
	for _, part := range []string{"pool", "provider"} {
		for _, r := range badIDs {
			pool, provider := "pool1234", "prov1234"
			if part == "pool" {
				pool = r.value
			} else {
				provider = r.value
			}
			_, err := Audience("123456789012", pool, provider)
			if !errors.Is(err, ErrCredentialInvalid) || err.Error() != fmt.Sprintf(msgFederationRequest, "audience ("+part+")") {
				t.Errorf("%s %s: %v; want the %s refusal", part, r.name, err, part)
			} else if r.value != "" && strings.Contains(err.Error(), r.value) {
				t.Errorf("%s %s: the refusal quotes the value", part, r.name)
			}
			aud := audiencePrefix + "123456789012" + audiencePools + pool + audienceProvider + provider
			if checkAudience(aud) {
				t.Errorf("checkAudience accepts a %s that is %s", part, r.name)
			}
		}
	}
	for _, r := range []row{{"empty", ""}, {"21 digits", strings.Repeat("1", 21)}, {"a letter", "12345a"}, {"a sign", "-12345"}} {
		if _, err := Audience(r.value, "pool1234", "prov1234"); err == nil || (r.value != "" && strings.Contains(err.Error(), r.value)) {
			t.Errorf("project number %s: %v", r.name, err)
		}
	}
	if _, err := Audience(strings.Repeat("9", 20), "pool1234", strings.Repeat("p", 32)); err != nil {
		t.Errorf("the longest number and provider: %v", err)
	}
	for _, aud := range []string{
		"",
		"https://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pool1234/providers/prov1234",
		"//iam.googleapis.com/projects/123456789012/locations/us/workloadIdentityPools/pool1234/providers/prov1234",
		fedAudience + "/x",
		fedAudience + "?x=1",
		"//iam.googleapis.com/projects/abc/locations/global/workloadIdentityPools/pool1234/providers/prov1234",
		"//iam.googleapis.com/projects/My-Project-1/locations/global/workloadIdentityPools/pool1234/providers/prov1234",
		"//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/pool1234",
		"//evil.example/projects/123456789012/locations/global/workloadIdentityPools/pool1234/providers/prov1234",
	} {
		if checkAudience(aud) {
			t.Errorf("checkAudience accepts %q", aud)
		}
	}
}

// TestGenerateAccessTokenPathShapes: the exact path for a service account's
// email, and a refusal that never quotes the input for anything else.
func TestGenerateAccessTokenPathShapes(t *testing.T) {
	got, err := GenerateAccessTokenPath(fedEmail)
	if err != nil || got != "/v1/projects/-/serviceAccounts/reader-sa1@proj-01.iam.gserviceaccount.com:generateAccessToken" {
		t.Fatalf("GenerateAccessTokenPath = %q, %v", got, err)
	}
	if _, err := GenerateAccessTokenPath(strings.Repeat("a", 30) + "@" + strings.Repeat("b", 30) + ".iam.gserviceaccount.com"); err != nil {
		t.Errorf("the longest parts: %v", err)
	}
	for _, email := range []string{
		"",
		"reader-sa1",
		"reader-sa1@@proj-01.iam.gserviceaccount.com",
		"reader-sa1@proj-01@x.iam.gserviceaccount.com",
		"Reader-sa1@proj-01.iam.gserviceaccount.com",
		"abcde@proj-01.iam.gserviceaccount.com",
		strings.Repeat("a", 31) + "@proj-01.iam.gserviceaccount.com",
		"reader-sa-@proj-01.iam.gserviceaccount.com",
		"1reader-sa@proj-01.iam.gserviceaccount.com",
		"reader-sa1@proj-01.example.com",
		"123-compute@developer.gserviceaccount.com",
		"reader-sa1@proj-01.iam.gserviceaccount.com\n",
		"reader-sa1@proj-01.iam.gserviceaccount.com/x",
		"../reader-sa1@proj-01.iam.gserviceaccount.com",
		"reader-sa1@proj-01.iam.gserviceaccount.com?x",
		"reader-sa1@proj.iam.gserviceaccount.com",
		"reader-sa1@proj-01.IAM.gserviceaccount.com",
	} {
		p, err := GenerateAccessTokenPath(email)
		if p != "" || !errors.Is(err, ErrCredentialInvalid) || err.Error() != fmt.Sprintf(msgFederationRequest, "service account") {
			t.Errorf("%q: %q, %v; want the service-account refusal", email, p, err)
			continue
		}
		if email != "" && strings.Contains(err.Error(), email) {
			t.Errorf("%q: the refusal quotes it", email)
		}
	}
}

// fedCounting is a Federation whose three hosts are one counting listener's
// address: a refusal before sending must leave it at zero.
func fedCounting(t *testing.T) (*Federation, *countingListener) {
	t.Helper()
	l, ok := listenCounting(t, "127.0.0.1")
	if !ok {
		t.Fatal("no IPv4 loopback")
	}
	addr := net.JoinHostPort("127.0.0.1", l.port())
	f, err := NewLoopbackFederation(addr, addr, addr, fedPool(t))
	if err != nil {
		t.Fatal(err)
	}
	return f, l
}

// TestExchangeRefusesBeforeSending: each malformed request is refused with
// msgFederationRequest's whole text and ErrCredentialInvalid, and nothing is
// dialled; a well-formed one, the control, does dial.
func TestExchangeRefusesBeforeSending(t *testing.T) {
	f, l := fedCounting(t)
	id := newFedIdentity(t, fedHexID)
	other := newFedIdentity(t, fedHexID)
	good := NewClientIdentity([][]byte{id.leafDER}, id.key)
	for _, c := range []struct {
		name, field string
		r           ExchangeRequest
	}{
		{"a mismatched signer", "client certificate", NewExchangeRequest(fedAudience, NewClientIdentity([][]byte{id.leafDER}, other.key), nil, nil)},
		{"an empty chain", "client certificate", NewExchangeRequest(fedAudience, NewClientIdentity(nil, id.key), [][]byte{id.leafDER}, nil)},
		{"a chain entry that does not parse", "client certificate", NewExchangeRequest(fedAudience, NewClientIdentity([][]byte{id.leafDER, []byte("x")}, id.key), nil, nil)},
		{"no signer", "client certificate", NewExchangeRequest(fedAudience, NewClientIdentity([][]byte{id.leafDER}, nil), nil, nil)},
		{"no TLS and no subject", "subject token", NewExchangeRequest(fedAudience, ClientIdentity{}, nil, nil)},
		{"a subject that does not parse", "subject token", NewExchangeRequest(fedAudience, ClientIdentity{}, [][]byte{[]byte("x")}, nil)},
		{"an empty subject", "subject token", NewExchangeRequest(fedAudience, ClientIdentity{}, [][]byte{}, nil)},
		{"a bad audience", "audience", NewExchangeRequest(fedAudience+"/x", good, nil, nil)},
		{"an empty audience", "audience", NewExchangeRequest("", good, nil, nil)},
		{"a scope off Google's prefix", "scope", NewExchangeRequest(fedAudience, good, nil, []string{ScopeCloudPlatform, "https://evil.example/auth/x"})},
		{"an uppercase scope", "scope", NewExchangeRequest(fedAudience, good, nil, []string{"https://www.googleapis.com/auth/Cloud-platform"})},
		{"a scope with a space", "scope", NewExchangeRequest(fedAudience, good, nil, []string{ScopeCloudPlatform + " " + ScopeUserinfoEmail})},
		{"the bare prefix", "scope", NewExchangeRequest(fedAudience, good, nil, []string{scopePrefix})},
	} {
		ans, err := f.Exchange(t.Context(), c.r)
		var fe *FederationError
		if ans != nil || !errors.Is(err, ErrCredentialInvalid) || errors.As(err, &fe) || err.Error() != fmt.Sprintf(msgFederationRequest, c.field) {
			t.Errorf("%s: %v, %v; want the %s refusal", c.name, ans, err, c.field)
		}
	}
	if n := l.accepted(t); n != 0 {
		t.Fatalf("%d connections were made for refused requests", n)
	}
	// The control: a well-formed request dials (the listener closes it).
	if _, err := f.Exchange(t.Context(), NewExchangeRequest(fedAudience, good, nil, nil)); !errors.Is(err, ErrUnreachable) {
		t.Errorf("the control: %v; want unreachable at a listener that closes every connection", err)
	}
	if n := l.accepted(t); n == 0 {
		t.Error("the control made no connection, so the zero above proves nothing")
	}
}

// TestImpersonateRefusesBeforeSending: a nil or empty federated token, a
// malformed email and a Scopes outside the closed list are refused before
// anything is dialled.
func TestImpersonateRefusesBeforeSending(t *testing.T) {
	f, l := fedCounting(t)
	for _, c := range []struct {
		name, field, email string
		tok                *auth.Token
		s                  Scopes
	}{
		{"a nil token", "federated token", fedEmail, nil, ScopesCluster},
		{"an empty token", "federated token", fedEmail, &auth.Token{Type: "Bearer"}, ScopesCluster},
		{"a bad email", "service account", "reader@example.com", &auth.Token{Value: "x"}, ScopesCluster},
		{"an empty email", "service account", "", &auth.Token{Value: "x"}, ScopesCluster},
		{"the zero Scopes", "scopes", fedEmail, &auth.Token{Value: "x"}, 0},
		{"a Scopes past the list", "scopes", fedEmail, &auth.Token{Value: "x"}, scopesIAM + 1},
		// The order: the token, then the email, then the scopes.
		{"a bad email and the zero Scopes", "service account", "reader@example.com", &auth.Token{Value: "x"}, 0},
		{"no token, no email and the zero Scopes", "federated token", "", nil, 0},
	} {
		tok, err := f.Impersonate(t.Context(), c.tok, c.email, c.s)
		if tok != nil || !errors.Is(err, ErrCredentialInvalid) || err.Error() != fmt.Sprintf(msgFederationRequest, c.field) {
			t.Errorf("%s: %v, %v; want the %s refusal", c.name, tok, err, c.field)
		}
	}
	if n := l.accepted(t); n != 0 {
		t.Fatalf("%d connections were made for refused requests", n)
	}
	if _, err := f.Impersonate(t.Context(), &auth.Token{Value: "x"}, fedEmail, ScopesStorage); !errors.Is(err, ErrUnreachable) {
		t.Errorf("the control: %v; want unreachable", err)
	}
	if n := l.accepted(t); n == 0 {
		t.Error("the control made no connection")
	}
}

// fedRemoteError stands for an error whose words Go formatted from a
// server's bytes, as net/http's and textproto's parse errors and HTTP/2's
// GoAwayError are.
type fedRemoteError string

func (e fedRemoteError) Error() string { return string(e) }

// fedTimeout is a net.Error whose Timeout is true and whose words are
// planted; with deadline it is context.DeadlineExceeded too, as net/http's
// client timeout is.
type fedTimeout struct {
	text     string
	deadline bool
}

func (e fedTimeout) Error() string   { return e.text }
func (e fedTimeout) Timeout() bool   { return true }
func (e fedTimeout) Temporary() bool { return true }
func (e fedTimeout) Is(target error) bool {
	return e.deadline && target == context.DeadlineExceeded
}

// fedMarkers are the planted values no error text may carry.
var fedMarkers = []string{fedSecretMarker, fedEmail, fedHexID, "serviceAccounts", "generateAccessToken"}

// fedPlanted is a body field's text carrying every marker.
const fedPlanted = fedSecretMarker + " " + fedEmail + " " + fedHexID

// TestFederationErrorTexts pins every failure's whole text, its sentinel and
// none of the others, and that no planted marker reaches any error in its
// tree.
func TestFederationErrorTexts(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	gatURL := "https://" + IAMCredentialsHost + "/v1/projects/-/serviceAccounts/" + fedEmail + ":generateAccessToken"
	stsURL := "https://" + STSMTLSHost + STSTokenPath
	alert := func(words string) error { return &net.OpError{Op: "remote error", Err: errors.New(words)} }
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	refusedEx := func(code int, body string) error {
		_, err := exchangeAnswer(code, []byte(body), tls.VersionTLS13, now)
		return err
	}
	refusedIm := func(code int, body string) error {
		_, err := impersonationAnswer(code, []byte(body), tls.VersionTLS13, now)
		return err
	}
	for _, c := range []struct {
		name     string
		err      error
		want     string
		sentinel string
		cause    error
	}{
		{"exchange refused, OAuth code", refusedEx(400, `{"error":"invalid_grant","error_description":"`+fedPlanted+`"}`),
			"kube: Google's token exchange refused the request (400 Bad Request, OAuth error invalid_grant)", "ErrTokenRefused", nil},
		{"exchange refused, Google status", refusedEx(403, `{"error":{"code":403,"message":"`+fedPlanted+`","status":"PERMISSION_DENIED"}}`),
			"kube: Google's token exchange refused the request (403 Forbidden, status PERMISSION_DENIED)", "ErrTokenRefused", nil},
		{"exchange refused, neither", refusedEx(500, fedPlanted),
			"kube: Google's token exchange refused the request (500 Internal Server Error)", "ErrTokenRefused", nil},
		{"impersonation refused, Google status", refusedIm(403, `{"error":{"code":403,"message":"`+fedPlanted+`","status":"PERMISSION_DENIED"}}`),
			"kube: IAM Credentials refused the service account's token (403 Forbidden, status PERMISSION_DENIED)", "ErrTokenRefused", nil},
		{"impersonation refused, an OAuth code is not read", refusedIm(401, `{"error":"invalid_grant","error_description":"`+fedPlanted+`"}`),
			"kube: IAM Credentials refused the service account's token (401 Unauthorized)", "ErrTokenRefused", nil},
		{"impersonation refused, neither", refusedIm(502, `<html>`+fedPlanted+`</html>`),
			"kube: IAM Credentials refused the service account's token (502 Bad Gateway)", "ErrTokenRefused", nil},
		{"exchange handshake", classifyFailure(context.Background(), StepExchange, &url.Error{Op: "Post", URL: stsURL, Err: alert("tls: certificate required")}, false),
			"kube: Google's token exchange refused the client certificate at the handshake (tls: certificate required)", "ErrTokenRefused", nil},
		{"exchange handshake, unshaped words", classifyFailure(context.Background(), StepExchange, &url.Error{Op: "Post", URL: stsURL, Err: alert("tls: " + fedPlanted)}, false),
			"kube: Google's token exchange refused the client certificate at the handshake (a TLS alert)", "ErrTokenRefused", nil},
		{"impersonation handshake", classifyFailure(context.Background(), StepImpersonate, &url.Error{Op: "Post", URL: gatURL, Err: alert("tls: protocol version not supported")}, false),
			"kube: IAM Credentials could not be reached: tls: protocol version not supported", "ErrUnreachable", nil},
		{"exchange unreachable", classifyFailure(context.Background(), StepExchange, &url.Error{Op: "Post", URL: stsURL, Err: dial}, false),
			"kube: Google's token exchange could not be reached: dial tcp: connect: connection refused", "ErrUnreachable", dial},
		{"impersonation unreachable", classifyFailure(context.Background(), StepImpersonate, &url.Error{Op: "Post", URL: gatURL, Err: dial}, false),
			"kube: IAM Credentials could not be reached: dial tcp: connect: connection refused", "ErrUnreachable", dial},
		{"impersonation, no answer", classifyFailure(context.Background(), StepImpersonate, errors.New(fedPlanted), false),
			"kube: IAM Credentials could not be reached: no answer within 30s", "ErrUnreachable", nil},
		{"exchange, the caller's context ended", classifyFailure(canceled, StepExchange, &url.Error{Op: "Post", URL: stsURL, Err: context.Canceled}, false),
			"kube: Google's token exchange could not be reached: context canceled", "ErrUnreachable", context.Canceled},
		{"exchange unusable", refusedEx(200, `{"access_token":"","issued_token_type":"`+TokenTypeAccessToken+`","token_type":"Bearer","expires_in":3599,"x":"`+fedPlanted+`"}`),
			"kube: Google's token exchange answered without a usable token (access_token)", "ErrUnreadable", nil},
		{"impersonation unusable", refusedIm(200, `{"accessToken":"`+fedSecretMarker+`","expireTime":"`+fedPlanted+`"}`),
			"kube: IAM Credentials answered without a usable token (expireTime)", "ErrUnreadable", nil},
	} {
		if c.err == nil {
			t.Errorf("%s: no error", c.name)
			continue
		}
		if c.err.Error() != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, c.err.Error(), c.want)
		}
		for name, s := range fedSentinels {
			if is := errors.Is(c.err, s); is != (name == c.sentinel) {
				t.Errorf("%s: errors.Is(%s) = %v", c.name, name, is)
			}
		}
		if c.cause != nil && !errors.Is(c.err, c.cause) {
			t.Errorf("%s: the cause %v is not in the tree", c.name, c.cause)
		}
		var ue *url.Error
		if errors.As(c.err, &ue) {
			t.Errorf("%s: a *url.Error, which names the URL, is in the tree", c.name)
		}
		for _, e := range fedErrorTree(c.err) {
			if m := containsAnyOf(e.Error(), fedMarkers...); m != "" {
				t.Errorf("%s: an error in the tree carries %q: %s", c.name, m, e.Error())
			}
		}
	}
	// The host guard's refusal passes through Do unchanged.
	guard := refuse(ErrEndpointRefused, msgFederationHost)
	if got := classifyFailure(context.Background(), StepExchange, &url.Error{Op: "Post", URL: stsURL, Err: guard}, false); got != guard {
		t.Errorf("the host guard's refusal through Do = %v, want it as it is", got)
	}
	// A read's own error keeps its words and is the cause when Go's network
	// stack wrote them from nothing a server sent.
	if got := classifyFailure(context.Background(), StepExchange, io.ErrUnexpectedEOF, true); got.Error() != "kube: Google's token exchange could not be reached: unexpected EOF" || !errors.Is(got, io.ErrUnexpectedEOF) {
		t.Errorf("a read's error = %v", got)
	}
	// Words Go formats from a server's bytes are never carried, before an
	// answer (through Do's *url.Error) or while one is read: a malformed
	// status or header line, an HTTP/2 GOAWAY's debug data. Each is
	// unreachable with fixed words and no cause. A failure Go described
	// itself keeps its own words, never a wrapper's.
	reset := &net.OpError{Op: "read", Net: "tcp", Err: errors.New("connection reset by peer")}
	unverified := &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}
	planted := func(text string) error { return fedRemoteError(text) }
	for _, c := range []struct {
		name    string
		step    Step
		err     error
		reading bool
		want    string
		cause   error
	}{
		{"exchange, a malformed header line", StepExchange,
			&url.Error{Op: "Post", URL: stsURL, Err: fmt.Errorf("net/http: HTTP/1.x transport connection broken: %w", planted(`malformed MIME header: missing colon: "`+fedPlanted+`"`))}, false,
			"kube: Google's token exchange could not be reached: no readable answer", nil},
		{"impersonation, a malformed header line", StepImpersonate,
			&url.Error{Op: "Post", URL: gatURL, Err: fmt.Errorf("net/http: HTTP/1.x transport connection broken: %w", planted(`malformed MIME header line: "`+fedPlanted+`"`))}, false,
			"kube: IAM Credentials could not be reached: no readable answer", nil},
		{"impersonation, a malformed status line", StepImpersonate,
			&url.Error{Op: "Post", URL: gatURL, Err: planted(`malformed HTTP response "` + fedPlanted + `"`)}, false,
			"kube: IAM Credentials could not be reached: no readable answer", nil},
		{"impersonation, a GOAWAY's debug data before the answer", StepImpersonate,
			&url.Error{Op: "Post", URL: gatURL, Err: planted(`http2: server sent GOAWAY and closed the connection; LastStreamID=1, ErrCode=NO_ERROR, debug="` + fedPlanted + `"`)}, false,
			"kube: IAM Credentials could not be reached: no readable answer", nil},
		{"impersonation, a GOAWAY's debug data while the answer is read", StepImpersonate,
			planted(`http2: server sent GOAWAY and closed the connection; LastStreamID=1, ErrCode=NO_ERROR, debug="` + fedPlanted + `"`), true,
			"kube: IAM Credentials could not be reached: no readable answer", nil},
		{"exchange, a read's error in a server's words", StepExchange,
			planted("invalid header field value for " + fedPlanted), true,
			"kube: Google's token exchange could not be reached: no readable answer", nil},
		{"exchange, a reset inside a wrapper that quotes the server", StepExchange,
			&url.Error{Op: "Post", URL: stsURL, Err: fmt.Errorf("%s: %w", fedPlanted, reset)}, false,
			"kube: Google's token exchange could not be reached: read tcp: connection reset by peer", reset},
		{"impersonation, the client's timeout over a server's words", StepImpersonate,
			&url.Error{Op: "Post", URL: gatURL, Err: fedTimeout{text: fedPlanted + " (Client.Timeout exceeded while awaiting headers)", deadline: true}}, false,
			"kube: IAM Credentials could not be reached: context deadline exceeded", context.DeadlineExceeded},
		{"exchange, a timeout with no context error", StepExchange,
			&url.Error{Op: "Post", URL: stsURL, Err: fedTimeout{text: fedPlanted}}, false,
			"kube: Google's token exchange could not be reached: timed out", nil},
		{"exchange, a record that is not TLS", StepExchange,
			&url.Error{Op: "Post", URL: stsURL, Err: tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}}, false,
			"kube: Google's token exchange could not be reached: tls: first record does not look like a TLS handshake", nil},
		{"impersonation, a chain that failed verification", StepImpersonate,
			&url.Error{Op: "Post", URL: gatURL, Err: unverified}, false,
			"kube: IAM Credentials could not be reached: tls: failed to verify certificate: x509: certificate signed by unknown authority", unverified},
		{"exchange, the read ended early", StepExchange,
			fmt.Errorf("%s: %w", fedPlanted, io.ErrUnexpectedEOF), true,
			"kube: Google's token exchange could not be reached: unexpected EOF", io.ErrUnexpectedEOF},
	} {
		err := classifyFailure(context.Background(), c.step, c.err, c.reading)
		var fe *FederationError
		if !errors.As(err, &fe) {
			t.Errorf("%s: %v (%T) is not a *FederationError", c.name, err, err)
			continue
		}
		if err.Error() != c.want || fe.Status != 0 || fe.Handshake || fe.Alert != "" || fe.Step != c.step || !errors.Is(err, ErrUnreachable) || errors.Is(err, ErrTokenRefused) {
			t.Errorf("%s:\n got %q (Status %d, Handshake %v, Alert %q)\nwant %q, unreachable", c.name, err.Error(), fe.Status, fe.Handshake, fe.Alert, c.want)
		}
		if c.cause != nil && !errors.Is(err, c.cause) {
			t.Errorf("%s: the cause %v is not in the tree", c.name, c.cause)
		}
		if c.cause == nil && fe.cause != nil {
			t.Errorf("%s: a cause %q is kept; want none", c.name, fe.cause.Error())
		}
		if errors.As(err, new(*url.Error)) {
			t.Errorf("%s: a *url.Error is in the tree", c.name)
		}
		var remote fedRemoteError
		if errors.As(err, &remote) {
			t.Errorf("%s: the error carrying the server's words is in the tree", c.name)
		}
		for _, e := range fedErrorTree(err) {
			if m := containsAnyOf(e.Error(), append([]string{"@"}, fedMarkers...)...); m != "" {
				t.Errorf("%s: an error in the tree carries %q: %s", c.name, m, e.Error())
			}
		}
	}
	// A TLS alert keeps its words in Alert, in their shape. Before an answer
	// came it ended the call at the handshake, whatever the alert, an
	// internal_error included; while an answer was read it ended no handshake
	// and decided nothing: unreachable, never a refusal, with no status.
	for _, c := range []struct {
		name      string
		step      Step
		words     string
		reading   bool
		want      string
		sentinel  error
		handshake bool
		alert     string
	}{
		{"exchange, certificate required", StepExchange, "tls: certificate required", false,
			"kube: Google's token exchange refused the client certificate at the handshake (tls: certificate required)", ErrTokenRefused, true, "tls: certificate required"},
		{"exchange, internal error at the handshake", StepExchange, "tls: internal error", false,
			"kube: Google's token exchange refused the client certificate at the handshake (tls: internal error)", ErrTokenRefused, true, "tls: internal error"},
		{"exchange, words out of shape", StepExchange, "tls: " + fedPlanted, false,
			"kube: Google's token exchange refused the client certificate at the handshake (a TLS alert)", ErrTokenRefused, true, ""},
		{"impersonation, at the handshake", StepImpersonate, "tls: protocol version not supported", false,
			"kube: IAM Credentials could not be reached: tls: protocol version not supported", ErrUnreachable, true, "tls: protocol version not supported"},
		{"exchange, an alert while the answer is read", StepExchange, "tls: internal error", true,
			"kube: Google's token exchange could not be reached: tls: internal error", ErrUnreachable, false, "tls: internal error"},
		{"exchange, certificate words while the answer is read", StepExchange, "tls: certificate required", true,
			"kube: Google's token exchange could not be reached: tls: certificate required", ErrUnreachable, false, "tls: certificate required"},
		{"exchange, words out of shape while the answer is read", StepExchange, "tls: " + fedPlanted, true,
			"kube: Google's token exchange could not be reached: a TLS alert", ErrUnreachable, false, ""},
		{"impersonation, an alert while the answer is read", StepImpersonate, "tls: record overflow", true,
			"kube: IAM Credentials could not be reached: tls: record overflow", ErrUnreachable, false, "tls: record overflow"},
	} {
		in := alert(c.words) // as the body's read returns it
		if !c.reading {
			in = &url.Error{Op: "Post", URL: stsURL, Err: in} // as Do returns it
		}
		err := classifyFailure(context.Background(), c.step, in, c.reading)
		var fe *FederationError
		if !errors.As(err, &fe) {
			t.Errorf("%s: %v (%T) is not a *FederationError", c.name, err, err)
			continue
		}
		if err.Error() != c.want || fe.Handshake != c.handshake || fe.Alert != c.alert || fe.Status != 0 || fe.Step != c.step || !errors.Is(err, c.sentinel) {
			t.Errorf("%s: %q (Handshake %v, Alert %q, Status %d); want %q (Handshake %v, Alert %q, %v)",
				c.name, err.Error(), fe.Handshake, fe.Alert, fe.Status, c.want, c.handshake, c.alert, c.sentinel)
		}
		if c.sentinel == ErrUnreachable && errors.Is(err, ErrTokenRefused) {
			t.Errorf("%s: an unreachable is also a refusal", c.name)
		}
		for _, e := range fedErrorTree(err) {
			if m := containsAnyOf(e.Error(), fedMarkers...); m != "" {
				t.Errorf("%s: an error in the tree carries %q: %s", c.name, m, e.Error())
			}
		}
		if m := containsAnyOf(fe.Alert, fedMarkers...); m != "" {
			t.Errorf("%s: Alert carries %q", c.name, m)
		}
	}
}

func containsAnyOf(s string, markers ...string) string {
	for _, m := range markers {
		if m != "" && strings.Contains(s, m) {
			return m
		}
	}
	return ""
}

// TestOAuthCodeAndGoogleStatusShapes: the codes an error may carry, each in
// its shape, read from "error" alone, never from error_description or
// message.
func TestOAuthCodeAndGoogleStatusShapes(t *testing.T) {
	for _, c := range []struct {
		shape string
		f     func(string) bool
		yes   []string
		no    []string
	}{
		{"OAuth code", isOAuthCode,
			[]string{"invalid_grant", "a", strings.Repeat("a", 64), "unauthorized_client", "invalid_target"},
			[]string{"", strings.Repeat("a", 65), "Invalid_grant", "invalid-grant", "invalid grant", "invalid_grant\n", "invalid_grant1", "ïnvalid"}},
		{"Google status", isGoogleStatus,
			[]string{"PERMISSION_DENIED", "UNAUTHENTICATED", "A", strings.Repeat("A", 64)},
			[]string{"", strings.Repeat("A", 65), "permission_denied", "PERMISSION-DENIED", "PERMISSION DENIED", "PERMISSION_DENIED\n", "NOT_FOUND1"}},
		{"alert words", isAlertWords,
			[]string{"tls: certificate required", "tls: protocol version not supported", "tls: unknown certificate authority", "tls: alert(115)", "tls: no application protocol"},
			[]string{"", "tls: ", "tls: bad record MAC", "x509: certificate signed by unknown authority", "tls: a\nb", "tls: " + strings.Repeat("a", 65), "TLS: certificate required", "tls: " + fedEmail}},
	} {
		for _, s := range c.yes {
			if !c.f(s) {
				t.Errorf("%s refuses %q", c.shape, s)
			}
		}
		for _, s := range c.no {
			if c.f(s) {
				t.Errorf("%s accepts %q", c.shape, s)
			}
		}
	}

	for _, c := range []struct {
		body          string
		oauth, status string
	}{
		{`{"error":"invalid_grant","error_description":"` + fedPlanted + `"}`, "invalid_grant", ""},
		{`{"error":{"code":403,"status":"PERMISSION_DENIED","message":"` + fedPlanted + `"}}`, "", "PERMISSION_DENIED"},
		{`{"error":{"status":"PERMISSION_DENIED"}}`, "", "PERMISSION_DENIED"},
		{`{"error_description":"invalid_grant","message":"PERMISSION_DENIED"}`, "", ""},
		{`{"error":{"message":"PERMISSION_DENIED"}}`, "", ""},
		{`{"error":42}`, "", ""},
		{`{"error":["invalid_grant"]}`, "", ""},
		{`{"error":null}`, "", ""},
		{`{"error":true}`, "", ""},
		{`{"error":"Invalid Grant"}`, "", ""},
		{`{"error":{"status":"permission_denied"}}`, "", ""},
		{`{"error":{"status":42}}`, "", ""},
		{`{"Error":"invalid_grant"}`, "", ""},
		{`not json ` + fedPlanted, "", ""},
		{``, "", ""},
	} {
		oauth, status := errorCodes([]byte(c.body))
		if oauth != c.oauth || status != c.status {
			t.Errorf("errorCodes(%s) = %q, %q; want %q, %q", c.body, oauth, status, c.oauth, c.status)
		}
		if m := containsAnyOf(oauth+status, fedMarkers...); m != "" {
			t.Errorf("errorCodes(%s) carries %q", c.body, m)
		}
	}

	// STS's Google error shape gives GoogleStatus, on the error itself.
	_, err := exchangeAnswer(403, []byte(`{"error":{"code":403,"status":"PERMISSION_DENIED","message":"`+fedPlanted+`"}}`), tls.VersionTLS13, time.Now())
	var fe *FederationError
	if !errors.As(err, &fe) || fe.GoogleStatus != "PERMISSION_DENIED" || fe.OAuthError != "" || fe.Status != 403 || fe.Step != StepExchange || fe.TLSVersion != tls.VersionTLS13 {
		t.Errorf("STS's Google error shape: %+v", fe)
	}
	_, err = exchangeAnswer(400, []byte(`{"error":"invalid_scope"}`), tls.VersionTLS13, time.Now())
	if !errors.As(err, &fe) || fe.OAuthError != "invalid_scope" || fe.GoogleStatus != "" {
		t.Errorf("STS's OAuth error: %+v", fe)
	}
	_, err = impersonationAnswer(400, []byte(`{"error":"invalid_scope"}`), 0, time.Now())
	if !errors.As(err, &fe) || fe.OAuthError != "" || fe.Step != StepImpersonate {
		t.Errorf("IAM Credentials' string error: %+v", fe)
	}
}

// fedValidExchange is a usable STS answer.
const fedValidExchange = `{"access_token":"tok-1","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3599}`

// TestExchangeAnswerValidation is the 200 decoder's table: every unusable
// answer names its field, an oversize one is never cut to fit, a 300 is no
// success, and a usable one expires exactly expires_in after now.
func TestExchangeAnswerValidation(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	with := func(field, raw string) string {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(fedValidExchange), &m); err != nil {
			t.Fatal(err)
		}
		if raw == "" {
			delete(m, field)
		} else {
			m[field] = json.RawMessage(raw)
		}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	pad := func(body string, size int) string { return body + strings.Repeat(" ", size-len(body)) }
	for _, c := range []struct{ name, body, field string }{
		{"no access_token", with("access_token", ""), "access_token"},
		{"an empty access_token", with("access_token", `""`), "access_token"},
		{"an oversize access_token", with("access_token", `"`+strings.Repeat("a", 12289)+`"`), "access_token"},
		{"a numeric access_token", with("access_token", `42`), "access_token"},
		{"a null access_token", with("access_token", `null`), "access_token"},
		{"another issued_token_type", with("issued_token_type", `"urn:ietf:params:oauth:token-type:id_token"`), "issued_token_type"},
		{"no issued_token_type", with("issued_token_type", ""), "issued_token_type"},
		{"another token_type", with("token_type", `"MAC"`), "token_type"},
		{"no token_type", with("token_type", ""), "token_type"},
		{"expires_in 0", with("expires_in", `0`), "expires_in"},
		{"a negative expires_in", with("expires_in", `-1`), "expires_in"},
		{"a string expires_in", with("expires_in", `"3599"`), "expires_in"},
		{"a float expires_in", with("expires_in", `3599.5`), "expires_in"},
		{"an exponent expires_in", with("expires_in", `3.599e3`), "expires_in"},
		{"no expires_in", with("expires_in", ""), "expires_in"},
		{"an expires_in no Duration holds", with("expires_in", `99999999999999`), "expires_in"},
		{"not JSON", "nope", answerNotObject},
		{"an array", `[]`, answerNotObject},
		{"null", `null`, answerNotObject},
		{"over 64 KiB", pad(fedValidExchange, maxFederationAnswer+1), answerOversize},
	} {
		ans, err := exchangeAnswer(http.StatusOK, []byte(c.body), tls.VersionTLS13, now)
		var fe *FederationError
		if ans != nil || !errors.Is(err, ErrUnreadable) || !errors.As(err, &fe) || fe.Field != c.field || fe.Status != 200 || fe.Step != StepExchange {
			t.Errorf("%s: %v, %v; want ErrUnreadable naming %q", c.name, ans, err, c.field)
		}
	}

	// A 300 with a usable body is not success.
	_, err := exchangeAnswer(http.StatusMultipleChoices, []byte(fedValidExchange), tls.VersionTLS13, now)
	var fe *FederationError
	if !errors.Is(err, ErrTokenRefused) || !errors.As(err, &fe) || fe.Status != 300 {
		t.Errorf("a 300 with a usable body: %v; want a refusal with status 300", err)
	}

	for name, body := range map[string]string{
		"usable":                   fedValidExchange,
		"bearer in lower case":     with("token_type", `"bearer"`),
		"an unknown field":         with("scope", `"https://www.googleapis.com/auth/cloud-platform"`),
		"padded to exactly 64 KiB": pad(fedValidExchange, maxFederationAnswer),
	} {
		ans, err := exchangeAnswer(http.StatusOK, []byte(body), tls.VersionTLS13, now)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if ans.Token().Value != "tok-1" || ans.Token().Type != "Bearer" || ans.ExpiresIn() != 3599*time.Second || ans.TLSVersion() != tls.VersionTLS13 {
			t.Errorf("%s: %+v", name, ans)
		}
		if !ans.Token().Expiry.Equal(now.Add(3599 * time.Second)) {
			t.Errorf("%s: Expiry = %v, want now + expires_in exactly", name, ans.Token().Expiry)
		}
	}
	long := with("access_token", `"`+strings.Repeat("a", 12288)+`"`)
	if _, err := exchangeAnswer(http.StatusOK, []byte(long), 0, now); err != nil {
		t.Errorf("a 12288-byte access_token: %v", err)
	}
}

// TestImpersonationAnswerValidation is generateAccessToken's 200 decoder.
func TestImpersonationAnswerValidation(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		expireTime string
		want       time.Time
	}{
		{"2026-11-22T13:00:00Z", time.Date(2026, 11, 22, 13, 0, 0, 0, time.UTC)},
		{"2026-11-22T13:00:00.123Z", time.Date(2026, 11, 22, 13, 0, 0, 123000000, time.UTC)},
		{"2026-11-22T13:00:00.123456Z", time.Date(2026, 11, 22, 13, 0, 0, 123456000, time.UTC)},
		{"2026-11-22T13:00:00.123456789Z", time.Date(2026, 11, 22, 13, 0, 0, 123456789, time.UTC)},
		{"2026-11-22T14:00:00+01:00", time.Date(2026, 11, 22, 13, 0, 0, 0, time.UTC)},
	} {
		body := `{"accessToken":"sa-1","expireTime":"` + c.expireTime + `"}`
		tok, err := impersonationAnswer(http.StatusOK, []byte(body), tls.VersionTLS12, now)
		if err != nil {
			t.Errorf("%s: %v", c.expireTime, err)
			continue
		}
		if tok.Value != "sa-1" || tok.Type != "Bearer" || !tok.Expiry.Equal(c.want) || tok.Expiry.Location() != time.UTC || tok.Expiry != tok.Expiry.Round(0) {
			t.Errorf("%s: %+v; want sa-1, Bearer, %v in UTC with no monotonic reading", c.expireTime, tok, c.want)
		}
	}
	for _, c := range []struct{ name, body, field string }{
		{"an unparsable expireTime", `{"accessToken":"sa-1","expireTime":"tomorrow"}`, "expireTime"},
		{"a space for T", `{"accessToken":"sa-1","expireTime":"2026-11-22 13:00:00Z"}`, "expireTime"},
		{"a numeric expireTime", `{"accessToken":"sa-1","expireTime":1795000000}`, "expireTime"},
		{"no expireTime", `{"accessToken":"sa-1"}`, "expireTime"},
		{"a past expireTime", `{"accessToken":"sa-1","expireTime":"2026-11-22T11:00:00Z"}`, "expireTime"},
		{"expireTime now", `{"accessToken":"sa-1","expireTime":"2026-11-22T12:00:00Z"}`, "expireTime"},
		{"an empty accessToken", `{"accessToken":"","expireTime":"2026-11-22T13:00:00Z"}`, "accessToken"},
		{"no accessToken", `{"expireTime":"2026-11-22T13:00:00Z"}`, "accessToken"},
		{"an oversize accessToken", `{"accessToken":"` + strings.Repeat("a", 8193) + `","expireTime":"2026-11-22T13:00:00Z"}`, "accessToken"},
		{"access_token is not accessToken", `{"access_token":"sa-1","expireTime":"2026-11-22T13:00:00Z"}`, "accessToken"},
		{"not JSON", `nope`, answerNotObject},
		{"over 64 KiB", `{"accessToken":"sa-1","expireTime":"2026-11-22T13:00:00Z"}` + strings.Repeat(" ", maxFederationAnswer), answerOversize},
	} {
		tok, err := impersonationAnswer(http.StatusOK, []byte(c.body), tls.VersionTLS12, now)
		var fe *FederationError
		if tok != nil || !errors.Is(err, ErrUnreadable) || !errors.As(err, &fe) || fe.Field != c.field || fe.Step != StepImpersonate {
			t.Errorf("%s: %v, %v; want ErrUnreadable naming %q", c.name, tok, err, c.field)
		}
	}
	if _, err := impersonationAnswer(http.StatusOK, []byte(`{"accessToken":"`+strings.Repeat("a", 8192)+`","expireTime":"2026-11-22T13:00:00Z"}`), 0, now); err != nil {
		t.Errorf("an 8192-byte accessToken: %v", err)
	}
}

// TestFederationClockHasNoMonotonicReading is TestTheTokenClockHasNoMonotonicReading
// for the identity path: its clock is wall time alone, and so is a token's
// Expiry as Exchange and Impersonate return it, end to end over loopback.
func TestFederationClockHasNoMonotonicReading(t *testing.T) {
	for name, build := range map[string]func() (*Federation, error){
		"NewFederation": NewFederation,
		"NewLoopbackFederation": func() (*Federation, error) {
			return NewLoopbackFederation("127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3", fedPool(t))
		},
	} {
		f, err := build()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		n := f.now()
		if n != n.Round(0) {
			t.Errorf("%s: the clock carries a monotonic reading (%v)", name, n)
		}
		if d := time.Since(n); d < 0 || d > time.Minute {
			t.Errorf("%s: the clock reads %v, %s from now", name, n, d)
		}
	}

	srv := quietTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == STSTokenPath {
			_, _ = io.WriteString(w, fedValidExchange)
			return
		}
		_, _ = io.WriteString(w, `{"accessToken":"sa-1","expireTime":"`+time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)+`"}`)
	}))
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()
	f, err := NewLoopbackFederation(addr, addr, addr, roots)
	if err != nil {
		t.Fatal(err)
	}
	id := newFedIdentity(t, fedHexID)
	before := time.Now().Round(0)
	ans, err := f.Exchange(t.Context(), NewExchangeRequest(fedAudience, ClientIdentity{}, [][]byte{id.leafDER}, nil))
	after := time.Now().Round(0)
	if err != nil {
		t.Fatal(err)
	}
	exp := ans.Token().Expiry
	if exp != exp.Round(0) {
		t.Errorf("the exchange's Expiry carries a monotonic reading (%v)", exp)
	}
	if exp.Before(before.Add(3599*time.Second)) || exp.After(after.Add(3599*time.Second)) {
		t.Errorf("the exchange's Expiry %v is not received + expires_in", exp)
	}
	if ans.TLSVersion() != tls.VersionTLS13 {
		t.Errorf("TLSVersion = %s", tls.VersionName(ans.TLSVersion()))
	}
	sa, err := f.Impersonate(t.Context(), ans.Token(), fedEmail, ScopesCluster)
	if err != nil {
		t.Fatal(err)
	}
	if sa.Expiry != sa.Expiry.Round(0) {
		t.Errorf("the service account token's Expiry carries a monotonic reading (%v)", sa.Expiry)
	}

	// SetFederationClock's clock is the one used.
	fixed := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	SetFederationClock(f, func() time.Time { return fixed })
	ans, err = f.Exchange(t.Context(), NewExchangeRequest(fedAudience, ClientIdentity{}, [][]byte{id.leafDER}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !ans.Token().Expiry.Equal(fixed.Add(3599 * time.Second)) {
		t.Errorf("with a set clock, Expiry = %v", ans.Token().Expiry)
	}
}

// The formatting test's holders: each type in an exported field, and in an
// unexported one by value and by pointer. fmt calls no method on a value it
// reaches through an unexported field; it walks the raw fields instead.
type (
	fedExported struct {
		C  ClientIdentity
		CP *ClientIdentity
		R  ExchangeRequest
		RP *ExchangeRequest
		A  ExchangeAnswer
		AP *ExchangeAnswer
		V  any
	}
	fedUnexportedIdentity    struct{ c ClientIdentity }
	fedUnexportedIdentityPtr struct{ c *ClientIdentity }
	fedUnexportedRequest     struct{ r ExchangeRequest }
	fedUnexportedRequestPtr  struct{ r *ExchangeRequest }
	fedUnexportedAnswer      struct{ a ExchangeAnswer }
	fedUnexportedAnswerPtr   struct{ a *ExchangeAnswer }
	fedUnexportedAll         struct {
		c  ClientIdentity
		cp *ClientIdentity
		r  ExchangeRequest
		rp *ExchangeRequest
		a  ExchangeAnswer
		ap *ExchangeAnswer
	}
	fedUnexportedSlices struct {
		cs []ClientIdentity
		rs []ExchangeRequest
		as []*ExchangeAnswer
	}
	// M3b.3's types: the federated Credential, RoleTokens and IAMReader.
	fedExportedRole struct {
		Cr  Credential
		CrP *Credential
		T   RoleTokens
		TP  *RoleTokens
		I   IAMReader
		IP  *IAMReader
	}
	fedUnexportedRole struct {
		cr  Credential
		crp *Credential
		t   RoleTokens
		tp  *RoleTokens
		i   IAMReader
		ip  *IAMReader
	}
)

// TestFederationTypesNeverFormat: the identity path's types never print a
// certificate, its CN, a key, the audience's project number, pool or
// provider, or a token, under every fmt verb, encoding/json and both slog
// handlers: alone, as a pointer, in a struct's exported field, and in an
// unexported one by value or by pointer, where only their contents' two
// pointers keep them unprinted (fmt's badVerb dereferences a pointer at depth
// 0 under %s and %q). Since M3b.3 that holds for a federated Credential's
// federated part (the rest of a Credential formats as before: its exported
// fields), for RoleTokens holding a token, and for an IAMReader.
func TestFederationTypesNeverFormat(t *testing.T) {
	const (
		plantedCN       = "planted-cn-" + fedHexID
		plantedNumber   = "998877665544"
		plantedPool     = "planted-pool-x1"
		plantedProvider = "planted-prov-x1"
	)
	aud, err := Audience(plantedNumber, plantedPool, plantedProvider)
	if err != nil {
		t.Fatal(err)
	}
	id := newFedIdentity(t, plantedCN)
	ci := NewClientIdentity([][]byte{id.leafDER, id.anchorDER}, id.key)
	req := NewExchangeRequest(aud, ci, ci.Chain(), []string{ScopeCloudPlatform})
	ans := newExchangeAnswer(&auth.Token{Value: fedSecretMarker + "-token", Type: "Bearer"}, time.Hour, tls.VersionTLS13)
	keyBytes, err := id.key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	fed, err := NewLoopbackFederation("127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3", fedPool(t))
	if err != nil {
		t.Fatal(err)
	}
	cred, err := NewFederatedCredential(fed, aud, ci, fedEmail, Reader)
	if err != nil {
		t.Fatal(err)
	}
	cred.fed().cache.tok = &auth.Token{Value: fedSecretMarker + "-federated", Expiry: time.Now().Add(time.Hour)}
	rtp := newRoleTokens(Reader, true, ScopesStorage, func(context.Context) (*auth.Token, error) {
		return &auth.Token{Value: fedSecretMarker + "-sa", Expiry: time.Now().Add(time.Hour)}, nil
	})
	if v, _, err := rtp.Token(t.Context()); err != nil || v != fedSecretMarker+"-sa" {
		t.Fatalf("the planted RoleTokens: %q, %v", v, err)
	}
	rt := *rtp
	irp, err := NewIAMReader(cred)
	if err != nil {
		t.Fatal(err)
	}
	irp.get().tokens.get().tok = &auth.Token{Value: fedSecretMarker + "-iam", Expiry: time.Now().Add(time.Hour)}
	ir := *irp
	forbidden := []string{
		plantedCN, hex.EncodeToString([]byte(plantedCN)),
		string(id.leafDER), hex.EncodeToString(id.leafDER), base64.StdEncoding.EncodeToString(id.leafDER),
		string(id.anchorDER), hex.EncodeToString(id.anchorDER), base64.StdEncoding.EncodeToString(id.anchorDER),
		hex.EncodeToString(keyBytes), new(big.Int).SetBytes(keyBytes).String(),
		fedSecretMarker, hex.EncodeToString([]byte(fedSecretMarker)),
		plantedNumber, hex.EncodeToString([]byte(plantedNumber)),
		plantedPool, hex.EncodeToString([]byte(plantedPool)),
		plantedProvider, hex.EncodeToString([]byte(plantedProvider)),
		strings.Trim(fmt.Sprintf("%d", id.leafDER[:48]), "[]"), // the DER as %d prints a byte slice
		strings.Trim(fmt.Sprintf("%d", []byte(plantedPool)), "[]"),
	}
	values := map[string]any{
		"ClientIdentity":   ci,
		"*ClientIdentity":  &ci,
		"ExchangeRequest":  req,
		"*ExchangeRequest": &req,
		"ExchangeAnswer":   ans,
		"*ExchangeAnswer":  &ans,
		"exported fields":  fedExported{C: ci, CP: &ci, R: req, RP: &req, A: ans, AP: &ans, V: ci},
		"*exported fields": &fedExported{C: ci, CP: &ci, R: req, RP: &req, A: ans, AP: &ans, V: req},

		"an unexported ClientIdentity":    fedUnexportedIdentity{ci},
		"an unexported *ClientIdentity":   fedUnexportedIdentityPtr{&ci},
		"an unexported ExchangeRequest":   fedUnexportedRequest{req},
		"an unexported *ExchangeRequest":  fedUnexportedRequestPtr{&req},
		"an unexported ExchangeAnswer":    fedUnexportedAnswer{ans},
		"an unexported *ExchangeAnswer":   fedUnexportedAnswerPtr{&ans},
		"*an unexported ClientIdentity":   &fedUnexportedIdentity{ci},
		"*an unexported *ClientIdentity":  &fedUnexportedIdentityPtr{&ci},
		"*an unexported ExchangeRequest":  &fedUnexportedRequest{req},
		"*an unexported *ExchangeRequest": &fedUnexportedRequestPtr{&req},
		"*an unexported ExchangeAnswer":   &fedUnexportedAnswer{ans},
		"*an unexported *ExchangeAnswer":  &fedUnexportedAnswerPtr{&ans},
		"all of them unexported":          fedUnexportedAll{ci, &ci, req, &req, ans, &ans},
		"*all of them unexported":         &fedUnexportedAll{ci, &ci, req, &req, ans, &ans},
		"unexported slices of them":       fedUnexportedSlices{[]ClientIdentity{ci}, []ExchangeRequest{req}, []*ExchangeAnswer{&ans}},
		"slices of them":                  []any{ci, &req, ans},

		"a federated Credential":                 cred,
		"*a federated Credential":                &cred,
		"RoleTokens":                             rt,
		"*RoleTokens":                            rtp,
		"IAMReader":                              ir,
		"*IAMReader":                             irp,
		"M3b.3's types in exported fields":       fedExportedRole{cred, &cred, rt, rtp, ir, irp},
		"*M3b.3's types in exported fields":      &fedExportedRole{cred, &cred, rt, rtp, ir, irp},
		"M3b.3's types in unexported fields":     fedUnexportedRole{cred, &cred, rt, rtp, ir, irp},
		"*M3b.3's types in unexported fields":    &fedUnexportedRole{cred, &cred, rt, rtp, ir, irp},
		"slices of M3b.3's types":                []any{cred, rtp, ir},
		"a slice of federated Credentials":       []Credential{cred, cred},
		"a map of RoleTokens by their consumer":  map[string]*RoleTokens{"storage": rtp},
		"an unexported federated Credential map": struct{ m map[string]Credential }{map[string]Credential{"reader": cred}},
	}
	check := func(what, out string) {
		t.Helper()
		if m := containsAnyOf(out, forbidden...); m != "" {
			t.Errorf("%s printed planted material (%.24q…)", what, m)
		}
	}
	for name, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%b", "%t", "%p", "%08.3f", "%U", "%c", "%e"} {
			check(name+" under "+verb, fmt.Sprintf(verb, v))
		}
		check(name+" under fmt.Sprint", fmt.Sprint(v))
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: json.Marshal: %v", name, err)
		}
		check(name+" under json.Marshal", string(b))
		for hname, mk := range map[string]func(io.Writer) slog.Handler{
			"TextHandler": func(w io.Writer) slog.Handler { return slog.NewTextHandler(w, nil) },
			"JSONHandler": func(w io.Writer) slog.Handler { return slog.NewJSONHandler(w, nil) },
		} {
			var buf bytes.Buffer
			slog.New(mk(&buf)).Info("m", "v", v, slog.Group("g", "v", v))
			check(name+" under slog's "+hname, buf.String())
		}
	}
	// Alone, each prints exactly its fixed text under every verb: String alone
	// would leave %d, %o and %b to print the fields.
	var zeroC ClientIdentity
	var zeroR ExchangeRequest
	var zeroA ExchangeAnswer
	var zeroT RoleTokens
	var zeroI IAMReader
	for _, c := range []struct {
		name string
		v    any
		want string
	}{
		{"ClientIdentity", ci, clientIdentityText},
		{"*ClientIdentity", &ci, clientIdentityText},
		{"ExchangeRequest", req, exchangeRequestText},
		{"*ExchangeRequest", &req, exchangeRequestText},
		{"ExchangeAnswer", ans, exchangeAnswerText},
		{"*ExchangeAnswer", &ans, exchangeAnswerText},
		{"the zero ClientIdentity", zeroC, clientIdentityText},
		{"the zero ExchangeRequest", zeroR, exchangeRequestText},
		{"the zero ExchangeAnswer", zeroA, exchangeAnswerText},
		{"RoleTokens", rt, roleTokensText},
		{"*RoleTokens", rtp, roleTokensText},
		{"IAMReader", ir, iamReaderText},
		{"*IAMReader", irp, iamReaderText},
		{"the zero RoleTokens", zeroT, roleTokensText},
		{"the zero IAMReader", zeroI, iamReaderText},
	} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%b", "%t"} {
			if got := fmt.Sprintf(verb, c.v); got != c.want {
				t.Errorf("%s under %s prints %.40q, not %q", c.name, verb, got, c.want)
			}
		}
	}
	// encoding/json, which slog's JSONHandler uses for a struct below the
	// top, gives each its fixed text too, alone and in an exported field. A
	// {} would print nothing, but it is not the fixed text the preamble's
	// invariant promises, so MarshalJSON is held here, not only the absence
	// of planted material.
	for _, c := range []struct {
		name string
		v    any
		want string
	}{
		{"ClientIdentity", ci, clientIdentityText},
		{"*ClientIdentity", &ci, clientIdentityText},
		{"ExchangeRequest", req, exchangeRequestText},
		{"*ExchangeRequest", &req, exchangeRequestText},
		{"ExchangeAnswer", ans, exchangeAnswerText},
		{"*ExchangeAnswer", &ans, exchangeAnswerText},
		{"the zero ClientIdentity", zeroC, clientIdentityText},
		{"the zero ExchangeRequest", zeroR, exchangeRequestText},
		{"the zero ExchangeAnswer", zeroA, exchangeAnswerText},
		{"RoleTokens", rt, roleTokensText},
		{"*RoleTokens", rtp, roleTokensText},
		{"IAMReader", ir, iamReaderText},
		{"*IAMReader", irp, iamReaderText},
		{"the zero RoleTokens", zeroT, roleTokensText},
		{"the zero IAMReader", zeroI, iamReaderText},
	} {
		want, err := json.Marshal(c.want)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := json.Marshal(c.v); err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s under json.Marshal = %.40q, %v; want %s", c.name, got, err, want)
		}
	}
	// slog resolves each of M3b.3's types to its fixed text through
	// LogValue, alone and as the zero value, before any handler sees it.
	for _, c := range []struct {
		name string
		v    any
		want string
	}{
		{"RoleTokens", rt, roleTokensText},
		{"*RoleTokens", rtp, roleTokensText},
		{"the zero RoleTokens", zeroT, roleTokensText},
		{"IAMReader", ir, iamReaderText},
		{"*IAMReader", irp, iamReaderText},
		{"the zero IAMReader", zeroI, iamReaderText},
	} {
		if v := slog.AnyValue(c.v).Resolve(); v.Kind() != slog.KindString || v.String() != c.want {
			t.Errorf("%s resolves under slog to %s %.40q, not the string %q", c.name, v.Kind(), v.String(), c.want)
		}
	}
	// Held in a caller's unexported fields, where fmt cannot reach their
	// methods, RoleTokens' and IAMReader's contents are two pointers deep.
	// Under a verb a pointer does not take, fmt prints the inner pointer
	// again at depth 0, where one pointer to a struct would be followed and
	// the struct printed: the role, the IAM API host.
	held := struct {
		rt RoleTokens
		ir IAMReader
	}{rt, ir}
	for _, verb := range []string{"%s", "%q", "%t", "%v", "%+v"} {
		if out := fmt.Sprintf(verb, held); strings.Contains(out, string(Reader)) || strings.Contains(out, "127.0.0.1") {
			t.Errorf("RoleTokens and IAMReader in unexported fields under %s print their contents: %.120q", verb, out)
		}
	}
	holderJSON := `{"C":"` + clientIdentityText + `","CP":"` + clientIdentityText + `","R":"` + exchangeRequestText +
		`","RP":"` + exchangeRequestText + `","A":"` + exchangeAnswerText + `","AP":"` + exchangeAnswerText + `","V":"` + clientIdentityText + `"}`
	holder := fedExported{C: ci, CP: &ci, R: req, RP: &req, A: ans, AP: &ans, V: ci}
	if got, err := json.Marshal(holder); err != nil || string(got) != holderJSON {
		t.Errorf("exported fields under json.Marshal = %.60q, %v; want %s", got, err, holderJSON)
	}
	var jsonLog bytes.Buffer
	slog.New(slog.NewJSONHandler(&jsonLog, nil)).Info("m", "v", holder)
	if !strings.Contains(jsonLog.String(), `"v":`+holderJSON) {
		t.Errorf("exported fields under slog's JSONHandler are not each type's fixed text: %.60q", jsonLog.String())
	}
	// The accessors give back what was put in, as copies; the zero values
	// give nothing, and the zero ClientIdentity presents no certificate.
	if got := ci.Chain(); len(got) != 2 || !bytes.Equal(got[0], id.leafDER) || !bytes.Equal(got[1], id.anchorDER) {
		t.Error("Chain() is not the chain given")
	}
	ci.Chain()[0][0] ^= 0xff
	if !bytes.Equal(ci.Chain()[0], id.leafDER) {
		t.Error("Chain() hands out the identity's own bytes")
	}
	if ci.Signer() != crypto.Signer(id.key) || ci.IsZero() || !zeroC.IsZero() || zeroC.Signer() != nil || zeroC.Chain() != nil {
		t.Error("Signer() or IsZero() is not as given")
	}
	if ans.Token().Value != fedSecretMarker+"-token" || ans.ExpiresIn() != time.Hour || ans.TLSVersion() != tls.VersionTLS13 {
		t.Error("an ExchangeAnswer's accessors are not as given")
	}
	if zeroA.Token() != nil || zeroA.ExpiresIn() != 0 || zeroA.TLSVersion() != 0 {
		t.Error("the zero ExchangeAnswer's accessors are not empty")
	}
	// A federated Credential's federated part prints as an address at most,
	// and encoding/json, which skips it, gives the exported fields alone.
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		out := fmt.Sprintf(verb, cred)
		if !strings.Contains(out, "0x") || strings.Contains(out, "127.0.0.1") || strings.Contains(out, "reader\"") {
			t.Errorf("a federated Credential under %s prints more than an address for its federated part: %.120q", verb, out)
		}
	}
	if b, err := json.Marshal(cred); err != nil || string(b) != `{"Email":"`+fedEmail+`","PrivateKeyID":"","PrivateKeyPEM":null,"TokenURI":"","UniverseDomain":""}` {
		t.Errorf("a federated Credential under json.Marshal = %s, %v", b, err)
	}
}

// initTimeFaults lists what in the Go source src would run at package
// initialisation: an init function, a package-level var whose value holds a
// call (a conversion such as (*T)(nil) is one in go/ast), or an import of
// regexp, whose patterns are compiled at init.
func initTimeFaults(src string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "federated.go", src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var faults []string
	for _, imp := range file.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == "regexp" {
			faults = append(faults, "imports regexp")
		}
	}
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil && d.Name.Name == "init" {
				faults = append(faults, "has an init function")
			}
		case *ast.GenDecl:
			if d.Tok != token.VAR {
				continue
			}
			for _, spec := range d.Specs {
				vs := spec.(*ast.ValueSpec)
				for _, v := range vs.Values {
					ast.Inspect(v, func(n ast.Node) bool {
						if _, ok := n.(*ast.CallExpr); ok {
							faults = append(faults, fmt.Sprintf("var %s holds a call at %s", vs.Names[0].Name, fset.Position(n.Pos())))
							return false
						}
						return true
					})
				}
			}
		}
	}
	return faults, nil
}

// TestFederatedHasNoInitTimeState: the identity path's product files
// (fedProductFiles) run nothing at package initialisation, so while nothing
// calls them the linker drops them and farcast starts exactly as before. The
// scan itself is checked on planted sources.
func TestFederatedHasNoInitTimeState(t *testing.T) {
	for _, name := range fedProductFiles {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		faults, err := initTimeFaults(string(src))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range faults {
			t.Errorf("%s %s", name, f)
		}
	}
	for name, planted := range map[string]string{
		"an init function":    "package kube\nfunc init() {}\n",
		"a compiled pattern":  "package kube\nimport \"regexp\"\nvar re = regexp.MustCompile(`x`)\n",
		"an interface check":  "package kube\nimport \"net/http\"\ntype rt struct{}\nvar _ http.RoundTripper = (*rt)(nil)\n",
		"a call in a literal": "package kube\nimport \"strings\"\nvar xs = []string{strings.Repeat(\"a\", 2)}\n",
		"a regexp import":     "package kube\nimport _ \"regexp\"\n",
	} {
		if faults, err := initTimeFaults(planted); err != nil || len(faults) == 0 {
			t.Errorf("the scan misses %s: %v, %v", name, faults, err)
		}
	}
	if faults, err := initTimeFaults("package kube\nvar ok = &refusal{msg: \"x\"}\nconst c = 1\n"); err != nil || len(faults) != 0 {
		t.Errorf("the scan refuses a composite literal: %v, %v", faults, err)
	}
}
