package oci

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var linuxAMD64 = Platform{OS: "linux", Architecture: "amd64"}

// clientFor returns a client that presents creds to the fake registry's host
// and nothing to anyone else — the shape the image builder uses, where the
// instance's registry is authenticated and the public base is not.
func clientFor(r *fakeRegistry, user, pass string) *Client {
	host := r.host()
	return &Client{Credentials: func(registry string) (string, string) {
		if registry == host {
			return user, pass
		}
		return "", ""
	}}
}

func TestBearerChallengeFlow(t *testing.T) {
	reg := newFakeRegistry(t)
	reg.mode = authBearer
	reg.user, reg.pass = "oauth2accesstoken", "ya29.short-lived"
	_, amd64Digest := seedIndexedImage(t, reg, "proj/farcast-alpha/system/fatline", "0.2.0")

	c := clientFor(reg, reg.user, reg.pass)
	ref, err := ParseReference(reg.host() + "/proj/farcast-alpha/system/fatline:0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	img, err := c.Pull(t.Context(), ref, linuxAMD64)
	if err != nil {
		t.Fatalf("pull under a bearer challenge: %v", err)
	}
	if img.Digest != amd64Digest {
		t.Fatalf("pulled digest %s, want %s", img.Digest, amd64Digest)
	}
	if reg.countCalls("GET /token") == 0 {
		t.Fatal("the client never visited the token endpoint the challenge advertised")
	}
	// The token is cached per scope: one exchange serves the manifest, config,
	// and layer fetches that follow.
	if n := reg.countCalls("GET /token"); n != 1 {
		t.Fatalf("token endpoint hit %d times, want 1 — the token is not being cached", n)
	}
}

func TestBasicChallengeFlow(t *testing.T) {
	reg := newFakeRegistry(t)
	reg.mode = authBasic
	reg.user, reg.pass = "oauth2accesstoken", "ya29.short-lived"
	seedIndexedImage(t, reg, "proj/farcast-alpha/system/fatline", "0.2.0")

	c := clientFor(reg, reg.user, reg.pass)
	ref, err := ParseReference(reg.host() + "/proj/farcast-alpha/system/fatline:0.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Pull(t.Context(), ref, linuxAMD64); err != nil {
		t.Fatalf("pull under a basic challenge: %v", err)
	}
	if reg.countCalls("GET /token") != 0 {
		t.Fatal("a Basic challenge must not send the client to a token endpoint")
	}
}

func TestNoCredentialsOfferedUntilChallenged(t *testing.T) {
	reg := newFakeRegistry(t) // authNone: never challenges
	seedIndexedImage(t, reg, "distroless/static", "nonroot")

	c := clientFor(reg, "oauth2accesstoken", "ya29.secret")
	ref, err := ParseReference(reg.host() + "/distroless/static:nonroot")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Pull(t.Context(), ref, linuxAMD64); err != nil {
		t.Fatal(err)
	}
	if reg.sawCredentials() {
		t.Fatal("credentials were sent to a registry that never asked for them")
	}
}

func TestBasicChallengeWithoutCredentialsFails(t *testing.T) {
	reg := newFakeRegistry(t)
	reg.mode = authBasic
	reg.user, reg.pass = "user", "pass"
	seedIndexedImage(t, reg, "distroless/static", "nonroot")

	c := &Client{} // anonymous
	ref, err := ParseReference(reg.host() + "/distroless/static:nonroot")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Pull(t.Context(), ref, linuxAMD64)
	if err == nil || !strings.Contains(err.Error(), "requires credentials") {
		t.Fatalf("err = %v, want a clear 'requires credentials' failure", err)
	}
}

func TestTokenRealmMustNotBePlaintext(t *testing.T) {
	reg := newFakeRegistry(t)
	reg.mode = authBearer
	// The realm is attacker-controllable input: a downgrading proxy could point
	// it at a plaintext endpoint and harvest the access token.
	reg.tokenRealm = "http://registry.invalid/token"
	seedIndexedImage(t, reg, "distroless/static", "nonroot")

	c := clientFor(reg, "oauth2accesstoken", "ya29.secret")
	ref, err := ParseReference(reg.host() + "/distroless/static:nonroot")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Pull(t.Context(), ref, linuxAMD64)
	if err == nil || !strings.Contains(err.Error(), "plaintext HTTP") {
		t.Fatalf("err = %v, want a refusal to fetch a token over plaintext HTTP", err)
	}
}

func TestParseChallenge(t *testing.T) {
	ch := parseChallenge(`Bearer realm="https://gcr.io/v2/token",service="gcr.io",scope="repository:distroless/static:pull"`)
	if ch.scheme != "bearer" {
		t.Fatalf("scheme = %q, want bearer", ch.scheme)
	}
	want := map[string]string{
		"realm":   "https://gcr.io/v2/token",
		"service": "gcr.io",
		"scope":   "repository:distroless/static:pull",
	}
	for k, v := range want {
		if ch.params[k] != v {
			t.Errorf("param %s = %q, want %q", k, ch.params[k], v)
		}
	}
	if got := parseChallenge(`Basic realm="artifact registry"`); got.scheme != "basic" || got.params["realm"] != "artifact registry" {
		t.Fatalf("basic challenge parsed as %+v", got)
	}
	if got := parseChallenge(""); got.scheme != "" {
		t.Fatalf("empty challenge parsed as %+v", got)
	}
}

func TestSchemeForOnlyPlaintextOnLoopback(t *testing.T) {
	for host, want := range map[string]string{
		"gcr.io":                          "https",
		"europe-west1-docker.pkg.dev":     "https",
		"localhost:5000":                  "http",
		"127.0.0.1:5000":                  "http",
		"[::1]:5000":                      "http",
		"registry.localhost":              "http",
		"127.0.0.1.evil.example.com:5000": "https",
	} {
		if got := schemeFor(host); got != want {
			t.Errorf("schemeFor(%q) = %q, want %q", host, got, want)
		}
	}
}

// TestTokenRealmMustBeSameHost is the other half of the realm guard. A realm
// over TLS is not enough: the host must be the registry's own. This client's
// Artifact Registry credential is a Google access token carrying every
// permission the installer service account holds, so a registry that names
// somewhere else must not be able to collect it — the flaw behind
// CVE-2026-33540 in the reference distribution client.
func TestTokenRealmMustBeSameHost(t *testing.T) {
	var collected string
	thief := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		collected = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(tokenResponse{Token: "stolen"})
	}))
	defer thief.Close()

	reg := newFakeRegistry(t)
	reg.mode = authBearer
	reg.tokenRealm = thief.URL + "/token" // https, but a different host
	seedIndexedImage(t, reg, "distroless/static", "nonroot")

	c := clientFor(reg, "oauth2accesstoken", "ya29.secret")
	ref, err := ParseReference(reg.host() + "/distroless/static:nonroot")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Pull(t.Context(), ref, linuxAMD64); err == nil {
		t.Fatal("pull followed an authentication realm on a foreign host")
	} else if !strings.Contains(err.Error(), "refusing to send credentials") {
		t.Fatalf("err = %v, want a refusal to send credentials to another host", err)
	}
	if collected != "" {
		t.Errorf("credential reached the foreign realm: %q", collected)
	}
}

// TestUploadLocationMustBeSameHost covers the push-side twin: the upload
// Location header is chosen by the registry and names where the blob *and* the
// credential go.
func TestUploadLocationMustBeSameHost(t *testing.T) {
	if _, err := resolveLocation("https://registry.test/v2/repo/blobs/uploads/", "https://elsewhere.test/upload/1", "registry.test"); err == nil {
		t.Fatal("accepted an upload location on a foreign host")
	} else if !strings.Contains(err.Error(), "refusing to send the blob") {
		t.Fatalf("err = %v, want a refusal naming the redirected upload", err)
	}
	// The ordinary relative Location must still resolve against the registry.
	got, err := resolveLocation("https://registry.test/v2/repo/blobs/uploads/", "/v2/repo/blobs/uploads/abc?state=x", "registry.test")
	if err != nil {
		t.Fatalf("rejected a same-host relative location: %v", err)
	}
	if want := "https://registry.test/v2/repo/blobs/uploads/abc?state=x"; got != want {
		t.Errorf("resolved to %q, want %q", got, want)
	}
}

// TestRedirectDropsCredentialAcrossHosts pins the redirect policy. Go's default
// keeps Authorization across a subdomain redirect; this client must not.
func TestRedirectDropsCredentialAcrossHosts(t *testing.T) {
	from, _ := http.NewRequest(http.MethodGet, "https://registry.test/v2/", nil)
	next, _ := http.NewRequest(http.MethodGet, "https://cdn.registry.test/blob", nil)
	next.Header.Set("Authorization", "Bearer secret")
	if err := checkRedirect(next, []*http.Request{from}); err != nil {
		t.Fatalf("refused a legitimate https redirect: %v", err)
	}
	if got := next.Header.Get("Authorization"); got != "" {
		t.Errorf("credential survived a cross-host redirect: %q", got)
	}

	plain, _ := http.NewRequest(http.MethodGet, "http://registry.test/blob", nil)
	if err := checkRedirect(plain, []*http.Request{from}); err == nil {
		t.Error("followed a redirect that downgraded to plaintext HTTP")
	}
}
