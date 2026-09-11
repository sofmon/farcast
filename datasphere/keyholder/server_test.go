package keyholder

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sofmon/farcast/datasphere"
)

type harness struct {
	srv      *Server
	vault    *Vault
	provider *memProvider
	status   http.Handler
	control  http.Handler
	data     http.Handler
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	v := New("prod")
	p := newMemProvider()
	srv, err := NewServer(Config{
		Instance: "prod",
		Vault:    v,
		Stores: func(s datasphere.Scope) (*datasphere.Store, error) {
			return datasphere.NewStore(p, "farcast-test-bucket", s.Keyring())
		},
		Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return &harness{srv: srv, vault: v, provider: p,
		status: srv.StatusHandler(), control: srv.ControlHandler(), data: srv.DataHandler()}
}

func (h *harness) unseal(t *testing.T, generation uint64) {
	t.Helper()
	b := mustBundle(t, "prod", generation)
	if err := h.vault.Unseal(b, IntentOperator); err != nil {
		t.Fatalf("unseal: %v", err)
	}
}

func do(h http.Handler, method, target string, headers map[string]string, body []byte) *httptest.ResponseRecorder {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func objHeaders(key, scope string) map[string]string {
	return map[string]string{
		HeaderKey:   base64.StdEncoding.EncodeToString([]byte(key)),
		HeaderScope: scope,
	}
}

// Liveness must never fail because the keyholder is sealed.
//
// Do not "fix" this test by making it accept a 503. A sealed keyholder is
// healthy and waiting for a human; failing liveness restarts it, and every
// restart is another seal — a crash loop that no unseal can ever win.
func TestLivenessNeverFailsWhileSealed(t *testing.T) {
	h := newHarness(t)
	for _, phase := range []string{"fresh", "after hold", "after seal"} {
		if got := do(h.status, "GET", "/livez", nil, nil).Code; got != http.StatusOK {
			t.Fatalf("%s: /livez = %d, want 200", phase, got)
		}
		h.vault.Seal(phase == "after hold", "test")
	}
}

func TestReadinessTracksTheSeal(t *testing.T) {
	h := newHarness(t)
	if got := do(h.status, "GET", "/readyz", nil, nil).Code; got != http.StatusServiceUnavailable {
		t.Errorf("sealed /readyz = %d, want 503", got)
	}
	h.unseal(t, 1)
	if got := do(h.status, "GET", "/readyz", nil, nil).Code; got != http.StatusOK {
		t.Errorf("unsealed /readyz = %d, want 200", got)
	}
	h.vault.Seal(false, "")
	if got := do(h.status, "GET", "/readyz", nil, nil).Code; got != http.StatusServiceUnavailable {
		t.Errorf("resealed /readyz = %d, want 503", got)
	}
}

// The status endpoint answers while sealed and carries no material. It is what
// makes ErrStorageSealed reachable when the data Service has no endpoints.
func TestStateAnswersWhileSealedWithoutMaterial(t *testing.T) {
	h := newHarness(t)
	w := do(h.status, "GET", "/v1/state", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("/v1/state while sealed = %d, want 200", w.Code)
	}
	var st stateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.Phase != string(PhaseRestartSealed) || st.Instance != "prod" {
		t.Errorf("state = %+v", st)
	}
	if len(st.Scopes) != 0 {
		t.Errorf("a sealed keyholder reported scopes: %v", st.Scopes)
	}
}

func TestControlUnsealAndRefusals(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		h := newHarness(t)
		w := h.push(t, "prod", 5, IntentOperator)
		if w.Code != http.StatusOK {
			t.Fatalf("unseal = %d: %s", w.Code, w.Body)
		}
		if !h.vault.Ready() {
			t.Error("vault not ready after a successful unseal")
		}
	})

	// The envelope is the only way in: a bare bundle over the same
	// authenticated session must be refused, or every protection the
	// envelope carries becomes optional in practice.
	t.Run("a bare bundle is refused", func(t *testing.T) {
		h := newHarness(t)
		w := do(h.control, "POST", "/v1/unseal?intent=operator-unseal", nil, marshalBundle(t, "prod", 1))
		if w.Code == http.StatusOK {
			t.Fatal("an unsealed bundle was accepted")
		}
		if h.vault.Ready() {
			t.Fatal("a bare bundle loaded key material")
		}
	})

	// A challenge is single-use, so a captured push cannot be replayed.
	t.Run("a replayed envelope is refused", func(t *testing.T) {
		h := newHarness(t)
		cw := do(h.control, "GET", SealChallengePath, nil, nil)
		var ch Challenge
		if err := json.Unmarshal(cw.Body.Bytes(), &ch); err != nil {
			t.Fatalf("decode challenge: %v", err)
		}
		sealed, err := SealBundle(marshalBundle(t, "prod", 4), "prod", ch)
		if err != nil {
			t.Fatalf("SealBundle: %v", err)
		}
		hdr := map[string]string{"Content-Type": ContentTypeSealed}
		if w := do(h.control, "POST", "/v1/unseal?intent=operator-unseal", hdr, sealed); w.Code != http.StatusOK {
			t.Fatalf("first push = %d: %s", w.Code, w.Body)
		}
		h.vault.Seal(false, "")
		if w := do(h.control, "POST", "/v1/unseal?intent=operator-unseal", hdr, sealed); w.Code == http.StatusOK {
			t.Fatal("a replayed envelope was accepted")
		}
		if h.vault.Ready() {
			t.Fatal("a replay loaded key material")
		}
	})

	t.Run("foreign instance", func(t *testing.T) {
		h := newHarness(t)
		w := h.push(t, "staging", 1, IntentOperator)
		if w.Code != http.StatusConflict || w.Header().Get(HeaderCode) != CodeInstanceMismatch {
			t.Fatalf("= %d/%q, want 409/%s", w.Code, w.Header().Get(HeaderCode), CodeInstanceMismatch)
		}
	})

	t.Run("keeper cannot clear an operator hold", func(t *testing.T) {
		h := newHarness(t)
		h.unseal(t, 1)
		h.vault.Seal(true, "maintenance")
		w := h.push(t, "prod", 2, IntentReseed)
		if w.Code != http.StatusConflict || w.Header().Get(HeaderCode) != CodeOperatorHold {
			t.Fatalf("= %d/%q, want 409/%s", w.Code, w.Header().Get(HeaderCode), CodeOperatorHold)
		}
	})

	// An unseal that does not claim to be a person is not treated as one.
	t.Run("absent intent is the conservative one", func(t *testing.T) {
		h := newHarness(t)
		h.unseal(t, 1)
		h.vault.Seal(true, "maintenance")
		w := h.push(t, "prod", 2, "")
		if w.Header().Get(HeaderCode) != CodeOperatorHold {
			t.Fatalf("an unseal with no stated intent cleared a hold: %d/%q", w.Code, w.Header().Get(HeaderCode))
		}
	})

	t.Run("old generation", func(t *testing.T) {
		h := newHarness(t)
		h.unseal(t, 9)
		w := h.push(t, "prod", 8, IntentOperator)
		if w.Code != http.StatusConflict || w.Header().Get(HeaderCode) != CodeGenerationOld {
			t.Fatalf("= %d/%q, want 409/%s", w.Code, w.Header().Get(HeaderCode), CodeGenerationOld)
		}
	})
}

// The whole data path, through a real Store: real envelope encryption, real
// tokenized names, real provider round trip.
func TestDataRoundTrip(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)
	payload := []byte("application data")

	if w := doAs(h.data, asWeb, "PUT", "/v1/object", objHeaders("app/apps/web/doc", appScopeName), payload); w.Code != http.StatusNoContent {
		t.Fatalf("PUT = %d: %s", w.Code, w.Body)
	}
	w := doAs(h.data, asWeb, "GET", "/v1/object", objHeaders("app/apps/web/doc", appScopeName), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", w.Code, w.Body)
	}
	if !bytes.Equal(w.Body.Bytes(), payload) {
		t.Errorf("round trip = %q, want %q", w.Body.Bytes(), payload)
	}

	lw := doAs(h.data, asWeb, "GET", "/v1/list", map[string]string{
		HeaderPrefix: base64.StdEncoding.EncodeToString([]byte("app/apps/web/")),
		HeaderScope:  appScopeName,
	}, nil)
	if lw.Code != http.StatusOK {
		t.Fatalf("LIST = %d: %s", lw.Code, lw.Body)
	}
	var listed struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(lw.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Keys) != 1 || listed.Keys[0] != "app/apps/web/doc" {
		t.Errorf("list = %v, want [app/doc]", listed.Keys)
	}

	if w := doAs(h.data, asWeb, "DELETE", "/v1/object", objHeaders("app/apps/web/doc", appScopeName), nil); w.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", w.Code)
	}
	if w := doAs(h.data, asWeb, "GET", "/v1/object", objHeaders("app/apps/web/doc", appScopeName), nil); w.Code != http.StatusNotFound {
		t.Errorf("GET after delete = %d, want 404", w.Code)
	}

	// The cloud saw only tokenized names.
	for name := range h.provider.objects {
		if strings.Contains(name, "app/apps/web/doc") || strings.Contains(name, "doc") {
			t.Errorf("the provider holds a recognizable logical name: %q", name)
		}
	}
}

// Every verb must report a seal as a seal — never as absence, never as a bare
// transport failure.
func TestSealedDataPathReportsSealed(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)
	if w := doAs(h.data, asWeb, "PUT", "/v1/object", objHeaders("app/apps/web/doc", appScopeName), []byte("x")); w.Code != http.StatusNoContent {
		t.Fatalf("setup PUT = %d", w.Code)
	}
	h.vault.Seal(false, "")

	cases := []struct {
		method, target string
		headers        map[string]string
		body           []byte
	}{
		{"GET", "/v1/object", objHeaders("app/apps/web/doc", appScopeName), nil},
		{"PUT", "/v1/object", objHeaders("app/apps/web/doc", appScopeName), []byte("x")},
		{"DELETE", "/v1/object", objHeaders("app/apps/web/doc", appScopeName), nil},
		{"GET", "/v1/list", map[string]string{
			HeaderPrefix: base64.StdEncoding.EncodeToString([]byte("app/apps/web/")), HeaderScope: appScopeName}, nil},
	}
	for _, tc := range cases {
		w := doAs(h.data, asWeb, tc.method, tc.target, tc.headers, tc.body)
		if w.Code != http.StatusServiceUnavailable || w.Header().Get(HeaderCode) != CodeSealed {
			t.Errorf("%s %s = %d/%q, want 503/%s", tc.method, tc.target, w.Code, w.Header().Get(HeaderCode), CodeSealed)
		}
		if w.Header().Get(HeaderCode) == CodeNotFound {
			t.Errorf("%s %s reported a seal as absence — silent data loss by a second route", tc.method, tc.target)
		}
	}
}

// A sealed List must not answer with an empty set and success: an application
// that read "no objects" from a seal could conclude its data is gone.
func TestSealedListIsNotAnEmptySuccess(t *testing.T) {
	h := newHarness(t)
	w := doAs(h.data, asWeb, "GET", "/v1/list", map[string]string{
		HeaderPrefix: base64.StdEncoding.EncodeToString([]byte("app/apps/web/")), HeaderScope: appScopeName}, nil)
	if w.Code == http.StatusOK {
		t.Fatalf("sealed LIST returned 200: %s", w.Body)
	}
	var listed struct {
		Keys []string `json:"keys"`
	}
	if json.Unmarshal(w.Body.Bytes(), &listed) == nil && listed.Keys != nil {
		t.Error("sealed LIST returned a keys array")
	}
}

// A key outside every held scope is refused BEFORE the cloud is reached: the
// keyholder must not turn an out-of-scope request into a billable call, and a
// refusal that touched the provider would leak the attempt to the cloud.
func TestOutOfScopeRefusedBeforeTouchingTheCloud(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)
	h.provider.reset()

	w := doAs(h.data, asWeb, "GET", "/v1/object", objHeaders("system/secret", appScopeName), nil)
	if w.Code != http.StatusForbidden || w.Header().Get(HeaderCode) != CodePermission {
		t.Fatalf("= %d/%q, want 403/%s", w.Code, w.Header().Get(HeaderCode), CodePermission)
	}
	if h.provider.wasTouched() {
		t.Error("an out-of-scope request reached the cloud")
	}
}

// The scope header is required rather than inferred, so that 4.x deriving it
// from the caller's certificate is not a fail-open change.
func TestMissingScopeHeaderIsRefused(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)
	w := doAs(h.data, asWeb, "GET", "/v1/object", map[string]string{
		HeaderKey: base64.StdEncoding.EncodeToString([]byte("app/apps/web/doc"))}, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("= %d, want 403 when the scope is not declared", w.Code)
	}
}

func TestDeclaredScopeMustMatchTheKey(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)
	w := doAs(h.data, asWeb, "GET", "/v1/object", objHeaders("app/doc", "not-the-scope"), nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("= %d, want 403 when the declared scope does not own the key", w.Code)
	}
}

// Logical keys are raw bytes that participate in authentication, so they must
// survive the wire byte-exactly — no Unicode normalization, no path cleaning.
// This is why they ride a base64 header rather than a URL.
func TestExoticKeysRoundTripByteExactly(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)

	keys := []string{
		// NFC and NFD of the same word, written as escapes: literal bytes
		// can be normalized by an editor or a tool, which would collapse
		// them into one key and make this test prove nothing.
		"app/apps/web/caf\u00e9",
		"app/apps/web/cafe\u0301",
		"app/apps/web/a b/c+d&e=f?g#h",   // characters a URL would mangle
		"app/apps/web/../literal",        // ".." is a literal segment here, not traversal
		"app/apps/web/tab\tand\nnewline", // bytes a header could not carry unencoded
		"app/apps/web/\U0001F511",        // outside the BMP
	}
	if keys[0] == keys[1] {
		t.Fatal("guard: the NFC and NFD forms collapsed; this test would prove nothing")
	}
	for _, k := range keys {
		body := []byte("value for " + k)
		if w := doAs(h.data, asWeb, "PUT", "/v1/object", objHeaders(k, appScopeName), body); w.Code != http.StatusNoContent {
			t.Fatalf("PUT %q = %d: %s", k, w.Code, w.Body)
		}
	}
	for _, k := range keys {
		w := doAs(h.data, asWeb, "GET", "/v1/object", objHeaders(k, appScopeName), nil)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %q = %d: %s", k, w.Code, w.Body)
		}
		if got, want := w.Body.String(), "value for "+k; got != want {
			t.Errorf("GET %q = %q, want %q", k, got, want)
		}
	}
	// NFC and NFD must be distinct objects, not one overwriting the other.
	if len(h.provider.objects) != len(keys) {
		t.Errorf("stored %d objects for %d distinct keys — a key was normalized", len(h.provider.objects), len(keys))
	}
}

// An error body is the easiest place for a logical name to escape into a log.
func TestErrorsNeverQuoteTheLogicalKey(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)
	secret := "app/apps/web/very-distinctive-object-name"

	w := doAs(h.data, asWeb, "GET", "/v1/object", objHeaders(secret, appScopeName), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("= %d, want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "very-distinctive") {
		t.Errorf("the error body quoted the logical key: %s", w.Body)
	}

	sealedResp := doAs(h.data, asWeb, "GET", "/v1/object", objHeaders("system/"+secret, appScopeName), nil)
	if strings.Contains(sealedResp.Body.String(), "very-distinctive") {
		t.Errorf("the refusal quoted the logical key: %s", sealedResp.Body)
	}
}

func TestOversizeObjectIsRefused(t *testing.T) {
	h := newHarness(t)
	h.srv.max = 32
	h.unseal(t, 1)
	w := doAs(h.data, asWeb, "PUT", "/v1/object", objHeaders("app/apps/web/big", appScopeName), bytes.Repeat([]byte("x"), 64))
	if w.Code != http.StatusRequestEntityTooLarge || w.Header().Get(HeaderCode) != CodeTooLarge {
		t.Fatalf("= %d/%q, want 413/%s", w.Code, w.Header().Get(HeaderCode), CodeTooLarge)
	}
}

func marshalBundle(t *testing.T, instance string, generation uint64) []byte {
	t.Helper()
	out, err := mustBundle(t, instance, generation).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return out
}

// push performs a real unseal: fetch the single-use challenge, seal the bundle
// to this process, and post it. Tests go through the same path an operator
// does, so nothing is proved against a shortcut that production cannot take.
func (h *harness) push(t *testing.T, instance string, generation uint64, intent Intent) *httptest.ResponseRecorder {
	t.Helper()
	cw := do(h.control, "GET", SealChallengePath, nil, nil)
	if cw.Code != http.StatusOK {
		t.Fatalf("challenge = %d: %s", cw.Code, cw.Body)
	}
	var ch Challenge
	if err := json.Unmarshal(cw.Body.Bytes(), &ch); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	sealed, err := SealBundle(marshalBundle(t, instance, generation), h.srv.cfg.Instance, ch)
	if err != nil {
		t.Fatalf("SealBundle: %v", err)
	}
	return do(h.control, "POST", "/v1/unseal?intent="+string(intent),
		map[string]string{"Content-Type": ContentTypeSealed}, sealed)
}

// safeMessage is the guard that stops a logical name escaping in an error
// body. No error in the code today embeds a key, so this pins the guard
// directly — otherwise the protection is unfalsifiable and the first error
// that does embed one would leak it silently.
func TestSafeMessageReducesToTheSentinel(t *testing.T) {
	name := "app/very-distinctive-object-name"
	cases := []error{
		fmt.Errorf("reading %q: %w", name, datasphere.ErrObjectNotFound),
		fmt.Errorf("%w: while resolving %s", ErrOutOfScope, name),
		fmt.Errorf("%w: object %s", datasphere.ErrIntegrity, name),
		fmt.Errorf("%w: key %s", datasphere.ErrInvalidKey, name),
	}
	for _, err := range cases {
		got := safeMessage(err)
		if strings.Contains(got, "very-distinctive") {
			t.Errorf("safeMessage(%v) leaked the logical key: %q", err, got)
		}
		if got == "" {
			t.Errorf("safeMessage(%v) said nothing; a caller still needs the classification", err)
		}
	}
	// An error matching no sentinel must not be echoed either.
	if got := safeMessage(errors.New("unexpected: " + name)); strings.Contains(got, "very-distinctive") {
		t.Errorf("safeMessage leaked an unclassified error: %q", got)
	}
}

// The application data path may read a secret and may not create or destroy
// one.
//
// This is not isolation and must not be read as isolation: the path
// authenticates the server only, and every application in the instance
// declares the same scope, so the keyholder cannot tell whose secret this is.
// What it can enforce is that no application plants a credential for a
// neighbour to pick up, or deletes one to force a fallback.
func TestSecretsAreReadOnlyOnTheDataPath(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)

	// The application's OWN secret, so the refusal below is the read-only
	// rule and not the ownership rule that resolve applies first.
	const key = "app/secrets/web/DB_PASSWORD"

	for _, tc := range []struct {
		method string
		body   []byte
	}{
		{"PUT", []byte("planted")},
		{"DELETE", nil},
	} {
		w := doAs(h.data, asWeb, tc.method, "/v1/object", objHeaders(key, appScopeName), tc.body)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", tc.method, w.Code)
		}
		if got := w.Header().Get(HeaderCode); got != CodePermission {
			t.Errorf("%s code = %q, want %q", tc.method, got, CodePermission)
		}
	}

	// Ordinary application storage is untouched by the rule.
	if w := doAs(h.data, asWeb, "PUT", "/v1/object", objHeaders("app/apps/web/reports/q3.csv", appScopeName), []byte("data")); w.Code != http.StatusNoContent {
		t.Errorf("writing ordinary storage = %d, want 204", w.Code)
	}
	if w := doAs(h.data, asWeb, "DELETE", "/v1/object", objHeaders("app/apps/web/reports/q3.csv", appScopeName), nil); w.Code != http.StatusNoContent {
		t.Errorf("deleting ordinary storage = %d, want 204", w.Code)
	}
}

// Listing is deliberately not refused: the parent prefix is listable, so a
// refusal would prevent nothing and would imply an enumeration boundary that
// does not exist. Asserted so that "hardening" it later is a deliberate act
// with ADR 0017 reopened, not a quiet one.
func TestSecretListingIsNotRefused(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)

	headers := map[string]string{
		HeaderPrefix: base64.StdEncoding.EncodeToString([]byte("app/apps/web/secrets/")),
		HeaderScope:  appScopeName,
	}
	if w := doAs(h.data, asWeb, "GET", "/v1/list", headers, nil); w.Code != http.StatusOK {
		t.Errorf("listing its own secrets subtree = %d, want 200", w.Code)
	}
}

// The boot label is the keeper fleet's reconciliation primitive, and it is
// disclosed only where the peer is authenticated.
//
// The status endpoint has to answer while sealed and is reachable by whatever
// can route to the port — the kubelet probes it — so how many times this
// instance has restarted does not belong there.
func TestBootLabelIsControlSurfaceOnly(t *testing.T) {
	h := newHarness(t)

	var public struct {
		Boot string `json:"boot"`
	}
	mustJSON(t, do(h.status, "GET", "/v1/state", nil, nil), &public)
	if public.Boot != "" {
		t.Errorf("the unauthenticated status endpoint disclosed a boot label: %q", public.Boot)
	}

	var control struct {
		Boot string `json:"boot"`
	}
	mustJSON(t, do(h.control, "GET", "/v1/state", nil, nil), &control)
	if control.Boot == "" {
		t.Fatal("the control surface reported no boot label; a keeper cannot record which process it seeded")
	}
	if len(control.Boot) != bootIDLen*2 {
		t.Errorf("boot = %q, want %d hex characters", control.Boot, bootIDLen*2)
	}

	// It rides every control response, because the push response is what a
	// keeper has in hand when it writes its ledger entry.
	h.unseal(t, 1)
	var afterUnseal struct {
		Boot string `json:"boot"`
	}
	mustJSON(t, do(h.control, "GET", "/v1/state", nil, nil), &afterUnseal)
	if afterUnseal.Boot != control.Boot {
		t.Errorf("the boot label changed within one process: %q then %q", control.Boot, afterUnseal.Boot)
	}
}

// Two processes are two labels. Without that, "reseeded twice" and "restarted
// twice" are indistinguishable in a ledger, and the audit ADR 0008 relies on
// cannot be performed.
func TestEachProcessGetsItsOwnBootLabel(t *testing.T) {
	seen := map[string]bool{}
	for range 8 {
		b := New("prod").State().Boot
		if b == "" {
			t.Fatal("a vault minted an empty boot label")
		}
		if seen[b] {
			t.Fatalf("two vaults share the boot label %q", b)
		}
		seen[b] = true
	}
}

// mustJSON decodes a recorded response body or fails the test.
func mustJSON(t *testing.T, w *httptest.ResponseRecorder, out any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
}

// Identities the data-path tests act as. Every leaf has already been verified
// by the listener by the time a handler runs, so a test supplies only what the
// handler reads: the URI on the peer certificate.
// The two applications the fixture bundle carries, and what their keys and
// scope names look like.
const (
	appScopeName = "app-apps-web"
	apiScopeName = "app-apps-api"
	webSecret    = "app/apps/web/secrets/DB"
	apiSecret    = "app/apps/api/secrets/DB"
)

// scopeOf names the scope a fixture key belongs to.
func scopeOf(key string) string {
	if strings.HasPrefix(key, "app/apps/api/") {
		return apiScopeName
	}
	return appScopeName
}

const (
	asWeb      = "farcast://prod/app/apps/web"
	asAPI      = "farcast://prod/app/apps/api"
	asOperator = "farcast://prod/operator"
	asDevice   = "farcast://prod/device/tablet"
	asKeeper   = "farcast://prod/keeper/laptop"
)

// doAs is do with a client identity on the connection. An empty uri is a
// request that arrived with no peer certificate at all.
func doAs(h http.Handler, uri, method, target string, headers map[string]string, body []byte) *httptest.ResponseRecorder {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, r)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			panic(err)
		}
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{u}}}}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// The shapes the keyholder parses are fatline/identity's; the modules mirror
// and do not import, so the same vectors live in both test files.
func TestParseIdentityMirrorsFatline(t *testing.T) {
	for uri, want := range map[string]Identity{
		"farcast://prod/operator":      {Role: RoleOperator, Instance: "prod"},
		"farcast://prod/keeper/laptop": {Role: RoleKeeper, Instance: "prod", Name: "laptop"},
		"farcast://prod/device/tablet": {Role: RoleDevice, Instance: "prod", Name: "tablet"},
		"farcast://prod/app/shop/api":  {Role: RoleApp, Instance: "prod", Namespace: "shop", Name: "api"},
	} {
		got, err := ParseIdentity(uri, "prod")
		if err != nil {
			t.Errorf("ParseIdentity(%q): %v", uri, err)
			continue
		}
		if got != want {
			t.Errorf("ParseIdentity(%q) = %+v, want %+v", uri, got, want)
		}
	}
	for _, bad := range []string{
		"", "farcast://staging/operator", "farcast://prod/keeper/", "farcast://prod/device",
		"farcast://prod/app/api", "farcast://prod/app//api", "farcast://prod/admin",
		"https://prod/operator", "farcast://prodx/operator", "farcast://prod/OPERATOR",
	} {
		if _, err := ParseIdentity(bad, "prod"); err == nil {
			t.Errorf("ParseIdentity(%q) accepted", bad)
		}
	}
}

// A data leaf never pushes; a keeper leaf never reads (ADR 0018 decision 2).
func TestAllowDataAdmitsEveryoneButKeepers(t *testing.T) {
	allow := AllowData("prod")
	for _, uri := range []string{asOperator, asDevice, asWeb} {
		if !allow(uri) {
			t.Errorf("AllowData refused %q", uri)
		}
	}
	for _, uri := range []string{asKeeper, "", "farcast://staging/operator", "farcast://prod/app/web"} {
		if allow(uri) {
			t.Errorf("AllowData admitted %q", uri)
		}
	}
	// And the control surface is the mirror image: a device never pushes.
	if AllowPusher("prod")(asDevice) {
		t.Error("AllowPusher admitted a device leaf to the control surface")
	}
}

// An application reaches its OWN scope. This is where the separation stops
// being a rule the keyholder enforces and starts being the keys themselves
// (ADR 0018 decision 5).
func TestMayReach(t *testing.T) {
	web, _ := ParseIdentity(asWeb, "prod")
	api, _ := ParseIdentity(asAPI, "prod")
	op, _ := ParseIdentity(asOperator, "prod")
	dev, _ := ParseIdentity(asDevice, "prod")
	keeper, _ := ParseIdentity(asKeeper, "prod")

	if !web.MayReach(appScopeName) {
		t.Errorf("web cannot reach its own scope %q", appScopeName)
	}
	for _, other := range []string{"app-apps-api", "app-other-web", "ops", "app"} {
		if web.MayReach(other) {
			t.Errorf("web reached %q, which is not its own", other)
		}
	}
	if api.MayReach(appScopeName) {
		t.Error("api reached web's scope")
	}
	if !op.MayReach("ops") || !dev.MayReach("ops") || !op.MayReach(appScopeName) {
		t.Error("the operator and a device reach every scope")
	}
	if keeper.MayReach(appScopeName) {
		t.Error("a keeper reaches storage")
	}
	// A namespace and name too long to compose a scope name reach nothing —
	// the mint would have failed too, so there is nothing there to reach.
	long, _ := ParseIdentity("farcast://prod/app/"+strings.Repeat("n", 40)+"/"+strings.Repeat("a", 40), "prod")
	if long.MayReach("anything") {
		t.Error("an uncomposable identity reached a scope")
	}
}

// The boundary ADR 0017 said the path could not hold, held — and now it is the
// keys rather than a rule: web's scope is not api's, so nothing web presents
// reaches anything of api's, secret or not.
func TestAnApplicationReachesItsOwnScopeAndNobodyElses(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)

	// The operator provisions both, through the data path, which it may do
	// because the path can tell it is the operator.
	for _, k := range []string{webSecret, apiSecret} {
		scope := scopeOf(k)
		if w := doAs(h.data, asOperator, "PUT", "/v1/object", objHeaders(k, scope), []byte("s3cret")); w.Code != http.StatusNoContent {
			t.Fatalf("operator PUT %s = %d, want 204", k, w.Code)
		}
	}

	if w := doAs(h.data, asWeb, "GET", "/v1/object", objHeaders(webSecret, appScopeName), nil); w.Code != http.StatusOK {
		t.Errorf("web reading its own secret = %d, want 200", w.Code)
	}
	w := doAs(h.data, asWeb, "GET", "/v1/object", objHeaders(apiSecret, apiScopeName), nil)
	if w.Code != http.StatusForbidden || w.Header().Get(HeaderCode) != CodePermission {
		t.Errorf("web reading api's secret = %d %q, want 403 permission", w.Code, w.Header().Get(HeaderCode))
	}
	if strings.Contains(w.Body.String(), "s3cret") {
		t.Error("a refused read carried the value")
	}
	// Ordinary objects too, which is what decision 5 adds over decision 1:
	// the neighbour boundary is no longer only about secrets.
	if w := doAs(h.data, asOperator, "PUT", "/v1/object", objHeaders("app/apps/api/report", apiScopeName), []byte("data")); w.Code != http.StatusNoContent {
		t.Fatalf("operator PUT api's object = %d", w.Code)
	}
	if w := doAs(h.data, asWeb, "GET", "/v1/object", objHeaders("app/apps/api/report", apiScopeName), nil); w.Code != http.StatusForbidden {
		t.Errorf("web reading api's ordinary object = %d, want 403", w.Code)
	}
	// Its own secrets subtree lists; a neighbour's scope does not.
	own := map[string]string{HeaderPrefix: base64.StdEncoding.EncodeToString([]byte("app/apps/web/secrets/")), HeaderScope: appScopeName}
	if w := doAs(h.data, asWeb, "GET", "/v1/list", own, nil); w.Code != http.StatusOK {
		t.Errorf("web listing its own secrets = %d, want 200", w.Code)
	}
	theirs := map[string]string{HeaderPrefix: base64.StdEncoding.EncodeToString([]byte("app/apps/api/secrets/")), HeaderScope: apiScopeName}
	if w := doAs(h.data, asWeb, "GET", "/v1/list", theirs, nil); w.Code != http.StatusForbidden {
		t.Errorf("web listing api's secrets = %d, want 403", w.Code)
	}
	// A device is the operator's hand and reaches all of them.
	if w := doAs(h.data, asDevice, "GET", "/v1/object", objHeaders(apiSecret, apiScopeName), nil); w.Code != http.StatusOK {
		t.Errorf("a device reading api's secret = %d, want 200", w.Code)
	}
}

// Applications still never create or destroy a secret; the operator and a
// device now can, through the same path.
func TestOnlyApplicationsAreRefusedSecretMutation(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)
	const key = "app/apps/web/secrets/TOKEN"
	if w := doAs(h.data, asWeb, "PUT", "/v1/object", objHeaders(key, appScopeName), []byte("x")); w.Code != http.StatusForbidden {
		t.Errorf("app PUT its own secret = %d, want 403", w.Code)
	}
	if w := doAs(h.data, asDevice, "PUT", "/v1/object", objHeaders(key, appScopeName), []byte("x")); w.Code != http.StatusNoContent {
		t.Errorf("device PUT = %d, want 204", w.Code)
	}
	if w := doAs(h.data, asWeb, "DELETE", "/v1/object", objHeaders(key, appScopeName), nil); w.Code != http.StatusForbidden {
		t.Errorf("app DELETE its own secret = %d, want 403", w.Code)
	}
	if w := doAs(h.data, asOperator, "DELETE", "/v1/object", objHeaders(key, appScopeName), nil); w.Code != http.StatusNoContent {
		t.Errorf("operator DELETE = %d, want 204", w.Code)
	}
}

// The handler refuses what the listener would already have refused, so a
// composition root that wired it behind the wrong listener fails closed.
func TestDataPathRefusesKeepersAndTheUnidentified(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)
	for name, uri := range map[string]string{"a keeper": asKeeper, "no identity": ""} {
		w := doAs(h.data, uri, "GET", "/v1/object", objHeaders("app/apps/web/doc", appScopeName), nil)
		if w.Code != http.StatusForbidden || w.Header().Get(HeaderCode) != CodePermission {
			t.Errorf("%s = %d %q, want 403 permission", name, w.Code, w.Header().Get(HeaderCode))
		}
	}
	// Identity is checked before anything else: an unidentified caller does
	// not learn that the keyholder is sealed.
	sealed := newHarness(t)
	if w := doAs(sealed.data, "", "GET", "/v1/object", objHeaders("app/apps/web/doc", appScopeName), nil); w.Header().Get(HeaderCode) == CodeSealed {
		t.Error("an unidentified caller was told the keyholder is sealed")
	}
}

// The scope header stays as a cross-check and is no longer what authorizes.
func TestScopeHeaderIsACrossCheckNotAnAuthorization(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)
	// Right identity, wrong declared scope: refused, as before.
	if w := doAs(h.data, asWeb, "GET", "/v1/object", objHeaders("app/apps/web/doc", "ops"), nil); w.Code != http.StatusForbidden {
		t.Errorf("mismatched scope header = %d, want 403", w.Code)
	}
	// The declared scope cannot widen what the identity may reach: a keeper
	// naming the right scope is still a keeper.
	if w := doAs(h.data, asKeeper, "GET", "/v1/object", objHeaders("app/apps/web/doc", appScopeName), nil); w.Code != http.StatusForbidden {
		t.Errorf("a keeper declaring the scope = %d, want 403", w.Code)
	}
}
