package keyholder

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

	if w := do(h.data, "PUT", "/v1/object", objHeaders("app/doc", "app"), payload); w.Code != http.StatusNoContent {
		t.Fatalf("PUT = %d: %s", w.Code, w.Body)
	}
	w := do(h.data, "GET", "/v1/object", objHeaders("app/doc", "app"), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d: %s", w.Code, w.Body)
	}
	if !bytes.Equal(w.Body.Bytes(), payload) {
		t.Errorf("round trip = %q, want %q", w.Body.Bytes(), payload)
	}

	lw := do(h.data, "GET", "/v1/list", map[string]string{
		HeaderPrefix: base64.StdEncoding.EncodeToString([]byte("app/")),
		HeaderScope:  "app",
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
	if len(listed.Keys) != 1 || listed.Keys[0] != "app/doc" {
		t.Errorf("list = %v, want [app/doc]", listed.Keys)
	}

	if w := do(h.data, "DELETE", "/v1/object", objHeaders("app/doc", "app"), nil); w.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", w.Code)
	}
	if w := do(h.data, "GET", "/v1/object", objHeaders("app/doc", "app"), nil); w.Code != http.StatusNotFound {
		t.Errorf("GET after delete = %d, want 404", w.Code)
	}

	// The cloud saw only tokenized names.
	for name := range h.provider.objects {
		if strings.Contains(name, "app/doc") || strings.Contains(name, "doc") {
			t.Errorf("the provider holds a recognizable logical name: %q", name)
		}
	}
}

// Every verb must report a seal as a seal — never as absence, never as a bare
// transport failure.
func TestSealedDataPathReportsSealed(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)
	if w := do(h.data, "PUT", "/v1/object", objHeaders("app/doc", "app"), []byte("x")); w.Code != http.StatusNoContent {
		t.Fatalf("setup PUT = %d", w.Code)
	}
	h.vault.Seal(false, "")

	cases := []struct {
		method, target string
		headers        map[string]string
		body           []byte
	}{
		{"GET", "/v1/object", objHeaders("app/doc", "app"), nil},
		{"PUT", "/v1/object", objHeaders("app/doc", "app"), []byte("x")},
		{"DELETE", "/v1/object", objHeaders("app/doc", "app"), nil},
		{"GET", "/v1/list", map[string]string{
			HeaderPrefix: base64.StdEncoding.EncodeToString([]byte("app/")), HeaderScope: "app"}, nil},
	}
	for _, tc := range cases {
		w := do(h.data, tc.method, tc.target, tc.headers, tc.body)
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
	w := do(h.data, "GET", "/v1/list", map[string]string{
		HeaderPrefix: base64.StdEncoding.EncodeToString([]byte("app/")), HeaderScope: "app"}, nil)
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

	w := do(h.data, "GET", "/v1/object", objHeaders("system/secret", "app"), nil)
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
	w := do(h.data, "GET", "/v1/object", map[string]string{
		HeaderKey: base64.StdEncoding.EncodeToString([]byte("app/doc"))}, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("= %d, want 403 when the scope is not declared", w.Code)
	}
}

func TestDeclaredScopeMustMatchTheKey(t *testing.T) {
	h := newHarness(t)
	h.unseal(t, 1)
	w := do(h.data, "GET", "/v1/object", objHeaders("app/doc", "not-the-scope"), nil)
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
		"app/café",              // NFC
		"app/café",             // NFD — a different key, and must stay one
		"app/a b/c+d&e=f?g#h",   // characters a URL would mangle
		"app/../literal",        // ".." is a literal segment here, not traversal
		"app/tab\tand\nnewline", // bytes a header could not carry unencoded
		"app/\U0001F511",        // outside the BMP
	}
	for _, k := range keys {
		body := []byte("value for " + k)
		if w := do(h.data, "PUT", "/v1/object", objHeaders(k, "app"), body); w.Code != http.StatusNoContent {
			t.Fatalf("PUT %q = %d: %s", k, w.Code, w.Body)
		}
	}
	for _, k := range keys {
		w := do(h.data, "GET", "/v1/object", objHeaders(k, "app"), nil)
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
	secret := "app/very-distinctive-object-name"

	w := do(h.data, "GET", "/v1/object", objHeaders(secret, "app"), nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("= %d, want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "very-distinctive") {
		t.Errorf("the error body quoted the logical key: %s", w.Body)
	}

	sealedResp := do(h.data, "GET", "/v1/object", objHeaders("system/"+secret, "app"), nil)
	if strings.Contains(sealedResp.Body.String(), "very-distinctive") {
		t.Errorf("the refusal quoted the logical key: %s", sealedResp.Body)
	}
}

func TestOversizeObjectIsRefused(t *testing.T) {
	h := newHarness(t)
	h.srv.max = 32
	h.unseal(t, 1)
	w := do(h.data, "PUT", "/v1/object", objHeaders("app/big", "app"), bytes.Repeat([]byte("x"), 64))
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
