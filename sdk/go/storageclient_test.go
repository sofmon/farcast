package farcast

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeKeyholder stands in for datasphered: a TLS data path and a plain status
// endpoint, the same split the real deployment has.
type fakeKeyholder struct {
	data   *httptest.Server
	status *httptest.Server

	objects map[string][]byte
	// sawBody records whether any request arrived carrying a payload, so a
	// test can assert that a refusal happened before anything was sent.
	sawBody  bool
	sawKeys  []string
	sawScope string
	phase    string
	code     string // when set, every data request is refused with this code
}

func newFakeKeyholder(t *testing.T) *fakeKeyholder {
	t.Helper()
	f := &fakeKeyholder{objects: map[string][]byte{}, phase: "unsealed"}

	f.data = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.sawScope = r.Header.Get(headerScope)
		if r.ContentLength > 0 {
			f.sawBody = true
		}
		if f.code != "" {
			w.Header().Set(headerCode, f.code)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		switch {
		case r.URL.Path == "/v1/list":
			prefix := decodeHeader(r.Header.Get(headerPrefix))
			keys := []string{}
			for k := range f.objects {
				if strings.HasPrefix(k, prefix) {
					keys = append(keys, k)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
		case r.Method == http.MethodGet:
			key := decodeHeader(r.Header.Get(headerKey))
			f.sawKeys = append(f.sawKeys, key)
			data, ok := f.objects[key]
			if !ok {
				w.Header().Set(headerCode, "not-found")
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(data)
		case r.Method == http.MethodPut:
			key := decodeHeader(r.Header.Get(headerKey))
			f.sawKeys = append(f.sawKeys, key)
			buf := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(buf)
			f.objects[key] = buf
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete:
			delete(f.objects, decodeHeader(r.Header.Get(headerKey)))
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(f.data.Close)

	f.status = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > 0 {
			f.sawBody = true
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"phase": f.phase, "since": time.Now(), "generation": 3,
		})
	}))
	t.Cleanup(f.status.Close)
	return f
}

func decodeHeader(v string) string {
	raw, _ := base64.StdEncoding.DecodeString(v)
	return string(raw)
}

func (f *fakeKeyholder) client(t *testing.T) *storageClient {
	t.Helper()
	c, err := newStorageClient(f.data.URL, f.status.URL, "app", certPEM(t, f.data.Certificate()), "")
	if err != nil {
		t.Fatalf("newStorageClient: %v", err)
	}
	return c
}

func certPEM(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return pemEncode(cert.Raw)
}

func pemEncode(der []byte) []byte {
	const header = "-----BEGIN CERTIFICATE-----\n"
	const footer = "-----END CERTIFICATE-----\n"
	b64 := base64.StdEncoding.EncodeToString(der)
	var out strings.Builder
	out.WriteString(header)
	for len(b64) > 64 {
		out.WriteString(b64[:64] + "\n")
		b64 = b64[64:]
	}
	out.WriteString(b64 + "\n" + footer)
	return []byte(out.String())
}

func TestClientRoundTrip(t *testing.T) {
	f := newFakeKeyholder(t)
	c := f.client(t)
	ctx := context.Background()

	if err := c.Write(ctx, "app/doc", []byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := c.Read(ctx, "app/doc")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("Read = %q", got)
	}
	keys, err := c.List(ctx, "app/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != "app/doc" {
		t.Errorf("List = %v", keys)
	}
	if err := c.Delete(ctx, "app/doc"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.Read(ctx, "app/doc"); !errors.Is(err, ErrObjectNotFound) {
		t.Errorf("Read after delete = %v, want ErrObjectNotFound", err)
	}
	if f.sawScope != "app" {
		t.Errorf("the scope header was not sent: %q", f.sawScope)
	}
}

// Logical keys must reach the keyholder byte-exactly: they participate in
// authentication and are never normalized.
func TestClientKeysSurviveTheWire(t *testing.T) {
	f := newFakeKeyholder(t)
	c := f.client(t)
	ctx := context.Background()

	// The first two are the SAME WORD in NFC and NFD. They are written as
	// escapes rather than literal bytes because an editor or a tool that
	// normalizes the source file would silently collapse them into one key
	// and this test would then prove nothing.
	keys := []string{
		"app/caf\u00e9",       // NFC: é as one code point
		"app/cafe\u0301",      // NFD: e + combining acute
		"app/a b/c+d&e=f?g#h", // characters a URL would mangle
		"app/../literal",      // ".." is a literal segment, not traversal
		"app/tab\tnewline\n",  // bytes a header could not carry unencoded
		"app/\U0001F511",      // outside the BMP
	}
	if keys[0] == keys[1] {
		t.Fatal("guard: the NFC and NFD forms collapsed; this test would prove nothing")
	}
	for _, k := range keys {
		if err := c.Write(ctx, k, []byte("v")); err != nil {
			t.Fatalf("Write %q: %v", k, err)
		}
	}
	if len(f.objects) != len(keys) {
		t.Fatalf("stored %d objects for %d distinct keys — a key was normalized", len(f.objects), len(keys))
	}
	for _, k := range keys {
		if _, ok := f.objects[k]; !ok {
			t.Errorf("the keyholder never saw %q as written", k)
		}
	}
}

func TestClientMapsWireCodes(t *testing.T) {
	f := newFakeKeyholder(t)
	c := f.client(t)
	for code, want := range map[string]error{
		CodeSealed:     ErrStorageSealed,
		CodeNotFound:   ErrObjectNotFound,
		CodeIntegrity:  ErrIntegrity,
		CodeInvalidKey: ErrInvalidKey,
		CodeTooLarge:   ErrTooLarge,
		CodePermission: ErrPermission,
		"brand-new":    ErrStorageUnavailable,
	} {
		f.code = code
		if _, err := c.Read(context.Background(), "app/x"); !errors.Is(err, want) {
			t.Errorf("code %q mapped to %v, want %v", code, err, want)
		}
	}
}

// The flagship case. The data Service is readiness-gated, so when every
// replica is sealed it has NO endpoints and the client sees a dial failure,
// not a 503. Without the status fallback an application would receive an
// opaque transport error in exactly the situation ADR 0008 fixed this
// contract for.
func TestSealedFleetYieldsErrStorageSealedNotATransportError(t *testing.T) {
	f := newFakeKeyholder(t)
	c := f.client(t)
	f.phase = "restart-sealed"
	f.data.Close() // every replica sealed: the data Service has no endpoints

	ctx := context.Background()
	if _, err := c.Read(ctx, "app/doc"); !errors.Is(err, ErrStorageSealed) {
		t.Fatalf("Read = %v, want ErrStorageSealed", err)
	}
	if err := c.Write(ctx, "app/doc", []byte("x")); !errors.Is(err, ErrStorageSealed) {
		t.Errorf("Write = %v, want ErrStorageSealed", err)
	}
	if err := c.Delete(ctx, "app/doc"); !errors.Is(err, ErrStorageSealed) {
		t.Errorf("Delete = %v, want ErrStorageSealed", err)
	}
	keys, err := c.List(ctx, "app/")
	if !errors.Is(err, ErrStorageSealed) {
		t.Errorf("List = %v, want ErrStorageSealed", err)
	}
	if keys != nil {
		t.Error("a sealed List returned a slice; an application could read that as an empty bucket")
	}
}

// Unreachable data path AND unreachable status: honest unavailability, never a
// seal an operator cannot clear because there is nothing to unseal.
func TestBothPathsDownIsUnavailableNotSealed(t *testing.T) {
	f := newFakeKeyholder(t)
	c := f.client(t)
	f.data.Close()
	f.status.Close()
	err := errFrom(c.Read(context.Background(), "app/doc"))
	if !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("= %v, want ErrStorageUnavailable", err)
	}
	if errors.Is(err, ErrStorageSealed) {
		t.Error("an unreachable instance was reported as sealed")
	}
}

// Status claims ready but the data path is down: report what is true, not what
// is convenient.
func TestReadyStatusWithDeadDataPathIsUnavailable(t *testing.T) {
	f := newFakeKeyholder(t)
	c := f.client(t)
	f.phase = "unsealed"
	f.data.Close()
	err := errFrom(c.Read(context.Background(), "app/doc"))
	if !errors.Is(err, ErrStorageUnavailable) || errors.Is(err, ErrStorageSealed) {
		t.Fatalf("= %v, want ErrStorageUnavailable", err)
	}
}

// A misconfiguration is neither "this build never can" nor "wait for an
// operator". Both would waste an outage.
func TestBrokenConfigurationIsNeitherStubNorSeal(t *testing.T) {
	cases := []struct{ name, endpoint, status, scope, ca string }{
		{"no CA", "https://k:8443", "http://s:8444", "app", ""},
		{"garbage CA", "https://k:8443", "http://s:8444", "app", "not a certificate"},
		{"plain http endpoint", "http://k:8443", "http://s:8444", "app", "x"},
		{"no scope", "https://k:8443", "http://s:8444", "", "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newStorageClient(tc.endpoint, tc.status, tc.scope, []byte(tc.ca), "")
			if err == nil {
				t.Fatal("an unusable configuration was accepted")
			}
			if errors.Is(err, ErrNotImplemented) {
				t.Error("a misconfiguration reported as ErrNotImplemented")
			}
			if errors.Is(err, ErrStorageSealed) {
				t.Error("a misconfiguration reported as a seal")
			}
			broken := storageBroken{err: err}
			if _, e := broken.Read(context.Background(), "k"); !errors.Is(e, err) {
				t.Error("storageBroken did not carry its cause")
			}
		})
	}
}

// The status endpoint is plain HTTP and unauthenticated. Its word decides only
// how an ALREADY-FAILED operation is reported; it must never receive data and
// must never cause an operation to be sent to an unverified peer.
func TestStatusEndpointNeverReceivesData(t *testing.T) {
	f := newFakeKeyholder(t)
	c := f.client(t)
	f.phase = "restart-sealed"
	f.data.Close()
	f.sawBody = false

	if err := c.Write(context.Background(), "app/doc", []byte("SECRET-PAYLOAD")); !errors.Is(err, ErrStorageSealed) {
		t.Fatalf("Write = %v, want ErrStorageSealed", err)
	}
	if f.sawBody {
		t.Fatal("a payload reached the unauthenticated status endpoint")
	}
}

// A peer that is not the configured keyholder must be refused by TLS, and the
// payload must not have left the process.
func TestUntrustedPeerIsRefusedBeforeAnyPayloadIsSent(t *testing.T) {
	real := newFakeKeyholder(t)
	impostor := newFakeKeyholder(t)

	// Point the client at the impostor while trusting a DIFFERENT authority.
	//
	// The trusted CA is minted here rather than taken from the other fake:
	// every httptest TLS server presents the same built-in certificate, so
	// trusting one would trust the impostor too and this test would pass
	// without verifying anything.
	_ = real
	c, err := newStorageClient(impostor.data.URL, impostor.status.URL, "app", freshCAPEM(t), "")
	if err != nil {
		t.Fatalf("newStorageClient: %v", err)
	}
	impostor.sawBody = false
	impostor.phase = "unsealed"

	if err := c.Write(context.Background(), "app/doc", []byte("SECRET-PAYLOAD")); err == nil {
		t.Fatal("the client wrote to a peer it could not verify")
	}
	if impostor.sawBody {
		t.Fatal("the payload reached an unverified peer")
	}
	if len(impostor.objects) != 0 {
		t.Fatal("the impostor stored an object")
	}
}

// A build that does not understand a newer keyholder's phase must not conclude
// storage is working.
func TestUnknownPhaseIsTreatedAsSealed(t *testing.T) {
	for _, phase := range []string{"", "quiesced", "draining", "UNSEALED"} {
		st := statusFromPhase(phase, time.Time{}, 0)
		if !st.Sealed() {
			t.Errorf("phase %q was read as ready", phase)
		}
	}
	if st := statusFromPhase("unsealed", time.Time{}, 0); st.Sealed() {
		t.Error("unsealed was read as sealed")
	}
	if st := statusFromPhase("operator-hold", time.Time{}, 0); st.Reason != SealOperator {
		t.Errorf("operator-hold reason = %q", st.Reason)
	}
}

// The optional seam must be discoverable on the real client.
func TestClientImplementsTheStatusSeam(t *testing.T) {
	f := newFakeKeyholder(t)
	c := f.client(t)
	st, err := StorageStatusOf(context.Background(), c)
	if err != nil {
		t.Fatalf("StorageStatusOf: %v", err)
	}
	if st.State != StorageReady || st.Generation != 3 {
		t.Errorf("status = %+v", st)
	}
}

func errFrom(_ []byte, err error) error { return err }

// freshCAPEM mints a self-signed certificate that no fake server presents, so
// a client trusting only it must refuse every one of them.
func freshCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "not-the-keyholder"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return pemEncode(der)
}

// The three outcomes of reading the environment must stay distinct. This
// covers the wiring itself, not just the constructor: a build that degraded a
// misconfiguration to the stub would tell every application that storage is
// permanently unavailable in this build, and they would stop trying.
func TestStorageFromEnvHasThreeDistinctOutcomes(t *testing.T) {
	f := newFakeKeyholder(t)

	t.Run("no endpoint is the stub", func(t *testing.T) {
		t.Setenv(envStorageEndpoint, "")
		s := newStorageFromEnv()
		if _, ok := s.(storageStub); !ok {
			t.Fatalf("got %T, want the stub", s)
		}
		if _, err := s.Read(context.Background(), "k"); !errors.Is(err, ErrNotImplemented) {
			t.Errorf("stub Read = %v", err)
		}
	})

	t.Run("a misconfiguration is broken, not the stub", func(t *testing.T) {
		t.Setenv(envStorageEndpoint, "https://keyholder:8443")
		t.Setenv(envStorageStatus, "http://keyholder-status:8444")
		t.Setenv(envStorageScope, "app")
		t.Setenv(envStorageCA, "this is not a certificate")

		s := newStorageFromEnv()
		if _, ok := s.(storageStub); ok {
			t.Fatal("a misconfiguration degraded to the stub; applications would stop trying")
		}
		_, err := s.Read(context.Background(), "k")
		if errors.Is(err, ErrNotImplemented) {
			t.Error("a misconfiguration reported as ErrNotImplemented")
		}
		if errors.Is(err, ErrStorageSealed) {
			t.Error("a misconfiguration reported as a seal; nobody can unseal a bad CA")
		}
		if !errors.Is(err, ErrStorageUnavailable) {
			t.Errorf("= %v, want ErrStorageUnavailable", err)
		}
	})

	t.Run("a complete configuration is live", func(t *testing.T) {
		t.Setenv(envStorageEndpoint, f.data.URL)
		t.Setenv(envStorageStatus, f.status.URL)
		t.Setenv(envStorageScope, "app")
		t.Setenv(envStorageCA, string(certPEM(t, f.data.Certificate())))

		s := newStorageFromEnv()
		if _, ok := s.(*storageClient); !ok {
			t.Fatalf("got %T, want a live client", s)
		}
		if err := s.Write(context.Background(), "app/doc", []byte("v")); err != nil {
			t.Errorf("Write through the env-built client: %v", err)
		}
	})
}

// The address an application dials and the identity the keyholder must present
// are different things. A keyholder's certificate carries a synthetic,
// instance-scoped name verified against the instance's own CA; the address is
// whatever the platform routes to — a cluster Service, a port-forward, a
// future carrier. Conflating them makes the client unusable from inside a
// cluster, which is the only place it will ever actually run.
func TestServerNameIsSeparableFromTheAddress(t *testing.T) {
	f := newFakeKeyholder(t)

	// The fake's certificate is issued for "example.com"/127.0.0.1, never for
	// this name, so a client that verifies against it must fail.
	c, err := newStorageClient(f.data.URL, f.status.URL, "app",
		certPEM(t, f.data.Certificate()), "p32.datasphered.farcast")
	if err != nil {
		t.Fatalf("newStorageClient: %v", err)
	}
	f.phase = "unsealed"
	if err := c.Write(context.Background(), "app/doc", []byte("v")); err == nil {
		t.Fatal("the client accepted a peer that does not present the pinned name")
	}
	if f.sawBody {
		t.Fatal("a payload reached a peer whose identity was not verified")
	}

	// With no override the endpoint's own host is the identity, which is what
	// every existing caller relies on.
	plain := f.client(t)
	if err := plain.Write(context.Background(), "app/doc", []byte("v")); err != nil {
		t.Errorf("an un-overridden client failed: %v", err)
	}
}
