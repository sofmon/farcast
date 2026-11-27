package kube

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fedProvider is a provider's JSON as Google's get answers it [PROV], with
// its state.
func fedProvider(id, state string) string {
	return `{"name":"projects/123456789012/locations/global/workloadIdentityPools/pool1234/providers/` + id + `","state":"` + state + `",` +
		`"attributeMapping":{"google.subject":"assertion.issuer.dn.cn"},` +
		`"attributeCondition":"assertion.issuer.dn.cn == '` + fedHexID + `' && assertion.subject.dn.cn == '` + fedHexID + `'",` +
		`"x509":{"trustStore":{"trustAnchors":[{"pemCertificate":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}]}}}`
}

// TestIAMReaderRefusesAWriter is R1's local half: IAM's API is read with the
// reader's federated credential alone. A key, the zero Credential and the
// writer's federated credential are refused before anything is built,
// minted or dialled, each with its whole text. (That a writer's token sent
// to IAM's API is refused there is kubetest's IAM API fake's, in package
// kube_test.)
func TestIAMReaderRefusesAWriter(t *testing.T) {
	fed, l := fedCountingFederation(t)
	id := newFedIdentity(t, fedHexID)
	ci := NewClientIdentity([][]byte{id.leafDER}, id.key)
	writer, err := NewFederatedCredential(fed, fedAudience, ci, fedEmail, Writer)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		cred Credential
		want string
	}{
		{"the writer's federated credential", writer,
			"kube: IAM's API is read with the reader's federated credential alone, and this one is the writer's; nothing was sent"},
		{"the installer's key", googleCredential(t),
			"kube: IAM's API is read with the reader's federated credential alone, and this credential is not federated; nothing was sent"},
		{"a reader key", Credential{Email: fedEmail, PrivateKeyPEM: []byte(rsaPKCS8PEM(t))},
			"kube: IAM's API is read with the reader's federated credential alone, and this credential is not federated; nothing was sent"},
		{"the zero Credential", Credential{},
			"kube: IAM's API is read with the reader's federated credential alone, and this credential is not federated; nothing was sent"},
	} {
		r, err := NewIAMReader(c.cred)
		if r != nil || !errors.Is(err, ErrEndpointRefused) || err.Error() != c.want {
			t.Errorf("%s: %v, %v; want %q", c.name, r != nil, err, c.want)
		}
	}
	reader, err := NewFederatedCredential(fed, fedAudience, ci, fedEmail, Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewIAMReader(reader)
	if err != nil {
		t.Fatal(err)
	}
	if v := r.get(); v.tokens.Role() != Reader || v.tokens.Scopes() != scopesIAM || !v.tokens.Federated() || v.host != fed.iamAPI {
		t.Error("the reader's IAM reader is not the reader's, at IAM's scopes, at the IAM API host")
	}
	if n := l.accepted(t); n != 0 {
		t.Errorf("%d connections were made", n)
	}
}

// TestIAMReaderRefusesMalformedParts: a read's project number, pool and
// provider are shape-checked before anything is built or sent, and the
// refusal names the part, never its value.
func TestIAMReaderRefusesMalformedParts(t *testing.T) {
	fake := newFedFake(t)
	r, err := NewIAMReader(fake.credential(t, Reader))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, part, number, pool, provider string
	}{
		{"a project ID", "project number", "my-project-1", "pool1234", "prov1234"},
		{"no project", "project number", "", "pool1234", "prov1234"},
		{"21 digits", "project number", strings.Repeat("1", 21), "pool1234", "prov1234"},
		{"a path in the number", "project number", "123/../456", "pool1234", "prov1234"},
		{"a query in the pool", "pool", "123456789012", "pool1234?x=1", "prov1234"},
		{"a gcp- pool", "pool", "123456789012", "gcp-pool", "prov1234"},
		{"an upper-case pool", "pool", "123456789012", "Pool1234", "prov1234"},
		{"a path in the provider", "provider", "123456789012", "pool1234", "prov1234/../x"},
		{"a short provider", "provider", "123456789012", "pool1234", "abc"},
		{"a planted provider", "provider", "123456789012", "pool1234", fedSecretMarker},
	} {
		want := "kube: the IAM read has no usable " + c.part + "; nothing was sent"
		body, err := r.GetProvider(t.Context(), c.number, c.pool, c.provider)
		if body != nil || !errors.Is(err, ErrCredentialInvalid) || err.Error() != want {
			t.Errorf("get, %s: %v; want %q", c.name, err, want)
		}
		if c.part != "provider" {
			pages, err := r.ListProviders(t.Context(), c.number, c.pool)
			if pages != nil || !errors.Is(err, ErrCredentialInvalid) || err.Error() != want {
				t.Errorf("list, %s: %v; want %q", c.name, err, want)
			}
		}
	}
	var zero IAMReader
	if _, err := zero.GetProvider(t.Context(), "123456789012", "pool1234", "prov1234"); !errors.Is(err, ErrCredentialInvalid) ||
		err.Error() != "kube: the IAM read has no usable request; nothing was sent" {
		t.Errorf("the zero IAMReader: %v", err)
	}
	var none context.Context // a nil context is what the guard refuses
	if _, err := r.GetProvider(none, "123456789012", "pool1234", "prov1234"); !errors.Is(err, ErrCredentialInvalid) {
		t.Errorf("a nil context: %v", err)
	}
	if n := len(fake.requests("sts")) + len(fake.requests("iam")) + len(fake.requests("api")); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
}

// TestGetProviderReadsOneProvider: a get is exactly
// GET /v1/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>,
// with no query, the reader's service-account bearer, Accept JSON,
// User-Agent farcast and no other header, over a connection that presented
// no certificate (R2), and its answer comes back byte for byte.
func TestGetProviderReadsOneProvider(t *testing.T) {
	fake := newFedFake(t)
	want := fedProvider("prov1234", "DELETED")
	fake.set(func(f *fedFake) {
		f.apiAnswer = func(r *http.Request) (int, string) { return http.StatusOK, want }
	})
	r, err := NewIAMReader(fake.credential(t, Reader))
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.GetProvider(t.Context(), "123456789012", "pool1234", "prov1234")
	if err != nil || string(got) != want {
		t.Fatalf("GetProvider = %.60q, %v", got, err)
	}
	api := fake.requests("api")
	if len(api) != 1 {
		t.Fatalf("%d IAM API requests, want 1", len(api))
	}
	a := api[0]
	if a.method != http.MethodGet || a.path != "/v1/projects/123456789012/locations/global/workloadIdentityPools/pool1234/providers/prov1234" || a.query != "" {
		t.Errorf("sent %s %s?%s", a.method, a.path, a.query)
	}
	if a.bearer != "sa" || a.certs != 0 || strings.Join(a.headers, ",") != "Accept,Authorization,User-Agent" {
		t.Errorf("bearer %q, %d certificates, headers %q", a.bearer, a.certs, a.headers)
	}
	if bodies := fake.impersonationBodies(); len(bodies) != 1 || bodies[0] != string(ImpersonationBody(ScopesCluster)) {
		t.Errorf("the reader's impersonations: %q, want one with TokenScopes", bodies)
	}
	for _, server := range []string{"iam", "api"} {
		for _, req := range fake.requests(server) {
			if req.certs != 0 {
				t.Errorf("a %s connection presented a certificate", server)
			}
		}
	}
}

// TestListProvidersPagesAndDeleted: a list asks for ten a page and the
// soft-deleted providers, follows each page's token (escaped), returns every
// page's body in order, deleted entries included, and stops at the page
// with none. It refuses a token already given, more than 50 pages, a page
// over 1 MiB, a page that is not one JSON object with no key twice, a token
// out of its shape, and any status but 200 (a 401 aside, which
// re-impersonates once).
func TestListProvidersPagesAndDeleted(t *testing.T) {
	const base = "/v1/projects/123456789012/locations/global/workloadIdentityPools/pool1234/providers"
	page := func(entries []string, next string) string {
		s := `{"workloadIdentityPoolProviders":[` + strings.Join(entries, ",") + `]`
		if next != "" {
			s += `,"nextPageToken":"` + next + `"`
		}
		return s + "}"
	}
	t.Run("three pages", func(t *testing.T) {
		fake := newFedFake(t)
		pages := map[string]string{
			"":       page([]string{fedProvider("prov-aaaa", "ACTIVE")}, "p+2/="),
			"p+2/=":  page([]string{fedProvider("prov-bbbb", "DELETED")}, "p3~._-"),
			"p3~._-": `{"workloadIdentityPoolProviders":[` + fedProvider("prov-cccc", "ACTIVE") + `],"nextPageToken":null}`,
		}
		fake.set(func(f *fedFake) {
			f.apiAnswer = func(r *http.Request) (int, string) { return http.StatusOK, pages[r.URL.Query().Get("pageToken")] }
		})
		r, err := NewIAMReader(fake.credential(t, Reader))
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.ListProviders(t.Context(), "123456789012", "pool1234")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 || string(got[0]) != pages[""] || string(got[1]) != pages["p+2/="] || string(got[2]) != pages["p3~._-"] {
			t.Fatalf("%d pages, not the three answered, in order", len(got))
		}
		if !strings.Contains(string(got[1]), `"state":"DELETED"`) {
			t.Error("the deleted provider's page lost it")
		}
		var queries []string
		for _, a := range fake.requests("api") {
			if a.path != base || a.method != http.MethodGet {
				t.Errorf("sent %s %s", a.method, a.path)
			}
			queries = append(queries, a.query)
		}
		want := []string{
			"pageSize=10&showDeleted=true",
			"pageSize=10&showDeleted=true&pageToken=p%2B2%2F%3D",
			"pageSize=10&showDeleted=true&pageToken=p3~._-",
		}
		if strings.Join(queries, "|") != strings.Join(want, "|") {
			t.Errorf("queries %q, want %q", queries, want)
		}
		if n := len(fake.impersonationBodies()); n != 1 {
			t.Errorf("%d impersonations for one list, want 1", n)
		}
	})

	for _, c := range []struct {
		name    string
		answer  func(n int) (int, string)
		pages   int // requests sent
		want    string
		refused bool // ErrIAMRefused rather than ErrUnreadable
	}{
		{"a token given before", func(n int) (int, string) {
			return http.StatusOK, page(nil, []string{"tok-a", "tok-b", "tok-a"}[min(n, 2)])
		}, 3, "kube: IAM answered without a usable provider read (a nextPageToken given before)", false},
		{"an empty page that repeats its token", func(int) (int, string) { return http.StatusOK, page(nil, "same") }, 2,
			"kube: IAM answered without a usable provider read (a nextPageToken given before)", false},
		{"more than 50 pages", func(n int) (int, string) { return http.StatusOK, page(nil, fmt.Sprintf("tok-%d", n)) }, 50,
			"kube: IAM answered without a usable provider read (more than 50 pages)", false},
		{"a page over 1 MiB", func(int) (int, string) {
			return http.StatusOK, `{"workloadIdentityPoolProviders":[],"pad":"` + strings.Repeat("a", 1<<20) + `"}`
		}, 1, "kube: IAM answered without a usable provider read (the answer is larger than 1 MiB)", false},
		{"a second page that fails", func(n int) (int, string) {
			if n == 1 {
				return http.StatusInternalServerError, `{"error":{"code":500,"message":"` + fedPlanted + `","status":"INTERNAL"}}`
			}
			return http.StatusOK, page(nil, "tok-1")
		}, 2, "kube: IAM refused the provider read (500 Internal Server Error, status INTERNAL)", true},
		{"a redirect", func(int) (int, string) { return http.StatusFound, "" }, 1,
			"kube: IAM refused the provider read (302 Found)", true},
		{"not an object", func(int) (int, string) { return http.StatusOK, `[]` }, 1,
			"kube: IAM answered without a usable provider read (the answer is not a JSON object)", false},
		{"a key twice", func(int) (int, string) { return http.StatusOK, `{"nextPageToken":"a","nextPageToken":"b"}` }, 1,
			"kube: IAM answered without a usable provider read (a key given twice)", false},
		{"a key twice, one escaped", func(int) (int, string) {
			return http.StatusOK, `{"nextPageToken":"a","next\u0050ageToken":"b"}`
		}, 1, "kube: IAM answered without a usable provider read (a key given twice)", false},
		{"trailing data", func(int) (int, string) { return http.StatusOK, `{}{}` }, 1,
			"kube: IAM answered without a usable provider read (the answer is not a JSON object)", false},
		{"a token with an ampersand", func(int) (int, string) { return http.StatusOK, page(nil, "a&b") }, 1,
			"kube: IAM answered without a usable provider read (nextPageToken)", false},
		{"a token too long", func(int) (int, string) { return http.StatusOK, page(nil, strings.Repeat("t", 4097)) }, 1,
			"kube: IAM answered without a usable provider read (nextPageToken)", false},
		{"a token that is a number", func(int) (int, string) { return http.StatusOK, `{"nextPageToken":5}` }, 1,
			"kube: IAM answered without a usable provider read (nextPageToken)", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			fake := newFedFake(t)
			n := 0
			fake.set(func(f *fedFake) {
				f.apiAnswer = func(*http.Request) (int, string) {
					code, body := c.answer(n)
					n++
					return code, body
				}
			})
			r, err := NewIAMReader(fake.credential(t, Reader))
			if err != nil {
				t.Fatal(err)
			}
			got, err := r.ListProviders(t.Context(), "123456789012", "pool1234")
			sentinel := ErrUnreadable
			if c.refused {
				sentinel = ErrIAMRefused
			}
			var fe *FederationError
			if got != nil || !errors.Is(err, sentinel) || !errors.As(err, &fe) || fe.Step != StepProviderList || err.Error() != c.want {
				t.Fatalf("%v; want %q", err, c.want)
			}
			if errors.Is(err, ErrTokenRefused) {
				t.Error("an IAM refusal reads as a token refusal")
			}
			if m := containsAnyOf(err.Error(), fedMarkers...); m != "" {
				t.Errorf("the error carries %q", m)
			}
			if sent := len(fake.requests("api")); sent != c.pages {
				t.Errorf("%d pages were asked for, want %d", sent, c.pages)
			}
		})
	}

	t.Run("pages at the caps", func(t *testing.T) {
		fake := newFedFake(t)
		n := 0
		exact := `{"workloadIdentityPoolProviders":[],"pad":"`
		exact += strings.Repeat("a", 1<<20-len(exact)-2) + `"}`
		fake.set(func(f *fedFake) {
			f.apiAnswer = func(*http.Request) (int, string) {
				n++
				switch {
				case n == 1:
					return http.StatusOK, page(nil, strings.Repeat("t", 4096))
				case n < 50:
					return http.StatusOK, page(nil, fmt.Sprintf("tok-%d", n))
				}
				return http.StatusOK, exact
			}
		})
		r, err := NewIAMReader(fake.credential(t, Reader))
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.ListProviders(t.Context(), "123456789012", "pool1234")
		if err != nil || len(got) != 50 || len(got[49]) != 1<<20 {
			t.Fatalf("50 pages, the last exactly 1 MiB: %d pages, %v", len(got), err)
		}
	})
}

// TestIAMReaderUnauthorizedReimpersonatesOnce: a 401 from IAM's API drops the
// service account's token and impersonates once more, with the role's cached
// federated token; nothing is exchanged again. A second 401 is the error.
func TestIAMReaderUnauthorizedReimpersonatesOnce(t *testing.T) {
	fake := newFedFake(t)
	r, err := NewIAMReader(fake.credential(t, Reader))
	if err != nil {
		t.Fatal(err)
	}
	fake.set(func(f *fedFake) { f.apiStatus = []int{http.StatusUnauthorized} })
	if _, err := r.GetProvider(t.Context(), "123456789012", "pool1234", "prov1234"); err != nil {
		t.Fatal(err)
	}
	if e, i, a := len(fake.requests("sts")), len(fake.requests("iam")), len(fake.requests("api")); e != 1 || i != 2 || a != 2 {
		t.Errorf("one 401: %d exchanges, %d impersonations, %d reads; want 1, 2, 2", e, i, a)
	}
	fake.set(func(f *fedFake) { f.apiStatus = []int{http.StatusUnauthorized, http.StatusUnauthorized} })
	_, err = r.GetProvider(t.Context(), "123456789012", "pool1234", "prov1234")
	var fe *FederationError
	if !errors.As(err, &fe) || fe.Step != StepProviderGet || fe.Status != http.StatusUnauthorized || fe.GoogleStatus != "UNAUTHENTICATED" ||
		!errors.Is(err, ErrIAMRefused) || err.Error() != "kube: IAM refused the provider read (401 Unauthorized, status UNAUTHENTICATED)" {
		t.Fatalf("two 401s: %v", err)
	}
	if e, i, a := len(fake.requests("sts")), len(fake.requests("iam")), len(fake.requests("api")); e != 1 || i != 3 || a != 4 {
		t.Errorf("two more 401s: %d exchanges, %d impersonations, %d reads; want 1, 3, 4", e, i, a)
	}
}

// TestIAMReadTakesOnly200AndRetriesOnly401: a 2xx other than 200 is a
// refusal like any other status, and only a 401 re-impersonates: a 403 is
// the error at once, with one read and no new impersonation.
func TestIAMReadTakesOnly200AndRetriesOnly401(t *testing.T) {
	fake := newFedFake(t)
	r, err := NewIAMReader(fake.credential(t, Reader))
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{http.StatusCreated, http.StatusAccepted} {
		fake.set(func(f *fedFake) {
			f.apiAnswer = func(*http.Request) (int, string) { return code, fedProvider("prov1234", "ACTIVE") }
		})
		got, err := r.GetProvider(t.Context(), "123456789012", "pool1234", "prov1234")
		var fe *FederationError
		want := fmt.Sprintf("kube: IAM refused the provider read (%d %s)", code, http.StatusText(code))
		if got != nil || !errors.As(err, &fe) || fe.Status != code || !errors.Is(err, ErrIAMRefused) || err.Error() != want {
			t.Errorf("a %d: %.40q, %v; want %q", code, got, err, want)
		}
		if _, err := r.ListProviders(t.Context(), "123456789012", "pool1234"); !errors.As(err, &fe) || fe.Step != StepProviderList || fe.Status != code {
			t.Errorf("a %d to a list: %v", code, err)
		}
	}
	fake.set(func(f *fedFake) { f.apiAnswer = nil })
	impersonations, reads := len(fake.requests("iam")), len(fake.requests("api"))
	fake.set(func(f *fedFake) { f.apiStatus = []int{http.StatusForbidden} })
	_, err = r.GetProvider(t.Context(), "123456789012", "pool1234", "prov1234")
	var fe *FederationError
	if !errors.As(err, &fe) || fe.Status != http.StatusForbidden || !errors.Is(err, ErrIAMRefused) {
		t.Errorf("a 403: %v", err)
	}
	if i, a := len(fake.requests("iam")), len(fake.requests("api")); i != impersonations || a != reads+1 {
		t.Errorf("a 403: %d impersonations and %d reads after %d and %d; want no new impersonation and one read", i, a, impersonations, reads)
	}
}

// TestIAMReadBodyFailureIsAReadFailure: an answer whose head came and whose
// body broke off is a failure while reading it, unreachable with Go's own
// words for it ("unexpected EOF"), not a call that had no answer.
func TestIAMReadBodyFailureIsAReadFailure(t *testing.T) {
	fake := newFedFake(t)
	cut := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{\"name\":")
		_ = buf.Flush()
		_ = conn.Close()
	}))
	cut.Config.ErrorLog = log.New(io.Discard, "", 0)
	cut.StartTLS() // the same httptest certificate as the fake's, so fake.roots verifies it
	t.Cleanup(cut.Close)
	fed, err := NewLoopbackFederation(fake.sts.Listener.Addr().String(), fake.iam.Listener.Addr().String(), cut.Listener.Addr().String(), fake.roots)
	if err != nil {
		t.Fatal(err)
	}
	id := newFedIdentity(t, fedHexID)
	cred, err := NewFederatedCredential(fed, fedAudience, NewClientIdentity([][]byte{id.leafDER}, id.key), fedEmail, Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewIAMReader(cred)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.GetProvider(t.Context(), "123456789012", "pool1234", "prov1234")
	var fe *FederationError
	if !errors.As(err, &fe) || fe.Step != StepProviderGet || !errors.Is(err, ErrUnreachable) || err.Error() != "kube: IAM could not be reached: unexpected EOF" {
		t.Errorf("a body cut short: %v", err)
	}
}

// TestIAMReadErrorTexts pins the IAM reader's failures' whole texts and
// sentinels, and that none carries a planted body marker (R10).
func TestIAMReadErrorTexts(t *testing.T) {
	for _, c := range []struct {
		name     string
		err      error
		want     string
		sentinel error
	}{
		{"refused, Google status", refusedAnswer(StepProviderGet, 403, []byte(`{"error":{"code":403,"message":"`+fedPlanted+`","status":"PERMISSION_DENIED"}}`), 0),
			"kube: IAM refused the provider read (403 Forbidden, status PERMISSION_DENIED)", ErrIAMRefused},
		{"refused, an OAuth code is not read", refusedAnswer(StepProviderList, 400, []byte(`{"error":"invalid_grant","error_description":"`+fedPlanted+`"}`), 0),
			"kube: IAM refused the provider read (400 Bad Request)", ErrIAMRefused},
		{"refused, neither", refusedAnswer(StepProviderGet, 404, []byte(`<html>`+fedPlanted+`</html>`), 0),
			"kube: IAM refused the provider read (404 Not Found)", ErrIAMRefused},
		{"refused, over the cap", refusedAnswer(StepProviderGet, 403, []byte(`{"error":{"status":"PERMISSION_DENIED","message":"`+strings.Repeat("x", 1<<20)+`"}}`), 0),
			"kube: IAM refused the provider read (403 Forbidden)", ErrIAMRefused},
		{"refused, over STS's 64 KiB and within IAM's 1 MiB", refusedAnswer(StepProviderList, 403, []byte(`{"error":{"status":"PERMISSION_DENIED","message":"`+strings.Repeat("x", 100<<10)+`"}}`), 0),
			"kube: IAM refused the provider read (403 Forbidden, status PERMISSION_DENIED)", ErrIAMRefused},
		{"an alert before any answer", classifyFailure(context.Background(), StepProviderGet,
			&url.Error{Op: "Get", URL: "https://" + IAMHost + "/v1/projects/123456789012/" + fedSecretMarker, Err: &net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}}, false),
			"kube: IAM could not be reached: tls: handshake failure", ErrUnreachable},
		{"unusable", unusableAnswer(StepProviderList, answerOversizeIAM, 0),
			"kube: IAM answered without a usable provider read (the answer is larger than 1 MiB)", ErrUnreadable},
		{"unreachable", classifyFailure(context.Background(), StepProviderGet,
			&url.Error{Op: "Get", URL: "https://" + IAMHost + "/v1/projects/123456789012/" + fedSecretMarker, Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}}, false),
			"kube: IAM could not be reached: dial tcp: connect: connection refused", ErrUnreachable},
	} {
		if c.err.Error() != c.want || !errors.Is(c.err, c.sentinel) {
			t.Errorf("%s: %v; want %q", c.name, c.err, c.want)
		}
		for _, other := range []error{ErrTokenRefused, ErrIAMRefused, ErrUnreadable, ErrUnreachable} {
			if other != c.sentinel && errors.Is(c.err, other) {
				t.Errorf("%s: it also wraps %v", c.name, other)
			}
		}
		for _, e := range fedErrorTree(c.err) {
			if m := containsAnyOf(e.Error(), append(fedMarkers, "123456789012")...); m != "" {
				t.Errorf("%s: an error in its tree carries %q", c.name, m)
			}
			if _, ok := e.(*url.Error); ok {
				t.Errorf("%s: a *url.Error is in its tree", c.name)
			}
		}
	}

	// An IAM API host nothing listens on: unreachable, naming no URL.
	fake := newFedFake(t)
	cred := fake.credential(t, Reader)
	fake.api.Close()
	r, err := NewIAMReader(cred)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.GetProvider(t.Context(), "123456789012", "pool1234", "prov1234")
	var fe *FederationError
	if !errors.Is(err, ErrUnreachable) || !errors.As(err, &fe) || fe.Step != StepProviderGet || !strings.HasPrefix(err.Error(), "kube: IAM could not be reached: ") {
		t.Errorf("a closed IAM API host: %v", err)
	}
	if strings.Contains(err.Error(), "pool1234") || strings.Contains(err.Error(), "/v1/") {
		t.Errorf("the unreachable error names the URL: %v", err)
	}
}

// TestProviderPageToken is the page token's shape: absent, null or "" is the
// last page; otherwise 1 to 4096 of [A-Za-z0-9+/=_.~-].
func TestProviderPageToken(t *testing.T) {
	for _, c := range []struct {
		body, next, field string
	}{
		{`{}`, "", ""},
		{`{"workloadIdentityPoolProviders":[]}`, "", ""},
		{`{"nextPageToken":null}`, "", ""},
		{`{"nextPageToken":""}`, "", ""},
		{` { "nextPageToken" : "AZaz09+/=_.~-" } `, "AZaz09+/=_.~-", ""},
		{`{"nextPageToken":"` + strings.Repeat("t", 4096) + `"}`, strings.Repeat("t", 4096), ""},
		{`{"nextPageToken":"` + strings.Repeat("t", 4097) + `"}`, "", "nextPageToken"},
		{`{"nextPageToken":"a b"}`, "", "nextPageToken"},
		{`{"nextPageToken":"a%2B"}`, "", "nextPageToken"},
		{`{"nextPageToken":true}`, "", "nextPageToken"},
		{`{"nextPageToken":["a"]}`, "", "nextPageToken"},
		{`{"a":1,"a":2}`, "", answerKeyTwice},
		{`{"nextPageToken":"a","next\u0050ageToken":"b"}`, "", answerKeyTwice},
		{`{"next\u0050ageToken":"a","nextPageToken":"b"}`, "", answerKeyTwice},
		{`{"next\u0050ageToken":"a"}`, "a", ""},
		{`null`, "", answerNotObject},
		{`"x"`, "", answerNotObject},
		{``, "", answerNotObject},
		{`{"nextPageToken":"a"`, "", answerNotObject},
		{`{"nextPageToken":"a"} x`, "", answerNotObject},
	} {
		next, field := providerPageToken([]byte(c.body))
		if next != c.next || field != c.field {
			t.Errorf("%.40q: %q, %q; want %q, %q", c.body, next, field, c.next, c.field)
		}
	}
}
