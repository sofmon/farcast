//go:build realapi

// TestEveryRenderedStreamAppliesOnARealServer is the real-API suite's one test
// over the streams farcast renders (ADR 0023 M2.7, design A30-18). It lives
// here because renderedStreams is this package's test code, which package
// kube cannot import. It runs only by docs/runbooks/adr-0023-m2-realapi.md,
// R6; ./check.sh type-checks and lints it, and never runs it.
//
// It reads the suite's three variables, FARCAST_REALAPI_ENDPOINT,
// FARCAST_REALAPI_CA_FILE and FARCAST_REALAPI_TOKEN_FILE, and fails without
// them: it never skips. The token is read once, trimmed, and used only as the
// bearer; it is never printed and never put in a message.
//
// Its sender is its own, because this package cannot reach kube's in-package
// client. It is built as walkcluster_test.go builds its requests: a transport
// with no proxy and no redirect, TLS trusting the CA file alone, a dialer that
// refuses every address but the endpoint's, and User-Agent farcast. For each
// document kube.SplitStream yields, it sends exactly kube.Apply's request:
//
//	PATCH {Kind.Path}?fieldManager=farcast&fieldValidation=Strict&force=true
//	Content-Type: application/apply-patch+yaml
//
// with the document's own bytes as its body.
package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// The suite's environment (the runbook's R6).
const (
	envRealAPIEndpoint  = "FARCAST_REALAPI_ENDPOINT"
	envRealAPICAFile    = "FARCAST_REALAPI_CA_FILE"
	envRealAPITokenFile = "FARCAST_REALAPI_TOKEN_FILE"
)

// realAPIMaxAnswer caps an answer's body, as kube caps its own.
const realAPIMaxAnswer = 64 << 20

// realAPISender is the test's own client of the real API server.
type realAPISender struct {
	endpoint string        // FARCAST_REALAPI_ENDPOINT, as given; only scrub uses it
	ep       kube.Endpoint // classified by kube.ParseEndpoint: loopback only
	token    string        // never printed
	hc       *http.Client
}

// openRealAPISender checks the environment first, and fails the test without
// it, before anything is dialed. Then it builds the sender and waits up to
// 60 s for GET /readyz.
func openRealAPISender(t *testing.T) *realAPISender {
	t.Helper()
	var missing []string
	get := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			missing = append(missing, name)
		}
		return v
	}
	endpoint, caFile, tokenFile := get(envRealAPIEndpoint), get(envRealAPICAFile), get(envRealAPITokenFile)
	if len(missing) > 0 {
		t.Fatalf("the real-API suite needs %s set (docs/runbooks/adr-0023-m2-realapi.md, R6); it fails rather than skips, so a tagged run cannot pass by testing nothing", strings.Join(missing, ", "))
	}
	caPEM := readRealAPIFile(t, envRealAPICAFile, caFile)
	raw := readRealAPIFile(t, envRealAPITokenFile, tokenFile)
	token := strings.TrimSpace(string(raw))
	clear(raw)
	if token == "" {
		t.Fatalf("the file %s names holds no token", envRealAPITokenFile)
	}
	ep, err := kube.ParseEndpoint(endpoint, "", caPEM)
	if err != nil {
		t.Fatalf("%s: %v", envRealAPIEndpoint, err)
	}
	if ep.Mode != kube.ModeLoopback {
		t.Fatalf("%s must be a loopback endpoint, 127.0.0.1:<port>", envRealAPIEndpoint)
	}
	allowed := net.JoinHostPort(ep.Host, ep.Port)
	dialer := &net.Dialer{Timeout: 30 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		if address != allowed {
			return fmt.Errorf("the real-API sender refused to dial %s", address)
		}
		return nil
	}}
	s := &realAPISender{endpoint: endpoint, ep: ep, token: token, hc: &http.Client{
		Transport: realAPIAgent{inner: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: ep.CA},
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		}},
		Timeout:       60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	for {
		code, _, err := s.send(ctx, http.MethodGet, "/readyz", nil, "", nil)
		if err == nil && code == http.StatusOK {
			return s
		}
		select {
		case <-ctx.Done():
			t.Fatalf("GET /readyz did not answer 200 within 60 s (last: %d, %s)", code, s.scrub(fmt.Sprint(err)))
		case <-time.After(time.Second):
		}
	}
}

// readRealAPIFile reads the file a variable names. Its failure names the
// variable and the cause, never the path.
func readRealAPIFile(t *testing.T, variable, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		t.Fatalf("the file %s names cannot be read: %v", variable, err)
	}
	return b
}

// realAPIAgent sets User-Agent: farcast, kube.UserAgent, on every request.
type realAPIAgent struct{ inner http.RoundTripper }

func (a realAPIAgent) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("User-Agent", kube.UserAgent)
	return a.inner.RoundTrip(r)
}

// scrub takes the endpoint out of a message: a transport's words name it.
func (s *realAPISender) scrub(msg string) string {
	for _, a := range []string{s.endpoint, net.JoinHostPort(s.ep.Host, s.ep.Port)} {
		if a != "" {
			msg = strings.ReplaceAll(msg, a, "<endpoint>")
		}
	}
	return msg
}

// send makes one request to the endpoint's origin, with the token as its
// bearer, and returns the status and at most 64 MiB of the body. An error is
// the request not answered, scrubbed.
func (s *realAPISender) send(ctx context.Context, method, path string, q url.Values, contentType string, body []byte) (int, []byte, error) {
	target := s.ep.BaseURL() + path
	if e := q.Encode(); e != "" {
		target += "?" + e
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		return 0, nil, fmt.Errorf("build %s %s: %s", method, path, s.scrub(err.Error()))
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, nil, fmt.Errorf("%s %s was not answered: %s", method, path, s.scrub(err.Error()))
	}
	defer func() { _ = resp.Body.Close() }()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, realAPIMaxAnswer))
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: the answer could not be read: %s", method, path, s.scrub(err.Error()))
	}
	return resp.StatusCode, answer, nil
}

// realAPIRefused is a non-2xx answer: its code, and, when the body is a
// Kubernetes Status, its reason, its message and its causes' field paths.
type realAPIRefused struct {
	code    int
	status  bool // the body is a Kubernetes Status
	reason  string
	message string // the server's own words: on the FAIL line only, never in a fact
	fields  []string
}

// realAPIRefusal reads a non-2xx answer.
func realAPIRefusal(code int, body []byte) *realAPIRefused {
	e := &realAPIRefused{code: code}
	var st kube.Status
	if json.Unmarshal(body, &st) == nil && st.Kind == "Status" {
		e.status, e.reason, e.message = true, st.Reason, st.Message
		if st.Details != nil {
			for _, c := range st.Details.Causes {
				e.fields = append(e.fields, c.Field)
			}
		}
	}
	return e
}

// Error is the refusal as a FAIL line carries it, the server's message
// included: unscrubbed, so it is read and never copied into a record.
func (e *realAPIRefused) Error() string {
	if !e.status {
		return fmt.Sprintf("%d %s (not a Kubernetes Status)", e.code, http.StatusText(e.code))
	}
	return fmt.Sprintf("%d %s: %s", e.code, e.reason, e.message)
}

// fact is the refusal as a fact line records it: the code, the reason and the
// causes' field paths, never the message, which can quote a value or an
// address.
func (e *realAPIRefused) fact() string {
	if !e.status {
		return fmt.Sprintf("%d (not a Kubernetes Status)", e.code)
	}
	fields := "none"
	if len(e.fields) > 0 {
		fields = strings.Join(e.fields, ", ")
	}
	return fmt.Sprintf("%d %s; the causes' fields: %s", e.code, e.reason, fields)
}

// refusedFact is a fact line's words for an apply's failure: a refusal's fact,
// or "not answered" for an error that is not one.
func refusedFact(err error) string {
	var e *realAPIRefused
	if errors.As(err, &e) {
		return e.fact()
	}
	return "not answered"
}

// realAPIApplied is the part of an apply's answer the test compares.
type realAPIApplied struct {
	Generation      int64  `json:"generation"`
	ResourceVersion string `json:"resourceVersion"`
}

// apply sends kube.Apply's request for d, forced, as every apply is from ADR
// 0023 M2.7 (P1).
func (s *realAPISender) apply(ctx context.Context, d kube.Document) (realAPIApplied, error) {
	q := url.Values{"fieldManager": {kube.FieldManager}, "fieldValidation": {"Strict"}, "force": {"true"}}
	code, body, err := s.send(ctx, http.MethodPatch, d.Kind.Path(d.Namespace, d.Name), q, "application/apply-patch+yaml", d.Raw)
	if err != nil {
		return realAPIApplied{}, err
	}
	if code < 200 || code > 299 {
		return realAPIApplied{}, realAPIRefusal(code, body)
	}
	var answer struct {
		Metadata realAPIApplied `json:"metadata"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return realAPIApplied{}, fmt.Errorf("the answer to %s does not decode", docIdentity(d))
	}
	return answer.Metadata, nil
}

// clearJob deletes the Job d names, when one exists, before its stream's
// first apply. A Job's template is immutable, and two of renderedStreams'
// streams render one Job name twice (build and fetch, with and without a git
// credential). On a real instance the TTL controller deletes a finished Job
// (ttlSecondsAfterFinished); envtest runs no controller, so this does it. The
// delete is Background, which adds no finalizer that only a garbage collector
// would remove.
func (s *realAPISender) clearJob(t *testing.T, d kube.Document) {
	t.Helper()
	ctx := t.Context()
	path := d.Kind.Path(d.Namespace, d.Name)
	code, body, err := s.send(ctx, http.MethodGet, path, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	switch code {
	case http.StatusNotFound:
		return
	case http.StatusOK:
	default:
		t.Fatalf("GET %s: %v", docIdentity(d), realAPIRefusal(code, body))
	}
	opts := []byte(`{"apiVersion":"v1","kind":"DeleteOptions","propagationPolicy":"Background"}`)
	code, body, err = s.send(ctx, http.MethodDelete, path, nil, "application/json", opts)
	if err != nil {
		t.Fatal(err)
	}
	if code != http.StatusOK && code != http.StatusAccepted {
		t.Fatalf("DELETE %s: %v", docIdentity(d), realAPIRefusal(code, body))
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		code, _, err = s.send(ctx, http.MethodGet, path, nil, "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if code == http.StatusNotFound {
			t.Logf("fact: %s: an earlier stream's Job of this name was deleted first, as the TTL controller deletes a finished one", docIdentity(d))
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was still there 30 s after its delete", docIdentity(d))
		}
		time.Sleep(time.Second)
	}
}

// TestEveryRenderedStreamAppliesOnARealServer applies every stream
// TestEveryRenderedStreamPassesTheApplyChecks covers (renderedStreams), in its
// order, to a real API server. First it applies a Namespace document for each
// namespace a stream names before any stream creates it: my-platform, alpha
// and beta today. Then each stream is applied twice. Every apply must succeed,
// and the second must leave each object's generation where the first left it.
// Whether the second moved a resourceVersion is recorded, and so is each
// refusal, on a fact line of its own: the stream, the document, the code, the
// Status reason and its causes' field paths, never the server's message, which
// only the FAIL line beside it carries. There is no dryRun
// pass (C21): on a throwaway server the real apply shows the same refusals.
//
// This is where server-side apply's own refusals would show before the
// billable walk: duplicate list-map keys, strict validation, Job
// immutability, Service allocations, and privileged pods, which the server
// refuses because the runbook starts it without --allow-privileged.
func TestEveryRenderedStreamAppliesOnARealServer(t *testing.T) {
	s := openRealAPISender(t)
	ctx := t.Context()

	type split struct {
		name string
		docs []kube.Document
	}
	var splits []split
	created := map[string]bool{}
	var first []string // namespaces named before any stream creates them
	for _, rs := range renderedStreams(t) {
		docs, err := kube.SplitStream(rs.stream)
		if err != nil {
			t.Fatalf("%s: refused: %v", rs.name, err)
		}
		splits = append(splits, split{name: rs.name, docs: docs})
		for _, d := range docs {
			if d.Kind.Kind == "Namespace" {
				created[d.Name] = true
			} else if d.Namespace != "" && !created[d.Namespace] && !slices.Contains(first, d.Namespace) {
				first = append(first, d.Namespace)
			}
		}
	}
	slices.Sort(first)
	t.Logf("fact: namespaces created first: %s", strings.Join(first, ", "))
	for _, ns := range first {
		docs, err := kube.SplitStream(fmt.Appendf(nil, "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n", ns))
		if err != nil || len(docs) != 1 {
			t.Fatalf("the Namespace %s does not split: %v", ns, err)
		}
		if _, err := s.apply(ctx, docs[0]); err != nil {
			t.Fatalf("the Namespace %s: %v", ns, err)
		}
	}

	for _, sp := range splits {
		t.Run(sp.name, func(t *testing.T) {
			for _, d := range sp.docs {
				if d.Kind.Kind == "Job" {
					s.clearJob(t, d)
				}
			}
			// Each refusal is a fact line of its own (refusedFact), so R8
			// records it with no server message; the FAIL line beside it
			// carries the message, for the operator to read.
			refused := func(which string, d kube.Document, err error) {
				t.Logf("fact: %s: the %s apply of %s was refused: %s", sp.name, which, docIdentity(d), refusedFact(err))
				t.Errorf("the %s apply of %s: %v", which, docIdentity(d), err)
			}
			firstApply := make([]*realAPIApplied, len(sp.docs))
			for i, d := range sp.docs {
				m, err := s.apply(ctx, d)
				if err != nil {
					refused("first", d, err)
					continue
				}
				firstApply[i] = &m
			}
			var moved []string
			twice := 0
			for i, d := range sp.docs {
				if firstApply[i] == nil {
					continue
				}
				m, err := s.apply(ctx, d)
				if err != nil {
					refused("second", d, err)
					continue
				}
				twice++
				if m.Generation != firstApply[i].Generation {
					t.Errorf("the second apply of %s moved metadata.generation from %d to %d", docIdentity(d), firstApply[i].Generation, m.Generation)
				}
				if m.ResourceVersion != firstApply[i].ResourceVersion {
					moved = append(moved, docIdentity(d))
				}
			}
			if len(moved) == 0 {
				moved = []string{"none"}
			}
			t.Logf("fact: %s: %d of %d documents applied twice; the second apply moved the resourceVersion of: %s", sp.name, twice, len(sp.docs), strings.Join(moved, ", "))
		})
	}
}
