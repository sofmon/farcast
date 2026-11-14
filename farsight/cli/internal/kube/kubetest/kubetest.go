// Package kubetest is a fake Kubernetes API server and Google token endpoint
// for farcast's cluster client, package kube, and for the rehearsal (ADR 0023
// M2.1, design §2.2).
//
// It is an ordinary package, not a _test file, so the rehearsal binary can run
// it; ./check.sh keeps it out of the farcast binary. It listens on loopback
// only, behind its own P-256 CA, and makes no outbound connection.
//
// What it emulates is listed on each piece below, and each piece is tested in
// kubetest_test.go. It reads every JSON body a client sends to the API by its
// exact keys, never into a struct, because the API server decodes
// case-sensitively and encoding/json does not (writes.go). What it leaves out
// is deliberate: field ownership (an apply keeps one managed-fields entry per
// manager, with empty fieldsV1), admission, controllers and watch. Field
// semantics belong to the real-Kubernetes test (§10.6), not to this fake.
//
// The order every API request goes through is: authentication (401), the
// WithRBAC check (403, before any object is looked up), WithHandler, the
// answers queued by Fail, the answers set by Script, and then the emulation.
// Everything the emulation does not cover answers 405. Every request is
// recorded, whatever its answer.
package kubetest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

const (
	// tokenPath is where the fake token endpoint answers. A client's token
	// URL is "https://"+Endpoint()+"/token", as kube.Endpoint.TokenURL
	// builds it in loopback mode.
	tokenPath = "/token"

	// maxRequestBody caps what one request may send. Larger bodies answer
	// 413 and are recorded without their body.
	maxRequestBody = 64 << 20

	// LogAnnotationPrefix, followed by a container's name, is the pod
	// annotation whose value is that container's log. kubetest has no
	// kubelet: a test seeds a pod's logs with Put. A container without the
	// annotation has an empty log.
	LogAnnotationPrefix = "kubetest.invalid/log."
	// PreviousLogAnnotationPrefix, followed by a container's name, is the pod
	// annotation whose value is the log of that container's previous
	// instance. Without it, a log request with previous=true answers 400, as
	// a container with no previous instance does.
	PreviousLogAnnotationPrefix = "kubetest.invalid/previous-log."

	// credentialDomain is the domain of the emails Credential registers.
	credentialDomain = "kubetest.invalid"
)

// Server is one fake API server and token endpoint. It is safe for concurrent
// use: every method may be called while requests are served.
type Server struct {
	opts     options
	endpoint string // "127.0.0.1:<port>"
	caPEM    []byte
	srv      *http.Server
	served   chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	rbac     map[string]*authorizer // by email; fixed at Start

	gate      sync.Mutex // guards closed and every inflight.Add
	closed    bool
	inflight  sync.WaitGroup
	closeOnce sync.Once

	mu       sync.Mutex
	keys     map[string][]registeredKey // by email
	tokens   map[string]*tokenInfo
	minted   int
	requests []Request
	objects  map[string]*stored // by the object's path
	rv       uint64
	fails    map[failKey][]injected
	scripts  map[string]*script
}

// Request is one request the server saw.
type Request struct {
	Method, Path, RawQuery, ContentType, UserAgent, Accept string
	// As is the id whose token authorized it; "" for none, "?" for an
	// unknown token. A revoked token is unknown here, because it authorized
	// nothing. On a /token request it is the id of the key that verified the
	// assertion, and "" when the assertion did not verify.
	As string
	// KeyID is, on /token requests, the assertion header's kid; "" otherwise.
	KeyID string
	Body  []byte
}

// Option configures a Server at New or Start.
type Option func(*options)

type options struct {
	addr        string
	identities  []identity
	handler     func(r Request) (status int, body []byte, handled bool)
	tokenAnswer func(email string) (status int, body []byte, handled bool)
	delay       func(r Request) time.Duration
	access      func(id string, a kube.ResourceAttributes) bool
	rbac        map[string][]byte
	warnings    func(r Request) []string
}

type identity struct {
	id, email string
	pub       *rsa.PublicKey
}

// WithAddr listens on addr ("127.0.0.1:<port>") instead of 127.0.0.1:0, so a
// restarted rehearsal reuses its recorded endpoint. addr must be a loopback IP
// literal (127.0.0.0/8 or [::1]) with a port; the leaf certificate names that
// IP.
func WithAddr(addr string) Option {
	return func(o *options) { o.addr = addr }
}

// WithIdentity registers an existing public key under id and email, as the
// rehearsal registers its reader and writer.
func WithIdentity(id, email string, pub *rsa.PublicKey) Option {
	return func(o *options) { o.identities = append(o.identities, identity{id: id, email: email, pub: pub}) }
}

// WithHandler sees every authorized non-token request before the emulation does.
// handled=false falls through to the emulation.
//
// "Authorized" means the token is live and WithRBAC, when it applies to the
// caller, allowed the request. A handled answer is written with the status
// given (0 is 200), as JSON when its body begins with { or [, and as text
// otherwise. h runs for every request, so a handler that reads its own state
// changes the answers while the server runs.
func WithHandler(h func(r Request) (status int, body []byte, handled bool)) Option {
	return func(o *options) { o.handler = h }
}

// WithTokenAnswer sees every /token request whose assertion verified, keyed by
// the assertion's iss. handled=false mints as usual.
func WithTokenAnswer(f func(email string) (status int, body []byte, handled bool)) Option {
	return func(o *options) { o.tokenAnswer = f }
}

// WithDelay is evaluated for every request: its answer is held for the duration
// f returns, or until the request's context ends; 0 holds nothing.
//
// The hold comes before the answer is computed, so a request abandoned during
// it changes nothing. /token requests are held too.
func WithDelay(f func(r Request) time.Duration) Option {
	return func(o *options) { o.delay = f }
}

// WithAccess answers SelfSubjectAccessReviews. Without it every review answers
// allowed: false.
func WithAccess(f func(id string, a kube.ResourceAttributes) bool) Option {
	return func(o *options) { o.access = f }
}

// WithRBAC authorizes every non-token request made by the identity registered
// under email with the rules of the rendered RBAC stream alone: the ClusterRoles
// it binds through a ClusterRoleBinding, cluster-wide, and through a RoleBinding,
// in that RoleBinding's namespace, matched on apiGroup, resource (pods/log as a
// subresource), verb (a GET of one object is get, of a collection list) and
// resourceNames. Anything they do not grant gets 403 with a JSON Status, as a
// real API server answers before it reads storage (§5.4). Other identities are
// unaffected.
//
// The stream is split and checked with kube.SplitStream, so only a stream
// farcast could apply can grant anything; Start fails on one it refuses. A
// subject counts when it is kind User named email. Creating a
// SelfSubjectAccessReview is always allowed, as system:basic-user allows it
// for every authenticated user. A server-side apply that creates its object
// needs create as well as patch, as the API server's patch handler checks it.
// A second WithRBAC for the same email replaces the first.
func WithRBAC(email string, stream []byte) Option {
	return func(o *options) {
		if o.rbac == nil {
			o.rbac = map[string][]byte{}
		}
		o.rbac[email] = bytes.Clone(stream)
	}
}

// WithWarnings makes every API answer, 401s and 403s included, carry one
// `Warning: 299 - "<text>"` header per text f returns for the request, in that
// order, quoted as the API server quotes them. /token answers carry none,
// because Google's token endpoint sends no Kubernetes warnings. f runs for
// every request.
func WithWarnings(f func(r Request) []string) Option {
	return func(o *options) { o.warnings = f }
}

// New starts a TLS server on 127.0.0.1:0, with a leaf for IP 127.0.0.1 issued by
// its own CA (crypto/x509, P-256), and registers t.Cleanup to stop it.
func New(t testing.TB, opts ...Option) *Server {
	t.Helper()
	s, err := Start(opts...)
	if err != nil {
		t.Fatalf("kubetest: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

// Start is New for the rehearsal: no testing.TB, the caller closes it.
func Start(opts ...Option) (*Server, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	addr := o.addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ip, err := loopbackAddr(addr)
	if err != nil {
		return nil, err
	}
	for _, id := range o.identities {
		if id.id == "" || id.email == "" || id.pub == nil {
			return nil, fmt.Errorf("WithIdentity(%q, %q) needs an id, an email and a public key", id.id, id.email)
		}
	}
	authorizers := map[string]*authorizer{}
	for email, stream := range o.rbac {
		a, err := newAuthorizer(email, stream)
		if err != nil {
			return nil, err
		}
		authorizers[email] = a
	}
	caPEM, leaf, err := newCertificates(ip)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		opts:     o,
		endpoint: net.JoinHostPort(ip.String(), port),
		caPEM:    caPEM,
		served:   make(chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
		rbac:     authorizers,
		keys:     map[string][]registeredKey{},
		tokens:   map[string]*tokenInfo{},
		objects:  map[string]*stored{},
		fails:    map[failKey][]injected{},
		scripts:  map[string]*script{},
	}
	for _, id := range o.identities {
		s.keys[id.email] = append(s.keys[id.email], registeredKey{id: id.id, pub: id.pub})
	}
	s.srv = &http.Server{
		Handler:           http.HandlerFunc(s.serve),
		TLSConfig:         serverTLSConfig(leaf),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		defer close(s.served)
		_ = s.srv.ServeTLS(ln, "", "")
	}()
	return s, nil
}

// loopbackAddr checks that addr is a loopback IP literal with a port, and
// returns the IP the leaf certificate names.
func loopbackAddr(addr string) (net.IP, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("WithAddr(%q): %w", addr, err)
	}
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" || a.Is4In6() || !a.IsLoopback() {
		return nil, fmt.Errorf("WithAddr(%q) is not a loopback IP literal (127.0.0.0/8 or ::1) with a port", addr)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return nil, fmt.Errorf("WithAddr(%q) names no port from 0 to 65535", addr)
	}
	return net.IP(a.AsSlice()), nil
}

// Endpoint is "127.0.0.1:<port>", as metadata.yaml records it.
func (s *Server) Endpoint() string { return s.endpoint }

// CAPEM is cluster-ca.crt's contents: the PEM of the CA that issued the
// server's leaf.
func (s *Server) CAPEM() []byte { return bytes.Clone(s.caPEM) }

// Credential is a fresh RSA key registered under <id>@kubetest.invalid.
func (s *Server) Credential(id string) kube.Credential {
	return s.CredentialFor(id, id+"@"+credentialDomain)
}

// CredentialFor is the same, under a given .invalid email.
//
// The key is RSA-2048, PEM-encoded PKCS#8, and its PrivateKeyID is 40 hex
// characters derived from its public key, the shape of Google's key ids.
// TokenURI and UniverseDomain are empty, which pairs in loopback mode.
func (s *Server) CredentialFor(id, email string) kube.Credential {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("kubetest: generate an RSA key: %v", err))
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(fmt.Sprintf("kubetest: encode an RSA key: %v", err))
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(fmt.Sprintf("kubetest: encode an RSA public key: %v", err))
	}
	sum := sha256.Sum256(pub)
	s.AddKey(id, email, &key.PublicKey)
	return kube.Credential{
		Email:         email,
		PrivateKeyID:  hex.EncodeToString(sum[:20]),
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
	}
}

// AddKey registers one more public key under id and email on a running server.
// An email may hold several keys: a /token assertion verifies when any key
// registered for its iss verifies it, and its token is minted for that key's id.
func (s *Server) AddKey(id, email string, pub *rsa.PublicKey) {
	if id == "" || email == "" || pub == nil {
		panic(fmt.Sprintf("kubetest: AddKey(%q, %q) needs an id, an email and a public key", id, email))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[email] = append(s.keys[email], registeredKey{id: id, pub: pub})
}

// Requests is every request, in order. Each Body is the caller's own copy.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Request, len(s.requests))
	for i, r := range s.requests {
		r.Body = bytes.Clone(r.Body)
		out[i] = r
	}
	return out
}

// Revoke makes the next request carrying this token get 401, and every one
// after it: a revoked token stays revoked. A fresh mint for the same identity
// gets a new token, which works.
func (s *Server) Revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if info := s.tokens[token]; info != nil {
		info.revoked = true
	}
}

// Close stops the server, ends every request still in flight (a followed log
// included) and waits for them. It may be called more than once.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.gate.Lock()
		s.closed = true
		s.gate.Unlock()
		s.cancel()
		_ = s.srv.Close()
		<-s.served
		s.inflight.Wait()
	})
}

// enter counts a request in, unless the server is closing.
func (s *Server) enter() bool {
	s.gate.Lock()
	defer s.gate.Unlock()
	if s.closed {
		return false
	}
	s.inflight.Add(1)
	return true
}

func (s *Server) record(r Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r)
}

// hold waits for WithDelay's duration, and reports false when the request's
// context ended first: its client is gone, and nothing is answered.
func (s *Server) hold(ctx context.Context, r Request) bool {
	if s.opts.delay == nil {
		return true
	}
	d := s.opts.delay(r)
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// serve is every request's entry.
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if !s.enter() {
		writeStatus(w, http.StatusServiceUnavailable, "", "kubetest: the server is closing", nil)
		return
	}
	defer s.inflight.Done()

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
	req := Request{
		Method:      r.Method,
		Path:        r.URL.Path,
		RawQuery:    r.URL.RawQuery,
		ContentType: r.Header.Get("Content-Type"),
		UserAgent:   r.UserAgent(),
		Accept:      r.Header.Get("Accept"),
		Body:        body,
	}
	if err != nil || len(body) > maxRequestBody {
		req.Body = nil
		s.record(req)
		if err != nil {
			writeStatus(w, http.StatusBadRequest, "", "kubetest: the request body could not be read", nil)
			return
		}
		writeStatus(w, http.StatusRequestEntityTooLarge, "", "kubetest: the request body is larger than 64 MiB", nil)
		return
	}
	if r.URL.Path == tokenPath {
		s.serveToken(w, r, req)
		return
	}
	s.serveAPI(w, r, req)
}

// serveAPI is every non-token request, in the order the package comment gives.
func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request, req Request) {
	info, as := s.authenticate(r.Header.Get("Authorization"))
	req.As = as
	s.record(req)
	if !s.hold(r.Context(), req) {
		return
	}
	if s.opts.warnings != nil {
		for _, text := range s.opts.warnings(req) {
			w.Header().Add("Warning", "299 - "+quoteWarning(text))
		}
	}
	if info == nil {
		writeStatus(w, http.StatusUnauthorized, "", "Unauthorized", nil)
		return
	}
	ri := parseRequestInfo(r.Method, r.URL.Path, r.URL.Query())
	az := s.rbac[info.email]
	if az != nil && !ri.isSelfReview() && !az.allows(ri) {
		writeForbidden(w, ri, info.email)
		return
	}
	if h := s.opts.handler; h != nil {
		if code, body, ok := h(req); ok {
			writeAnswer(w, code, body)
			return
		}
	}
	if f, ok := s.takeFail(r.Method, r.URL.Path); ok {
		writeInjected(w, f, ri, info.email)
		return
	}
	if r.Method == http.MethodGet {
		if body, ok := s.nextScript(r.URL.Path); ok {
			writeAnswer(w, http.StatusOK, body)
			return
		}
	}
	s.emulate(w, r, req, ri, *info, az)
}

// failKey is where an injected answer applies: one method on one path.
type failKey struct{ method, path string }

// injected is one answer queued by Fail.
type injected struct {
	code int
	st   kube.Status
}

// Fail queues one answer for the next request with this method and path
// (the path without its query), after authentication and WithRBAC: each
// call injects one answer, consumed by one request, and calls for the same
// method and path answer in the order they were made. A failure that must
// outlast a client's retries is injected once per attempt.
//
// The answer is a JSON Status built from st, with these defaults: st.Code is
// code, st.Status is Failure (Success below 400), st.Reason is the code's
// Kubernetes reason (Unauthorized, Forbidden, NotFound, Conflict, Expired for
// 410, Invalid for 422, TooManyRequests, InternalError, ServiceUnavailable),
// and st.Message is the code's HTTP text, except for 403, whose default
// message is the API server's, naming the caller's email, as GKE's does. A
// 409 carries whatever causes st.Details gives, FieldManagerConflict ones
// included, with each cause's type under its wire name "reason". A 429 also
// carries Retry-After: 1.
//
// A st.Kind other than "" or "Status" makes the body not a Status object:
// Google's JSON error, {"error":{"code","message","status"}}, as a 403 from
// the DNS endpoint's IAM check answers before Kubernetes sees the request.
func (s *Server) Fail(method, path string, code int, st kube.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := failKey{method, path}
	s.fails[k] = append(s.fails[k], injected{code: code, st: st})
}

func (s *Server) takeFail(method, path string) (injected, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := failKey{method, path}
	q := s.fails[k]
	if len(q) == 0 {
		return injected{}, false
	}
	f := q[0]
	if len(q) == 1 {
		delete(s.fails, k)
	} else {
		s.fails[k] = q[1:]
	}
	return f, true
}

// script is the answers Script set for one path.
type script struct {
	bodies [][]byte
	next   int
}

// Script makes successive GETs of path answer these objects in turn, each as
// JSON with 200; once they are used up, the last one answers every GET after
// it. An object answering a single-object path of a kind kubetest serves is
// given that kind's kind and apiVersion when it carries none, as a real
// server's answer does. Script answers come after Fail's and before the
// stored objects, which they leave untouched. Script with no objects removes
// the path's script.
func (s *Server) Script(path string, objs ...any) {
	bodies := make([][]byte, len(objs))
	k, single := singleObjectKind(path)
	for i, obj := range objs {
		b, err := marshalAny(obj)
		if err != nil {
			panic(fmt.Sprintf("kubetest: Script(%q): object %d: %v", path, i, err))
		}
		if single {
			if m, err := decodeJSONObject(b); err == nil {
				stampKind(m, k)
				b = mustMarshal(m)
			}
		}
		bodies[i] = b
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(bodies) == 0 {
		delete(s.scripts, path)
		return
	}
	s.scripts[path] = &script{bodies: bodies}
}

func (s *Server) nextScript(path string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc := s.scripts[path]
	if sc == nil {
		return nil, false
	}
	b := sc.bodies[min(sc.next, len(sc.bodies)-1)]
	sc.next++
	return b, true
}

// marshalAny is json.Marshal, except that raw JSON ([]byte or
// json.RawMessage) is taken as it is.
func marshalAny(obj any) ([]byte, error) {
	switch v := obj.(type) {
	case json.RawMessage:
		return bytes.Clone(v), nil
	case []byte:
		return bytes.Clone(v), nil
	}
	return json.Marshal(obj)
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("kubetest: encode an answer: %v", err))
	}
	return b
}

// errNotObject is a body that is JSON but not one object.
var errNotObject = errors.New("not a JSON object")
