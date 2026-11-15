package rehearsal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/kube/kubetest"
	"github.com/sofmon/farcast/fatline"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/shrike"
)

// The cluster, FatLine, Shrike and the keyholders, all on 127.0.0.1 (D5), and
// the traffic that gives the map something counted (D6).

const (
	// replicaName stands in for the Pod name Shrike stamps on its picture:
	// the monitor uses os.Hostname(), the operator's Mac's own name, which
	// must never reach a screenshot.
	replicaName = "fatline-rehearsal-0"
	// The one application host the rehearsal reaches, and the one it is
	// refused in denied.
	paymentsHost = "api.payments.invalid"
	telemetry    = "telemetry.invalid"
	trackerHost  = "tracker.invalid"
	// startupWait bounds how long Start waits for the monitor to hold the
	// start-up traffic.
	startupWait = 5 * time.Second
	egressTick  = time.Minute
	keeperTick  = 10 * time.Minute
	// tunnelWatch is how often the tunnel's watcher reads the scenario, so
	// tunnel-down takes effect within a moment of the switch.
	tunnelWatch = 100 * time.Millisecond
	// tokenPath is where the cluster's token endpoint answers (kubetest's).
	tokenPath = "/token"
)

// declared is what the shop's api declares, which Shrike and the policy
// ConfigMap both hold. web declares nothing.
func declared() []parser.External {
	return []parser.External{{Host: paymentsHost, Reason: "payments"}, {Host: telemetry, Reason: "error reports"}}
}

// discard is an Alerter that drops alerts: the rehearsal's alerts are the
// world document's, not Shrike's log.
type discard struct{}

func (discard) Alert(shrike.Alert) {}

func (r *Rig) serve(ctx context.Context) error {
	rctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	token, err := identity.LeafTokenPEM(r.m.keeperCert)
	if err != nil {
		return err
	}
	r.keeperID = token
	r.mon = shrike.New(shrike.Config{Declared: declared(), Alerter: discard{}})

	if err := r.serveCluster(); err != nil {
		return err
	}

	// Shrike's status route.
	sl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	r.shrikeAddr = sl.Addr().String()
	r.goServe(&http.Server{Handler: r.shrikeHandler(), ReadHeaderTimeout: 10 * time.Second}, sl)

	// The keyholders: TLS 1.3, the instance CA's leaves only, on a port pair
	// P and P+1 with P a multiple of ten, so FatLine's one route reaches
	// replica i at "127.0.0.1:<P/10>{ordinal}".
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(r.m.caCert) {
		return errors.New("the instance's CA certificate does not parse")
	}
	khLeaf, err := tls.X509KeyPair(r.m.khCert, r.m.khKey)
	if err != nil {
		return fmt.Errorf("the keyholder's leaf: %w", err)
	}
	pair, base, err := listenPair()
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{khLeaf},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: pool,
		NextProtos: []string{"http/1.1"},
	}
	for i, l := range pair {
		r.keyholderAddrs = append(r.keyholderAddrs, l.Addr().String())
		r.goServe(&http.Server{Handler: r.keyholderHandler(i), ReadHeaderTimeout: 10 * time.Second}, tls.NewListener(l, tlsCfg))
	}

	// FatLine.
	serverLeaf, err := tls.X509KeyPair(r.m.serverCert, r.m.serverKey)
	if err != nil {
		return fmt.Errorf("FatLine's leaf: %w", err)
	}
	r.fatlineConfig = fatline.Config{
		TunnelListen: r.TunnelAddr, Instance: r.spec.Instance,
		ServerCert: serverLeaf, ClientCA: pool,
		StreamRoutes: []fatline.StreamRoute{
			{Name: fldeploy.ShrikeStreamRoute, Addr: r.shrikeAddr},
			{Name: keyholder.StreamRoute, Addr: fmt.Sprintf("127.0.0.1:%d{ordinal}", base/10), Ordinals: 2},
		},
		KeeperRoutes: []string{keyholder.StreamRoute},
		Events:       r.mon, Endpoint: r.TunnelAddr, Node: "rehearsal",
		Logger: slog.New(slog.NewTextHandler(r.log, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}
	served, err := r.startTunnel()
	if err != nil {
		return err
	}

	// The start-up traffic, then wait until the monitor holds it. The
	// keeper's read is also what shows the tunnel answering: it is tried
	// until FatLine listens, and a bare TCP probe would leave FatLine a
	// handshake that never finished to log. The tunnel comes up for it even
	// in tunnel-down, and only then follows the scenario.
	r.emitEgress(true)
	if err := r.untilKeeperReads(ctx, served); err != nil {
		return err
	}
	if err := r.waitMonitor(ctx); err != nil {
		return err
	}
	r.syncTunnel()
	r.wg.Go(func() { r.traffic(rctx) })
	r.wg.Go(func() { r.watchTunnel(rctx) })
	return nil
}

// closerFunc is an io.Closer that runs a function.
type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// serveCluster starts the rehearsal's cluster: one fake API server and token
// endpoint (kubetest) on the recorded address, knowing the instance's reader
// and writer by their public keys, answering through clusterHandler, and
// keeping no request log of its own: a rehearsal serves for weeks, and every
// /token body holds a signed assertion. calls.log is written from what it
// answered, never with a body. Each start makes a new CA, so cluster-ca.crt
// is written anew.
func (r *Rig) serveCluster() error {
	srv, err := kubetest.Start(
		kubetest.WithAddr(r.ClusterAddr),
		kubetest.WithIdentity(readerID, readerEmail(r.spec.Instance), r.m.readerPub),
		kubetest.WithIdentity(writerID, writerEmail, r.m.writerPub),
		kubetest.WithHandler(r.clusterHandler),
		kubetest.WithTokenAnswer(r.tokenAnswer),
		kubetest.WithDelay(r.clusterDelay),
		kubetest.WithAnswered(r.clusterAnswered),
		kubetest.WithoutRecording(),
	)
	if err != nil {
		return fmt.Errorf("the rehearsal's cluster did not start on %s: %w", r.ClusterAddr, err)
	}
	r.cluster = srv
	r.servers = append(r.servers, closerFunc(func() error { srv.Close(); return nil }))
	if err := config.Dir(r.ConfigDir).SaveClusterCA(r.spec.Instance, srv.CAPEM()); err != nil {
		return fmt.Errorf("write the rehearsal instance's %s: %w", clusterCAFile, err)
	}
	return nil
}

// clusterHandler answers every request the cluster authenticated. A writer's
// token is refused first, whatever it asks for: the writer never reads. Then
// the reader's reads are answered as the scenario says (ClusterAnswer), and
// anything else is 405. Nothing falls through to kubetest's own emulation.
func (r *Rig) clusterHandler(req kubetest.Request) (int, []byte, bool) {
	if req.As == writerID {
		return http.StatusForbidden, statusJSON(http.StatusForbidden, "Forbidden",
			"forbidden: the rehearsal's cluster answers the instance's reader alone, and a writer token never reads", nil), true
	}
	s, err := LoadSpec(r.Dir)
	if err != nil {
		return http.StatusInternalServerError, statusJSON(http.StatusInternalServerError, "InternalError",
			"the rehearsal's state could not be read", nil), true
	}
	code, body := ClusterAnswer(s, req.Method, req.Path, req.RawQuery, time.Now())
	return code, body, true
}

// tokenAnswer is the token endpoint for an assertion that verified: in
// token-refused, Google's refusal; otherwise kubetest mints.
func (r *Rig) tokenAnswer(string) (int, []byte, bool) {
	if s, err := LoadSpec(r.Dir); err != nil || s.Scenario != ScenarioTokenRefused {
		return 0, nil, false
	}
	return http.StatusBadRequest, marshal(map[string]string{
		"error": "invalid_grant", "error_description": "the rehearsal refuses every assertion in token-refused",
	}), true
}

// clusterDelay holds every answer, a /token's included, for SlowSeconds in
// slow-cluster, and nothing otherwise.
func (r *Rig) clusterDelay(kubetest.Request) time.Duration {
	s, err := LoadSpec(r.Dir)
	if err != nil || s.Scenario != ScenarioSlowCluster {
		return 0
	}
	return time.Duration(s.SlowSeconds * float64(time.Second))
}

// clusterAnswered writes one calls.log line for every request the cluster
// answered or refused:
//
//	<time> cluster <METHOD> <path>[?<query>] as <reader|writer|none|unknown> | <outcome>
//	<time> token <METHOD> /token as <reader|writer|unknown> | <outcome>
//
// "none" is a request with no token, and "unknown" a token the cluster did
// not mint, or, on /token, an assertion that verified against no registered
// key. A line never holds a body, an assertion or a token.
func (r *Rig) clusterAnswered(req kubetest.Request, status int) {
	target := req.Path
	if req.RawQuery != "" {
		target += "?" + req.RawQuery
	}
	if req.Path == tokenPath {
		as := req.As
		if as == "" {
			as = "unknown"
		}
		appendCall(r.Dir, "token", []string{req.Method, target, "as", as}, tokenOutcome(req, status))
		return
	}
	as := req.As
	switch as {
	case "":
		as = "none"
	case "?":
		as = "unknown"
	}
	appendCall(r.Dir, "cluster", []string{req.Method, target, "as", as}, r.clusterOutcome(req, status))
}

// tokenOutcome is a /token answer's calls.log outcome.
func tokenOutcome(req kubetest.Request, status int) string {
	switch {
	case status == 0:
		return "refused: the caller left while the answer was held"
	case status == http.StatusOK:
		return "ok"
	case status == http.StatusBadRequest && req.As != "":
		return "refused: token-refused refuses every assertion"
	case status == http.StatusBadRequest:
		return "refused: the assertion did not verify"
	}
	return refusedStatus(status)
}

// clusterOutcome is an API answer's calls.log outcome. An absent ConfigMap's
// 404 is an answer, and ok.
func (r *Rig) clusterOutcome(req kubetest.Request, status int) string {
	switch status {
	case 0:
		return "refused: the caller left while the answer was held"
	case http.StatusOK, http.StatusNotFound:
		return "ok"
	case http.StatusUnauthorized:
		if req.As == "" || req.As == "?" {
			return "refused: no token the cluster minted"
		}
		return "refused: unauthorized answers every read"
	case http.StatusForbidden:
		if req.As == writerID {
			return "refused: a writer token on a read"
		}
		return "refused: forbidden answers this read"
	case http.StatusMethodNotAllowed:
		return "refused: no answer"
	case http.StatusInternalServerError:
		s, err := LoadSpec(r.Dir)
		switch {
		case err != nil:
			return "refused: the rehearsal's state could not be read"
		case s.expired(time.Now()):
			return "refused: " + errExpired
		}
		return "refused: the rehearsal could not build its answer"
	}
	return refusedStatus(status)
}

func refusedStatus(status int) string {
	return fmt.Sprintf("refused: %d %s", status, http.StatusText(status))
}

// errStopping is startTunnel's refusal once Close has begun.
var errStopping = errors.New("the rehearsal is stopping")

// startTunnel starts a FatLine on the tunnel's address, under its own stop,
// unless one runs or the rig is closing. served gets what its Serve returned.
func (r *Rig) startTunnel() (served <-chan error, err error) {
	r.tunnelMu.Lock()
	defer r.tunnelMu.Unlock()
	if r.tunnelClosed {
		return nil, errStopping
	}
	if r.tunnelUpLocked() {
		return nil, nil
	}
	// A new Server each time: Serve runs once, and a new one over the same
	// monitor keeps every row the monitor holds.
	srv, err := fatline.New(r.fatlineConfig)
	if err != nil {
		return nil, err
	}
	tctx, cancel := context.WithCancel(context.Background())
	ch := make(chan error, 1)
	done := make(chan struct{})
	r.wg.Go(func() {
		defer close(done)
		err := srv.Serve(tctx)
		if err != nil && tctx.Err() == nil {
			r.logf("FatLine's tunnel stopped: %v", err)
		}
		ch <- err
	})
	r.tunnelStop = func() { cancel(); <-done }
	r.tunnelDone = done
	return ch, nil
}

// tunnelUpLocked reports whether a FatLine started and has not stopped. The
// caller holds tunnelMu.
func (r *Rig) tunnelUpLocked() bool {
	if r.tunnelDone == nil {
		return false
	}
	select {
	case <-r.tunnelDone:
		return false
	default:
		return true
	}
}

// stopTunnel stops the FatLine running now, if any, and waits for it; its
// listener closes first, so the port refuses from then on. closing also keeps
// any from starting again.
func (r *Rig) stopTunnel(closing bool) {
	r.tunnelMu.Lock()
	stop := r.tunnelStop
	r.tunnelStop, r.tunnelDone = nil, nil
	if closing {
		r.tunnelClosed = true
	}
	r.tunnelMu.Unlock()
	if stop != nil {
		stop()
	}
}

// syncTunnel makes the tunnel what the scenario says: down in tunnel-down,
// up otherwise, a FatLine that stopped on its own included. A spec that
// cannot be read changes nothing.
func (r *Rig) syncTunnel() {
	s, err := LoadSpec(r.Dir)
	if err != nil {
		return
	}
	if s.Scenario == ScenarioTunnelDown {
		r.stopTunnel(false)
		return
	}
	if _, err := r.startTunnel(); err != nil && !errors.Is(err, errStopping) {
		r.logf("FatLine's tunnel did not start again: %v", err)
	}
}

// watchTunnel reads the scenario every tunnelWatch until ctx ends, and stops
// or starts the tunnel to follow it: SetScenario usually runs in another
// process, and nothing else would tell this one.
func (r *Rig) watchTunnel(ctx context.Context) {
	t := time.NewTicker(tunnelWatch)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.syncTunnel()
		}
	}
}

// goServe runs one HTTP server on a listener until Close.
func (r *Rig) goServe(s *http.Server, l net.Listener) {
	r.servers = append(r.servers, s)
	r.wg.Go(func() {
		if err := s.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			r.logf("a listener stopped: %v", err)
		}
	})
}

// listenPair listens on 127.0.0.1:P and P+1 for a random P that is a
// multiple of ten.
func listenPair() ([]net.Listener, int, error) {
	var last error
	for range 50 {
		p := 20000 + 10*rand.IntN(4000) // [20000, 60000)
		a, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			last = err
			continue
		}
		b, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p+1))
		if err != nil {
			_ = a.Close()
			last = err
			continue
		}
		return []net.Listener{a, b}, p, nil
	}
	return nil, 0, fmt.Errorf("no free port pair for the keyholders on 127.0.0.1: %w", last)
}

// untilKeeperReads makes the keeper's first read of storage through the
// tunnel, trying again until FatLine listens, for at most startupWait. It
// gives up at once if FatLine stops: its listener could not bind.
func (r *Rig) untilKeeperReads(ctx context.Context, served <-chan error) error {
	deadline := time.Now().Add(startupWait)
	for {
		select {
		case err := <-served:
			if err == nil {
				err = errors.New("it stopped")
			}
			return fmt.Errorf("FatLine did not start on %s: %w", r.TunnelAddr, err)
		default:
		}
		err := r.keeperCall(ctx)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the keeper could not read storage through the tunnel on %s within %s: %w", r.TunnelAddr, startupWait, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// shrikeHandler serves Shrike's picture with the replica renamed. In denied
// it first records one refusal of shop/web, synchronously, so the very read
// that asks shows it: Emit records before it returns.
func (r *Rig) shrikeHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+shrike.StatusPath, func(w http.ResponseWriter, _ *http.Request) {
		s, err := LoadSpec(r.Dir)
		if err != nil {
			http.Error(w, "the rehearsal's state could not be read", http.StatusInternalServerError)
			return
		}
		if s.Scenario == ScenarioDenied {
			r.mon.Emit(event.Event{
				Kind: event.Deny, Tenant: shopNamespace, App: "web", Host: trackerHost, Port: "443",
				Proto: "connect", SNI: trackerHost, Reason: event.ReasonNotInAllowlist,
			})
		}
		snap := r.mon.Snapshot()
		snap.Replica = replicaName
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snap)
	})
	return mux
}

// keyholderHandler answers GET /v1/state for one replica, and refuses
// everything else — and records the refusal, which is how calls.log proves
// that 'world' only ever reads state.
func (r *Rig) keyholderHandler(ordinal int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/v1/state" {
			appendCall(r.Dir, "keyholder", []string{req.Method, req.URL.Path}, "refused")
			http.NotFound(w, req)
			return
		}
		s, err := LoadSpec(r.Dir)
		if err != nil {
			http.Error(w, "the rehearsal's state could not be read", http.StatusInternalServerError)
			return
		}
		phase := "unsealed"
		if s.Scenario == ScenarioSealed && ordinal == 1 {
			phase = "sealed"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"instance": s.Instance, "phase": phase, "since": s.Started.UTC(), "generation": 7,
		})
	})
}

// emitEgress is the shop's api reaching its payments host, as FatLine reports
// it: an allow and its close. The first time, also one failed dial.
func (r *Rig) emitEgress(withFail bool) {
	e := event.Event{Tenant: shopNamespace, App: "api", Host: paymentsHost, Port: "443", Proto: "connect", SNI: paymentsHost}
	allow := e
	allow.Kind = event.Allow
	r.mon.Emit(allow)
	closed := e
	closed.Kind, closed.BytesUp, closed.BytesDown, closed.DialMillis, closed.DurationMillis = event.Close, 2048, 8192, 12, 340
	r.mon.Emit(closed)
	if withFail {
		fail := e
		fail.Kind, fail.Reason, fail.DialMillis = event.Fail, event.ReasonDialFailed, 3000
		r.mon.Emit(fail)
	}
}

// keeperCall is the keeper device reading storage's state through the
// tunnel, as itself: FatLine records the stream, and the map draws the keeper
// healthy with a line into storage.
func (r *Rig) keeperCall(ctx context.Context) error {
	cert, err := tls.X509KeyPair(r.m.keeperCert, r.m.keeperKey)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(r.m.caCert)
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := tunnel.Connect(cctx, "https://"+r.TunnelAddr, tunnel.ClientIdentity{
		Cert: cert, CA: pool, ServerName: identity.ServerName(r.spec.Instance),
	})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	kh, err := keyholder.New(conn, r.spec.Instance, r.m.caCert, r.m.keeperCert, r.m.keeperKey)
	if err != nil {
		return err
	}
	_, err = kh.State(cctx, 0)
	return err
}

// waitMonitor waits until the monitor holds the keeper's relayed stream into
// storage and the api's allowed egress. FatLine hands stream events to the
// monitor through a buffer, after the relay ends, so the keeper's row can
// trail the call that made it.
func (r *Rig) waitMonitor(ctx context.Context) error {
	deadline := time.Now().Add(startupWait)
	for !r.startupSeen() {
		if time.Now().After(deadline) {
			return errors.New("the keeper stream never reached the monitor")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return nil
}

func (r *Rig) startupSeen() bool {
	snap := r.mon.Snapshot()
	keeper, egress := false, false
	for _, t := range snap.Tunnel {
		if t.Role == event.PeerKeeper && t.Peer == r.keeperID && t.Route == keyholder.StreamRoute && t.Relayed >= 1 {
			keeper = true
		}
	}
	for _, a := range snap.Allowed {
		if a.Namespace == shopNamespace && a.App == "api" && a.Host == paymentsHost {
			egress = true
		}
	}
	return keeper && egress
}

// traffic repeats the egress every minute and the keeper every ten.
func (r *Rig) traffic(ctx context.Context) {
	egress := time.NewTicker(egressTick)
	defer egress.Stop()
	keeper := time.NewTicker(keeperTick)
	defer keeper.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-egress.C:
			r.emitEgress(false)
		case <-keeper.C:
			if err := r.keeperCall(ctx); err != nil && ctx.Err() == nil {
				r.logf("the keeper's periodic read failed: %v", err)
			}
		}
	}
}
