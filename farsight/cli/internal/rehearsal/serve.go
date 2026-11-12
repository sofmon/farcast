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

	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/fatline"
	fldeploy "github.com/sofmon/farcast/fatline/deploy"
	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/fatline/identity"
	"github.com/sofmon/farcast/fatline/tunnel"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/shrike"
)

// FatLine, Shrike and the keyholders, all on 127.0.0.1 (D5), and the traffic
// that gives the map something counted (D6).

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
	srv, err := fatline.New(fatline.Config{
		TunnelListen: r.TunnelAddr, Instance: r.spec.Instance,
		ServerCert: serverLeaf, ClientCA: pool,
		StreamRoutes: []fatline.StreamRoute{
			{Name: fldeploy.ShrikeStreamRoute, Addr: r.shrikeAddr},
			{Name: keyholder.StreamRoute, Addr: fmt.Sprintf("127.0.0.1:%d{ordinal}", base/10), Ordinals: 2},
		},
		KeeperRoutes: []string{keyholder.StreamRoute},
		Events:       r.mon, Endpoint: r.TunnelAddr, Node: "rehearsal",
		Logger: slog.New(slog.NewTextHandler(r.log, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		return err
	}
	served := make(chan error, 1)
	r.wg.Go(func() { served <- srv.Serve(rctx) })

	// The start-up traffic, then wait until the monitor holds it. The
	// keeper's read is also what shows the tunnel answering: it is tried
	// until FatLine listens, and a bare TCP probe would leave FatLine a
	// handshake that never finished to log.
	r.emitEgress(true)
	if err := r.untilKeeperReads(ctx, served); err != nil {
		return err
	}
	if err := r.waitMonitor(ctx); err != nil {
		return err
	}
	r.wg.Go(func() { r.traffic(rctx) })
	return nil
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
