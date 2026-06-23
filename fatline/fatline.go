// Package fatline is the FarCast data plane: the sole networking layer of an
// instance. It runs two planes as an ordinary userspace Pod (ADR 0003):
//
//   - the ingress mTLS tunnel — the operator (and later the FarSight GUI) dials
//     into the instance over one mutually-authenticated, multiplexed session;
//   - the egress proxy — an in-instance application reaches only the external
//     hosts its ./farcast manifest declares, deny-by-default.
//
// This is the Phase 2.1 artifact. The external point of presence (the carrier
// that makes the tunnel reachable across the internet) and the `farcast
// connect` command are bound in 2.3 (ADR 0005); Shrike is 2.2; the NetworkPolicy
// and sidecar that make FatLine unbypassable are Planck 4.2. FatLine
// authenticates the data plane with FarCast's own per-instance CA — never
// Google IAM — keeping the sovereign path free of any central dependency.
package fatline

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/sofmon/farcast/fatline/event"
	"github.com/sofmon/farcast/fatline/internal/allowlist"
	fcrypto "github.com/sofmon/farcast/fatline/internal/crypto"
	"github.com/sofmon/farcast/fatline/internal/proxy"
	"github.com/sofmon/farcast/fatline/internal/router"
	"github.com/sofmon/farcast/manifest/parser"
)

// Config configures a FatLine Server. mTLS material is minted by the crypto
// package; the allowlist is built from parsed manifest `external` declarations.
type Config struct {
	// TunnelListen is the ingress mTLS tunnel listen address (ClusterIP in 2.1).
	// Empty disables the tunnel.
	TunnelListen string
	// EgressListen is the forward-proxy listen address that the SDK's HTTPClient
	// points at (FARCAST_FATLINE_PROXY, injected by Planck 4.2). Empty disables
	// the egress proxy.
	EgressListen string

	// ServerCert is this listener's server leaf + key (server leg of the mTLS).
	ServerCert tls.Certificate
	// ClientCA verifies operator client certificates (no system-root fallback).
	ClientCA *x509.CertPool
	// AllowClientIdentity authorizes a verified client's URI-SAN identity. Nil
	// accepts any client presenting a CA-signed certificate.
	AllowClientIdentity func(uri string) bool

	// Allowlist is the egress policy: declared external hosts, deny-by-default.
	Allowlist []parser.External
	// Events receives egress decisions; Shrike (2.2) implements this. Nil logs
	// via slog.
	Events event.Sink

	// Endpoint is the externally advertised endpoint, reported in status.
	Endpoint string
	// Logger for diagnostics. Nil uses slog.Default().
	Logger *slog.Logger
}

// Server is the FatLine data plane: the ingress tunnel and the egress proxy.
type Server struct {
	cfg      Config
	allow    *allowlist.List
	egress   Egress
	sessions *router.Table
	events   *event.BufferedSink

	mu    sync.Mutex
	since time.Time
}

// New constructs a Server. At least one of TunnelListen / EgressListen must be set.
func New(cfg Config) (*Server, error) {
	if cfg.TunnelListen == "" && cfg.EgressListen == "" {
		return nil, errors.New("fatline: no listen address configured (set TunnelListen and/or EgressListen)")
	}
	al := allowlist.New(cfg.Allowlist)

	sink := cfg.Events
	if sink == nil {
		sink = event.SlogSink{Logger: cfg.Logger}
	}
	buffered := event.NewBufferedSink(sink, 0)

	s := &Server{
		cfg:      cfg,
		allow:    al,
		sessions: router.NewTable(),
		events:   buffered,
	}
	s.egress = proxy.New(proxy.Options{
		Allowlist:  al,
		Events:     buffered,
		EnforceSNI: true, // default-on; degrades only to authority-only, never off
	})
	return s, nil
}

// Serve runs both planes until ctx is cancelled, then drains gracefully. It
// returns the first fatal listener error, or nil on a clean shutdown.
func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	s.since = time.Now()
	s.mu.Unlock()

	go s.events.Run(ctx)

	var wg sync.WaitGroup
	errc := make(chan error, 2)

	var egressSrv *http.Server
	if s.cfg.EgressListen != "" {
		egressSrv = &http.Server{Addr: s.cfg.EgressListen, Handler: s.egress}
		wg.Go(func() {
			if err := egressSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("fatline: egress listener: %w", err)
			}
		})
	}

	var tunnelSrv *http.Server
	if s.cfg.TunnelListen != "" {
		tunnelSrv = &http.Server{
			Addr:      s.cfg.TunnelListen,
			Handler:   s.ingressHandler(),
			TLSConfig: fcrypto.ServerTLSConfig(s.cfg.ServerCert, s.cfg.ClientCA, s.cfg.AllowClientIdentity),
			ConnState: s.sessions.ConnState,
		}
		wg.Go(func() {
			// Certificates live in TLSConfig, so the file arguments are empty.
			if err := tunnelSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("fatline: tunnel listener: %w", err)
			}
		})
	}

	var retErr error
	select {
	case <-ctx.Done():
	case retErr = <-errc:
	}
	shutdown(egressSrv)
	shutdown(tunnelSrv)
	wg.Wait()
	return retErr
}

// shutdown gracefully drains a server with a bounded timeout.
func shutdown(srv *http.Server) {
	if srv == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// ingressHandler serves the tunnel. In 2.1 it answers the status probe; routing
// to in-instance services (the FarSight server) attaches here in later phases.
func (s *Server) ingressHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(StatusPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Status())
	})
	return mux
}

// Status reports the boundary's current health.
func (s *Server) Status() ConnStatus {
	s.mu.Lock()
	since := s.since
	s.mu.Unlock()
	return ConnStatus{
		Connected: true,
		Endpoint:  s.cfg.Endpoint,
		Since:     since,
		Active:    s.sessions.Active(),
		Allowlist: s.allow.Hosts(),
	}
}

// ReloadAllowlist atomically replaces the egress allowlist. Concurrent egress
// checks see either the old or the new list, never a mix.
func (s *Server) ReloadAllowlist(decls []parser.External) {
	s.allow.Reload(decls)
}

// DroppedEvents reports how many egress events were dropped because the event
// sink could not keep up (the block/allow decision always happened regardless).
func (s *Server) DroppedEvents() int64 { return s.events.Dropped() }

// String is redacted so a logged Config/Server can never leak key material.
func (s *Server) String() string {
	return fmt.Sprintf("fatline.Server{endpoint:%q active:%d}", s.cfg.Endpoint, s.sessions.Active())
}

// String is redacted: Config carries the server private key (in ServerCert), so
// it must never render in full.
func (c Config) String() string {
	return fmt.Sprintf("fatline.Config{tunnel:%q egress:%q hosts:%d …redacted…}",
		c.TunnelListen, c.EgressListen, len(c.Allowlist))
}
