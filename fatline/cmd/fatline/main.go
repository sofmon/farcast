// Command fatline runs the FatLine data plane: the ingress mTLS tunnel and the
// deny-by-default egress proxy. For phase 2.1 it is a thin operator/developer
// harness — it loads mTLS material and an allowlist (from a ./farcast manifest)
// and serves both planes until SIGINT. How the tunnel becomes reachable across
// the internet (the point-of-presence carrier) is bound at 2.3 (ADR 0005); the
// in-cluster deploy + Secret provisioning is 2.3/4.2.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sofmon/farcast/fatline"
	fcrypto "github.com/sofmon/farcast/fatline/internal/crypto"
	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/shrike"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fatline:", err)
		os.Exit(1)
	}
}

// policyPollInterval is how often the mounted policy file is re-read. A
// ConfigMap update reaches a pod on the kubelet's own schedule of tens of
// seconds, so polling faster would only spend wakeups.
const policyPollInterval = 10 * time.Second

func run(args []string) error {
	fs := flag.NewFlagSet("fatline", flag.ContinueOnError)
	var (
		tunnelListen = fs.String("tunnel-listen", "", "ingress mTLS tunnel listen address (e.g. :8443)")
		egressListen = fs.String("egress-listen", "", "egress forward-proxy listen address (e.g. :3128)")
		certPath     = fs.String("cert", "", "server certificate PEM (required for the tunnel)")
		keyPath      = fs.String("key", "", "server private key PEM (required for the tunnel)")
		caPath       = fs.String("ca", "", "client CA certificate PEM (required for the tunnel)")
		policyPath   = fs.String("policy", "", "path to the per-application egress policy (ADR 0013); absent means no application can be identified, so none may reach anything")
		endpoint     = fs.String("endpoint", "", "externally advertised endpoint, reported in status")
		streamRoutes routeFlag
		shrikeSocket = fs.String("shrike-socket", "", "if set, stream egress events to a Shrike sidecar at this Unix socket (else log via slog)")
	)
	fs.Var(&streamRoutes, "stream-route",
		"in-instance service the operator may reach through the tunnel, as name=host:port[=ordinals] (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tunnelListen == "" && *egressListen == "" {
		return fmt.Errorf("set --tunnel-listen and/or --egress-listen")
	}

	routes, err := streamRoutes.routes()
	if err != nil {
		return err
	}

	cfg := fatline.Config{
		StreamRoutes: routes,
		TunnelListen: *tunnelListen,
		EgressListen: *egressListen,
		Endpoint:     *endpoint,
	}

	if *tunnelListen != "" {
		if *certPath == "" || *keyPath == "" || *caPath == "" {
			return fmt.Errorf("--cert, --key and --ca are required for the tunnel")
		}
		cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			return fmt.Errorf("load server certificate: %w", err)
		}
		caPEM, err := os.ReadFile(*caPath)
		if err != nil {
			return fmt.Errorf("read client CA: %w", err)
		}
		pool, err := fcrypto.PoolFromPEM(caPEM)
		if err != nil {
			return err
		}
		cfg.ServerCert = cert
		cfg.ClientCA = pool
	}

	if *policyPath != "" {
		doc, err := loadPolicy(*policyPath)
		switch {
		case errors.Is(err, os.ErrNotExist):
			// Expected on a freshly connected instance: FatLine is deployed
			// before any application exists to have a policy. Start closed and
			// let the watcher pick the file up when `farcast run` writes it —
			// refusing to start would make the network boundary depend on
			// there being something to police.
			fmt.Fprintf(os.Stderr, "fatline: no egress policy at %s yet; starting closed\n", *policyPath)
		case err != nil:
			return err
		default:
			cfg.Policy = doc
		}
	}

	// Optionally ship egress decisions to a Shrike sidecar; otherwise FatLine's
	// default slog sink logs them. The data plane never depends on Shrike being
	// up — DialSink drops-and-counts when the sidecar is absent (2.2).
	var ds *shrike.DialSink
	if *shrikeSocket != "" {
		ds = shrike.NewDialSink(*shrikeSocket)
		cfg.Events = ds
	}

	srv, err := fatline.New(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The policy is a mounted ConfigMap: `farcast run` writes it and the
	// kubelet propagates the change. Watching the file is what makes deploying
	// an application not require restarting the instance's network boundary
	// (ADR 0013 decision 5).
	if *policyPath != "" {
		go watchPolicy(ctx, *policyPath, policyPollInterval, srv,
			func(format string, args ...any) { fmt.Fprintf(os.Stderr, format, args...) })
	}

	apps := 0
	if cfg.Policy != nil {
		apps = len(cfg.Policy.Apps)
	}
	fmt.Fprintf(os.Stderr, "fatline: serving (tunnel=%q egress=%q, %d application(s) with policy, shrike=%q)\n",
		*tunnelListen, *egressListen, apps, *shrikeSocket)
	if *policyPath == "" {
		fmt.Fprintf(os.Stderr, "fatline: no egress policy: no application can be identified, so none may reach anything\n")
	}
	err = srv.Serve(ctx)
	if ds != nil {
		_ = ds.Close()
	}
	return err
}

// flattenExternal collects every app's declared external hosts into one
// allowlist. Phase 2.1 is single-tenant; per-app scoping arrives in 4.4.
// loadPolicy reads and validates the per-application egress policy.
func loadPolicy(path string) (*policy.Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read egress policy: %w", err)
	}
	doc, err := policy.Parse(data)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

// watchPolicy re-reads the policy file and reloads on change.
//
// Polling rather than an inotify library, for the reason this project gives
// everywhere: a dependency is a security decision, and the thing being watched
// is a mounted ConfigMap whose updates the kubelet already applies on its own
// schedule of tens of seconds. A watch precise to the millisecond would be
// precision about the wrong end of the pipe.
//
// A policy that fails to parse is REFUSED and the previous one stays in force.
// The alternative — dropping to no policy — would turn a typo in a document
// into an instance-wide egress outage, and the last known-good policy is the
// operator's own most recent intent.
func watchPolicy(ctx context.Context, path string, every time.Duration, srv *fatline.Server, log func(string, ...any)) {
	last, _ := os.ReadFile(path)
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		data, err := os.ReadFile(path)
		if err != nil || bytes.Equal(data, last) {
			continue
		}
		doc, err := policy.Parse(data)
		if err != nil {
			log("fatline: refusing an unreadable egress policy, keeping the previous one: %v\n", err)
			// last is deliberately NOT updated: a file that is still broken on
			// the next tick must be complained about again, or an operator who
			// looks a minute later sees silence and assumes it took.
			continue
		}
		last = data
		srv.ReloadPolicy(doc)
		log("fatline: egress policy reloaded (%d applications)\n", len(doc.Apps))
	}
}

// routeFlag collects repeatable --stream-route values.
//
// The spec is name=host:port[=ordinals]. A caller of the relay names the ROUTE
// and never the address, so this is the only place an in-instance address is
// ever written down — fixed at deploy time, not chosen by whoever dials.
type routeFlag []string

func (r *routeFlag) String() string { return strings.Join(*r, ",") }

func (r *routeFlag) Set(v string) error {
	*r = append(*r, v)
	return nil
}

func (r *routeFlag) routes() ([]fatline.StreamRoute, error) {
	out := make([]fatline.StreamRoute, 0, len(*r))
	for _, spec := range *r {
		parts := strings.Split(spec, "=")
		if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("fatline: --stream-route wants name=host:port[=ordinals], got %q", spec)
		}
		route := fatline.StreamRoute{Name: parts[0], Addr: parts[1]}
		if len(parts) == 3 {
			n, err := strconv.Atoi(parts[2])
			if err != nil || n < 0 {
				return nil, fmt.Errorf("fatline: --stream-route %q has a bad ordinal count", spec)
			}
			route.Ordinals = n
		}
		out = append(out, route)
	}
	return out, nil
}
