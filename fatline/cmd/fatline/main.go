// Command fatline runs the FatLine data plane: the ingress mTLS tunnel and the
// deny-by-default egress proxy. For phase 2.1 it is a thin operator/developer
// harness — it loads mTLS material and an allowlist (from a ./farcast manifest)
// and serves both planes until SIGINT. How the tunnel becomes reachable across
// the internet (the point-of-presence carrier) is bound at 2.3 (ADR 0005); the
// in-cluster deploy + Secret provisioning is 2.3/4.2.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sofmon/farcast/fatline"
	fcrypto "github.com/sofmon/farcast/fatline/internal/crypto"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/shrike"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fatline:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("fatline", flag.ContinueOnError)
	var (
		tunnelListen = fs.String("tunnel-listen", "", "ingress mTLS tunnel listen address (e.g. :8443)")
		egressListen = fs.String("egress-listen", "", "egress forward-proxy listen address (e.g. :3128)")
		certPath     = fs.String("cert", "", "server certificate PEM (required for the tunnel)")
		keyPath      = fs.String("key", "", "server private key PEM (required for the tunnel)")
		caPath       = fs.String("ca", "", "client CA certificate PEM (required for the tunnel)")
		manifestPath = fs.String("manifest", "", "path to a ./farcast manifest whose external hosts seed the egress allowlist")
		endpoint     = fs.String("endpoint", "", "externally advertised endpoint, reported in status")
		shrikeSocket = fs.String("shrike-socket", "", "if set, stream egress events to a Shrike sidecar at this Unix socket (else log via slog)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tunnelListen == "" && *egressListen == "" {
		return fmt.Errorf("set --tunnel-listen and/or --egress-listen")
	}

	cfg := fatline.Config{
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

	if *manifestPath != "" {
		m, err := parser.ParseFile(*manifestPath)
		if err != nil {
			return fmt.Errorf("parse manifest: %w", err)
		}
		cfg.Allowlist = flattenExternal(m)
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

	fmt.Fprintf(os.Stderr, "fatline: serving (tunnel=%q egress=%q, %d allowlisted hosts, shrike=%q)\n",
		*tunnelListen, *egressListen, len(cfg.Allowlist), *shrikeSocket)
	err = srv.Serve(ctx)
	if ds != nil {
		_ = ds.Close()
	}
	return err
}

// flattenExternal collects every app's declared external hosts into one
// allowlist. Phase 2.1 is single-tenant; per-app scoping arrives in 4.4.
func flattenExternal(m *parser.Manifest) []parser.External {
	var out []parser.External
	for _, app := range m.Apps {
		out = append(out, app.External...)
	}
	return out
}
