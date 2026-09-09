// Command shrike runs the Shrike security monitor as a sidecar: it loads the
// declared egress policy from a ./farcast manifest, listens on a local Unix
// socket for FatLine's egress-decision stream, folds each decision into a live
// security picture, and raises alerts on violations. It optionally serves that
// picture as JSON for the operator (and, later, the FarSight GUI).
//
// For phase 2.2 it is a thin harness. The two-container Pod that co-schedules
// Shrike beside FatLine and wires the socket is templated by Planck (4.2).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sofmon/farcast/fatline/policy"
	"github.com/sofmon/farcast/manifest/parser"
	"github.com/sofmon/farcast/shrike"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "shrike:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("shrike", flag.ContinueOnError)
	var (
		socket       = fs.String("socket", "", "Unix socket to receive FatLine's egress events on (required)")
		manifestPath = fs.String("manifest", "", "path to a ./farcast manifest whose external hosts form the declared policy")
		policyPath   = fs.String("policy", "", "path to the per-application egress policy FatLine enforces (ADR 0013); the deployed sidecar reads the same mounted document")
		statusListen = fs.String("status-listen", "", "address to serve the security picture (JSON) on, e.g. :9090 (optional)")
		window       = fs.Duration("alert-window", time.Minute, "rate-limit window for repeated alerts of the same violation class")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *socket == "" {
		return errors.New("--socket is required")
	}

	if *manifestPath != "" && *policyPath != "" {
		return errors.New("--manifest and --policy both name the declared contract; pass one")
	}

	var declared []parser.External
	switch {
	case *manifestPath != "":
		m, err := parser.ParseFile(*manifestPath)
		if err != nil {
			return fmt.Errorf("parse manifest: %w", err)
		}
		declared = flattenExternal(m)
	case *policyPath != "":
		// The deployed sidecar reads the same mounted ConfigMap FatLine
		// enforces from, because in a cluster there is no manifest file: the
		// manifest was read inside the instance at 'farcast run' and what
		// survives is the policy document (ADR 0010 decision 6, ADR 0013).
		//
		// A missing file is not an error. A freshly connected instance has no
		// applications and therefore no policy, and the monitor's job — folding
		// FatLine's decisions and alerting on denials — does not depend on
		// knowing the contract. Without it the picture reports no declared
		// hosts, which is exactly true.
		var err error
		if declared, err = declaredFromPolicy(*policyPath); err != nil {
			return err
		}
	}

	mon := shrike.New(shrike.Config{
		Declared:    declared,
		AlertWindow: *window,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var statusSrv *http.Server
	if *statusListen != "" {
		statusSrv = &http.Server{Addr: *statusListen, Handler: mon.Handler()}
		go func() {
			if err := statusSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintln(os.Stderr, "shrike: status server:", err)
			}
		}()
	}

	fmt.Fprintf(os.Stderr, "shrike: monitoring (socket=%q, %d declared host(s), status=%q)\n",
		*socket, len(declared), *statusListen)

	err := shrike.Serve(ctx, *socket, mon)

	if statusSrv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = statusSrv.Shutdown(sctx)
		cancel()
	}
	return err
}

// declaredFromPolicy reads the egress policy document and flattens every
// application's declared hosts into the monitor's contract.
//
// Flattened, deliberately: FatLine enforces per application and reports the
// application on every event, so Shrike's contract is only used to annotate
// the picture — "was this allowed host one somebody declared?" — and that
// question has the same answer whichever application asked.
func declaredFromPolicy(path string) ([]parser.External, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read egress policy: %w", err)
	}
	doc, err := policy.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse egress policy: %w", err)
	}
	var out []parser.External
	for _, hosts := range doc.ByTenant() {
		out = append(out, hosts...)
	}
	return out, nil
}

// flattenExternal collects every app's declared external hosts into one policy.
// Phase 2.2 is single-tenant; per-app scoping arrives in 4.4.
func flattenExternal(m *parser.Manifest) []parser.External {
	var out []parser.External
	for _, app := range m.Apps {
		out = append(out, app.External...)
	}
	return out
}
