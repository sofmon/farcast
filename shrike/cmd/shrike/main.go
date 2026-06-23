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
		statusListen = fs.String("status-listen", "", "address to serve the security picture (JSON) on, e.g. :9090 (optional)")
		window       = fs.Duration("alert-window", time.Minute, "rate-limit window for repeated alerts of the same violation class")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *socket == "" {
		return errors.New("--socket is required")
	}

	var declared []parser.External
	if *manifestPath != "" {
		m, err := parser.ParseFile(*manifestPath)
		if err != nil {
			return fmt.Errorf("parse manifest: %w", err)
		}
		declared = flattenExternal(m)
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

	fmt.Fprintf(os.Stderr, "shrike: monitoring (socket=%q, %d declared hosts, status=%q)\n",
		*socket, len(declared), *statusListen)

	err := shrike.Serve(ctx, *socket, mon)

	if statusSrv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = statusSrv.Shutdown(sctx)
		cancel()
	}
	return err
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
