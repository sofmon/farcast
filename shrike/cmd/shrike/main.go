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
	"bytes"
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

	// The policy is a mounted ConfigMap that arrives after this process starts
	// and changes while it runs — the sidecar is deployed by `farcast connect`,
	// long before any application exists to declare anything. Watching it is
	// what keeps the picture's contract true; FatLine has watched its copy of
	// the same document since ADR 0013 decision 5.
	if *policyPath != "" {
		go watchPolicy(ctx, *policyPath, policyPollInterval, mon)
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

// policyPollInterval is how often the mounted policy is re-read. The kubelet
// propagates a ConfigMap change on its own schedule (tens of seconds), so
// polling faster buys nothing.
const policyPollInterval = 10 * time.Second

// watchPolicy re-reads the declared contract when the mounted document changes.
//
// It mirrors FatLine's watcher deliberately, including its failure behaviour:
// an unreadable document is complained about and the previous contract kept,
// and `last` is not updated so a file that is still broken on the next tick is
// complained about again rather than falling silent.
func watchPolicy(ctx context.Context, path string, every time.Duration, mon *shrike.Monitor) {
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
		doc, perr := policy.Parse(data)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "shrike: refusing an unreadable egress policy, keeping the previous one: %v\n", perr)
			continue
		}
		last = data
		var hosts []parser.External
		for _, h := range doc.ByTenant() {
			hosts = append(hosts, h...)
		}
		mon.ReloadDeclared(hosts)
		fmt.Fprintf(os.Stderr, "shrike: declared contract reloaded (%d application(s), %d host(s))\n",
			len(doc.Apps), len(hosts))
	}
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
