// Command planck is a thin manual harness for exercising a Planck provider
// against real cloud credentials — the way to test cluster create/delete
// before the farcast CLI wires Planck into `farcast install` (phase 1.3). It
// is NOT the user-facing CLI (that is `farcast`).
//
// Usage:
//
//	planck <validate|create|status|delete> --provider gke --project P --location REGION [--name NAME] [--credentials key.json]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sofmon/farcast/planck"
	_ "github.com/sofmon/farcast/planck/providers"
)

func main() {
	if err := hardenEnvironment(); err != nil {
		fail("planck: cannot harden the process environment: %v\n", err)
		os.Exit(1)
	}
	os.Exit(run(os.Args))
}

// hardenEnvironment closes the two routes by which vendored Google code starts
// programs nobody asked for (ADR 0023 decision 1): a certificate provider for
// a client certificate, and an executable named by an external-account
// credential. This harness drives real GCP with a service-account key and
// links the same Google libraries as farcast, so it turns both off in its own
// process before anything else runs.
//
// It is a copy of hardenEnvironment in farsight/cli/internal/cli/cli.go, its
// twin: two calls, which do not earn a package both could import.
func hardenEnvironment() error {
	if err := os.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false"); err != nil {
		return err
	}
	return os.Unsetenv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES")
}

func run(args []string) int {
	if len(args) < 2 {
		usage()
		return 2
	}
	cmd := args[1]

	fs := flag.NewFlagSet("planck "+cmd, flag.ContinueOnError)
	var providerName, project, location, name, creds string
	fs.StringVar(&providerName, "provider", "gke", "cloud provider")
	fs.StringVar(&project, "project", "", "cloud project / account")
	fs.StringVar(&location, "location", "", "region or zone")
	fs.StringVar(&name, "name", "", "cluster name")
	fs.StringVar(&creds, "credentials", "", "path to a credentials JSON file (optional)")
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}

	cfg := planck.Config{Project: project, Location: location}
	if creds != "" {
		data, err := os.ReadFile(creds)
		if err != nil {
			fail("planck: reading credentials: %v\n", err)
			return 1
		}
		cfg.Credentials = data
	}

	p, err := planck.Open(providerName, cfg)
	if err != nil {
		fail("%v\n", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	ref := planck.ClusterRef{Name: name, Location: location}

	switch cmd {
	case "validate":
		if err := p.Validate(ctx); err != nil {
			fail("%v\n", err)
			return 1
		}
		emit("credentials OK\n")
	case "create":
		c, err := p.CreateCluster(ctx, planck.ClusterSpec{Name: name, Location: location})
		if err != nil {
			fail("%v\n", err)
			return 1
		}
		emit("cluster %q ready at %s (kubeconfig: %d bytes)\n", c.Ref.Name, c.Endpoint, len(c.Kubeconfig))
	case "status":
		st, err := p.ClusterStatus(ctx, ref)
		if err != nil {
			fail("%v\n", err)
			return 1
		}
		emit("%s: %s\n", name, st)
	case "delete":
		if err := p.DeleteCluster(ctx, ref); err != nil {
			fail("%v\n", err)
			return 1
		}
		emit("cluster %q deleted\n", name)
	default:
		usage()
		return 2
	}
	return 0
}

func usage() {
	_, _ = fmt.Fprintln(os.Stderr, "usage: planck <validate|create|status|delete> --provider gke --project P --location REGION [--name NAME] [--credentials key.json]")
}

func emit(format string, a ...any) { _, _ = fmt.Fprintf(os.Stdout, format, a...) }
func fail(format string, a ...any) { _, _ = fmt.Fprintf(os.Stderr, format, a...) }
