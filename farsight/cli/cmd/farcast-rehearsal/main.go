// Command farcast-rehearsal runs the Connected view's no-cost rehearsal: an
// instance on 127.0.0.1 — a real FatLine, Shrike and two keyholder replicas,
// and fake kubectl, gke-gcloud-auth-plugin and gcloud — for the FarCast app
// to read from Finder before it reads a live one. See
// docs/runbooks/phase-7-connected-view.md.
//
// It is never part of farcast. Build it as ./bin/farcast-rehearsal.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/rehearsal"
)

func main() {
	// Linked as kubectl, gke-gcloud-auth-plugin or gcloud, this binary is
	// that fake tool, and this is the only place a tool reads the process's
	// own environment.
	if code, ok := rehearsal.ToolMain(os.Args[0], os.Args[1:], os.Environ(), os.Stdout, os.Stderr); ok {
		os.Exit(code)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usage = `Usage:
  farcast-rehearsal [--dir <dir>] [--farcast <path>] [--scenario <name>]
      Start a rehearsal, or restart the stopped one in <dir>, and run it until Ctrl-C.
      <dir> is new, empty, or one a stopped harness left; without it, a temporary one.
  farcast-rehearsal scenario --dir <dir> <name>
      Change what the instance shows from its next read. The scenarios:
      ` + "%s" + `
  farcast-rehearsal summarize < world.json
      Print only the shape of a world document or an error envelope: no name,
      host, repository, commit, replica, message, title or time of day.
`

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, usage, strings.Join(rehearsal.Scenarios(), ", "))
}

// run is the command, with its arguments after the program name. It returns
// the exit code: 2 for a command line it refuses, 1 for a failure.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "scenario":
			return runScenario(args[1:], stdout, stderr)
		case "summarize":
			if len(args) > 1 {
				_, _ = fmt.Fprintln(stderr, "farcast-rehearsal summarize takes no arguments; it reads the document on stdin")
				return 2
			}
			if err := rehearsal.Summarize(stdin, stdout); err != nil {
				_, _ = fmt.Fprintf(stderr, "farcast-rehearsal summarize: %v\n", err)
				return 1
			}
			return 0
		case "help":
			printUsage(stdout)
			return 0
		}
	}
	return runStart(ctx, args, stdout, stderr)
}

func runStart(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("farcast-rehearsal", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "the state directory: new, empty, or a stopped rehearsal's")
	farcast := fs.String("farcast", "", "the farcast the app will run, to check its commit")
	scenario := fs.String("scenario", "", "what the instance shows (a new rehearsal only)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(stdout)
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "farcast-rehearsal: %v\n", err)
		printUsage(stderr)
		return 2
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "farcast-rehearsal: unknown command %q\n", fs.Arg(0))
		printUsage(stderr)
		return 2
	}
	if *scenario != "" && !rehearsal.ValidScenario(*scenario) {
		_, _ = fmt.Fprintf(stderr, "farcast-rehearsal: unknown scenario %q; the scenarios are %s\n",
			*scenario, strings.Join(rehearsal.Scenarios(), ", "))
		return 2
	}
	commit := buildinfo.Get().Commit

	// The farcast given is run by its absolute path as given, and printed
	// resolved, as every path the settings text holds is.
	farcastAbs, farcastPath := "", ""
	if *farcast != "" {
		var err error
		farcastAbs, err = filepath.Abs(*farcast)
		if err == nil {
			farcastPath, err = filepath.EvalSymlinks(farcastAbs)
		}
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "farcast-rehearsal: --farcast %s: %v\n", *farcast, err)
			return 1
		}
	}

	rig, err := rehearsal.Start(ctx, rehearsal.Options{Dir: *dir, Scenario: *scenario, Farcast: farcastPath, Log: stderr})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "farcast-rehearsal: %v\n", err)
		return 1
	}

	farcastRow := "your ./bin/farcast built at commit " + commit
	if farcastPath != "" {
		farcastRow = farcastPath
		if version, got, err := farcastStamp(ctx, farcastAbs, rig.Dir, rig.ConfigDir); err != nil {
			_, _ = fmt.Fprintf(stderr, "warning: %s did not report its commit (%v); the app's Check will say why\n", farcastPath, err)
		} else if !sameCommit(got, commit) {
			_, _ = fmt.Fprintf(stderr, "warning: %s is farcast %s at commit %s, and this harness is commit %s; build both, and the app, from one clean commit\n",
				farcastPath, version, got, commit)
		}
	}

	_, _ = fmt.Fprintf(stdout, "FarCast rehearsal — commit %s. Everything here listens on 127.0.0.1; nothing reaches any other address.\n\n", commit)
	_, _ = io.WriteString(stdout, rig.SettingsText(farcastRow))

	<-ctx.Done()
	if err := rig.Close(); err != nil {
		_, _ = fmt.Fprintf(stderr, "farcast-rehearsal: stopping: %v\n", err)
	}
	_, _ = fmt.Fprintf(stdout, "stopped; remove %s when done\n", rehearsal.ShellQuote(rig.Dir))
	return 0
}

// farcastVersionArgs is the app's own version argv (testdata/app/argv.json)
// with <config> substituted: --config is given so farcast reads no
// configuration but the rehearsal's own, never $FARCAST_CONFIG_HOME or the
// operator's real directory.
func farcastVersionArgs(configDir string) []string {
	return []string{"--config", configDir, "-o", "json", "version"}
}

// farcastStamp runs farcast's version command with an environment of only
// HOME (the rehearsal's directory) and a system PATH, stdin closed, and reads
// the version and commit it reports.
func farcastStamp(ctx context.Context, path, home, configDir string) (version, commit string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, farcastVersionArgs(configDir)...)
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", "", err
	}
	var v struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		return "", "", fmt.Errorf("its version output is not the JSON farcast prints: %w", err)
	}
	return v.Version, v.Commit, nil
}

// sameCommit compares two commits by their first seven hex digits, as the
// app does.
func sameCommit(a, b string) bool {
	short := func(c string) string {
		c = strings.ToLower(strings.TrimSpace(c))
		if len(c) < 7 || strings.Trim(c, "0123456789abcdef") != "" {
			return ""
		}
		return c[:7]
	}
	sa, sb := short(a), short(b)
	return sa != "" && sa == sb
}

func runScenario(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scenario", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("dir", "", "the rehearsal's directory")
	var names []string
	for {
		if err := fs.Parse(args); err != nil {
			_, _ = fmt.Fprintf(stderr, "farcast-rehearsal scenario: %v\n", err)
			printUsage(stderr)
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		names = append(names, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if *dir == "" || len(names) != 1 {
		_, _ = fmt.Fprintln(stderr, "farcast-rehearsal scenario takes --dir <dir> and one scenario name")
		printUsage(stderr)
		return 2
	}
	if !rehearsal.ValidScenario(names[0]) {
		_, _ = fmt.Fprintf(stderr, "farcast-rehearsal scenario: unknown scenario %q; the scenarios are %s\n",
			names[0], strings.Join(rehearsal.Scenarios(), ", "))
		return 2
	}
	if err := rehearsal.SetScenario(*dir, names[0]); err != nil {
		_, _ = fmt.Fprintf(stderr, "farcast-rehearsal scenario: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "scenario %s: the instance shows it from its next read\n", names[0])
	return 0
}
