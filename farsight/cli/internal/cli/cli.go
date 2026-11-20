// Package cli implements the farcast command router: global-flag parsing,
// subcommand dispatch, and the version/help commands. See
// farsight/cli/README.md for the design.
package cli

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// Main is the CLI entry point. args is the full process argument list
// (program name at index 0). It returns the process exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if err := hardenEnvironment(); err != nil {
		fprintf(stderr, "farcast: cannot harden the process environment: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, args, stdin, stdout, stderr)
}

// hardenEnvironment removes what the environment could do to farcast's own
// network calls, process-wide, before anything else runs.
//
// First, three variables that would decide what a call trusts or prints
// (ADR 0023 M2.3, with the first in-process cluster call):
//   - GOOGLE_SDK_GO_LOGGING_LEVEL unset: a Google client library built with no
//     logger of its own, as the registry and storage token sources are, reads
//     it and logs request and response bodies (a signed assertion, an access
//     token) to stderr.
//   - SSL_CERT_FILE and SSL_CERT_DIR unset: they replace the system roots that
//     *.gke.goog, and the bearer token sent to it, are trusted on. On Linux
//     they always do; on macOS and Windows a GODEBUG of
//     x509sslcertoverrideplatform=1 makes them. The roots are loaded at their
//     first use, after this, so unsetting them here is enough.
//
// Then the two routes by which vendored Google code starts programs nobody
// asked for (ADR 0023 decision 1). GOOGLE_API_USE_CLIENT_CERTIFICATE=false
// keeps the Google client libraries from running a certificate provider to
// present a client certificate. GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES
// unset keeps an external-account credential file from naming an executable
// to run for a token. The cost: an organization that enforces
// certificate-based access refuses this CLI, and an operator whose machine
// trusts a private root through SSL_CERT_FILE (a corporate proxy's) does not
// reach Google through it.
//
// It runs here and not in a package init, so the unit tests, which call run,
// keep their environment. The planck harness keeps its own copy
// (planck/cmd/planck).
//
// One setting it cannot undo: a GODEBUG holding http2debug=1 or http2debug=2
// has already turned on Go's HTTP/2 logging, the bearer token included, when
// this runs. run
// refuses it for every command, with the kind unsafe_environment, once the
// printer exists and before anything is read (unsafeEnvironment, ADR 0023
// M2.8's step 0); an error here is printed with no kind, before -o is parsed.
func hardenEnvironment() error {
	for _, k := range []string{"GOOGLE_SDK_GO_LOGGING_LEVEL", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if err := os.Unsetenv(k); err != nil {
			return err
		}
	}
	if err := os.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false"); err != nil {
		return err
	}
	return os.Unsetenv("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES")
}

// unsafeEnvironment is kube.UnsafeEnvironment, a seam for the parent-side
// test (TestUnsafeEnvironmentIsRefusedBeforeAnythingIsRead), which makes it
// answer the refusal without GODEBUG. Its default is the real one, in the
// tests too.
var unsafeEnvironment = kube.UnsafeEnvironment

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	reg := defaultRegistry()

	var opts globalOpts
	gfs := flag.NewFlagSet("farcast", flag.ContinueOnError)
	gfs.SetOutput(io.Discard)
	gfs.Usage = func() {}
	opts.registerRoot(gfs)
	if err := gfs.Parse(args[1:]); err != nil {
		fprintf(stderr, "farcast: %v\nRun 'farcast help' for usage.\n", err)
		return 2
	}
	rest := gfs.Args()

	if opts.version {
		rest = []string{"version"}
		opts.help = false
	}

	if len(rest) == 0 {
		if opts.help {
			renderRootHelp(stdout, reg)
			return 0
		}
		renderRootHelp(stderr, reg)
		return 2
	}

	name := rest[0]
	cmd, ok := reg.Lookup(name)
	if !ok {
		fprintf(stderr, "farcast: unknown command %q\nRun 'farcast help' for usage.\n", name)
		return 2
	}

	// A global --help placed before the command shows that command's help.
	if opts.help && name != "help" {
		renderCommandHelp(stdout, cmd)
		return 0
	}

	cfs := flag.NewFlagSet(name, flag.ContinueOnError)
	cfs.SetOutput(io.Discard)
	cfs.Usage = func() {}
	opts.registerCommon(cfs)
	cmd.SetFlags(cfs)
	if g, ok := cmd.(subFlagged); ok {
		// A two-level command's flags belong to its subcommand; without them
		// here, parsing the line rejects every flag `storage` accepts.
		g.SetSubFlags(cfs, rest[1:])
	}
	cmdArgs, err := parseInterspersed(cfs, rest[1:])
	if err != nil {
		fprintf(stderr, "farcast %s: %v\nRun 'farcast help %s' for usage.\n", name, err, name)
		return 2
	}
	if opts.help {
		renderCommandHelp(stdout, cmd)
		return 0
	}

	mode, err := output.ParseMode(opts.output)
	if err != nil {
		fprintf(stderr, "farcast: %v\n", err)
		return 2
	}
	printer := &output.Printer{Mode: mode, Out: stdout, Err: stderr}

	// No command runs while GODEBUG has turned on Go's HTTP/2 logging, which
	// prints every request header, the bearer included, to stderr: not only
	// the cluster client refuses it, but every Google client farcast uses
	// would print it too. Nothing is read before this, so no key is loaded
	// and no token minted.
	if err := unsafeEnvironment(); err != nil {
		printer.PrintError(classified(err), exitCodeOf(err))
		return 1
	}

	dir, err := config.Resolve(opts.config)
	if err != nil {
		printer.PrintError(err, 1)
		return 1
	}
	cfg, err := config.Load(dir)
	if err != nil {
		printer.PrintError(err, 1)
		return 1
	}

	logOut := io.Writer(io.Discard)
	if opts.verbose {
		logOut = stderr
	}
	logger := slog.New(slog.NewTextHandler(logOut, &slog.HandlerOptions{Level: slog.LevelDebug}))

	env := &Env{
		Out:       stdout,
		Err:       stderr,
		In:        stdin,
		Printer:   printer,
		Config:    cfg,
		ConfigDir: dir,
		Verbose:   opts.verbose,
		Log:       logger,
		Argv:      append([]string(nil), args[1:]...),
		Flags:     cfs,
	}

	err = cmd.Run(ctx, env, cmdArgs)
	code := exitCodeOf(err)
	if _, usage := errors.AsType[*usageError](err); usage {
		fprintf(stderr, "farcast %s: %v\nRun 'farcast help %s' for usage.\n", name, err, name)
	} else if err != nil {
		// The JSON envelope carries the same code the process exits with, so
		// a script reading either reads one answer — and the error's kind,
		// so a reader can tell failures apart without parsing prose.
		printer.PrintError(classified(err), code)
	}
	return code
}

// parseInterspersed parses flags that may appear before, after, or between
// positional arguments, returning the positionals. The standard flag package
// stops at the first non-flag token, so we resume parsing after each
// positional — letting "release prod --yes" work as well as "release --yes
// prod". Flag values persist across the repeated Parse calls (they are set
// through the registered pointers).
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positionals, nil
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}
}

func defaultRegistry() *Registry {
	reg := NewRegistry()

	reg.Register(versionCommand{})
	help := &helpCommand{}
	reg.Register(help)
	help.reg = reg
	reg.Register(newInstancesCommand())

	reg.Register(&installCommand{})
	reg.Register(&releaseCommand{})
	reg.Register(newConnectCommand())
	reg.Register(newRedeployCommand())
	reg.Register(&runCommand{})
	reg.Register(&psCommand{})
	reg.Register(&logsCommand{})
	reg.Register(&costsCommand{})
	reg.Register(&usageCommand{})
	reg.Register(newWorldCommand())
	reg.Register(&buildCommand{})
	reg.Register(&toolchainCommand{})
	reg.Register(newStorageCommand())
	reg.Register(newSecretCommand())
	reg.Register(newKeeperCommand())
	reg.Register(newKernelCommand())
	reg.Register(newReaderCommand())
	reg.Register(newGitCredentialCommand())
	reg.Register(newStub("chat", "Terminal AI chat through AllThing", "6.2"))

	return reg
}

// globalOpts holds the global flag values. The same struct backs both the
// root flag set and each command's flag set, so a global flag is accepted on
// either side of the command name.
type globalOpts struct {
	output  string
	verbose bool
	config  string
	help    bool
	version bool
}

const (
	outputUsage  = "result format: human or json"
	verboseUsage = "enable diagnostic logging on stderr"
	configUsage  = "override the config directory"
	helpUsage    = "show help"
	versionUsage = "show version information"
)

func (o *globalOpts) registerRoot(fs *flag.FlagSet) {
	fs.StringVar(&o.output, "output", "human", outputUsage)
	fs.StringVar(&o.output, "o", "human", outputUsage)
	fs.BoolVar(&o.verbose, "verbose", false, verboseUsage)
	fs.BoolVar(&o.verbose, "v", false, verboseUsage)
	fs.StringVar(&o.config, "config", "", configUsage)
	fs.BoolVar(&o.help, "help", false, helpUsage)
	fs.BoolVar(&o.help, "h", false, helpUsage)
	fs.BoolVar(&o.version, "version", false, versionUsage)
}

// registerCommon registers the global flags on a command's flag set, using the
// already-parsed root values as defaults so a value set before the command is
// not clobbered when it is not repeated after the command.
func (o *globalOpts) registerCommon(fs *flag.FlagSet) {
	fs.StringVar(&o.output, "output", o.output, outputUsage)
	fs.StringVar(&o.output, "o", o.output, outputUsage)
	fs.BoolVar(&o.verbose, "verbose", o.verbose, verboseUsage)
	fs.BoolVar(&o.verbose, "v", o.verbose, verboseUsage)
	fs.StringVar(&o.config, "config", o.config, configUsage)
	fs.BoolVar(&o.help, "help", false, helpUsage)
	fs.BoolVar(&o.help, "h", false, helpUsage)
}
