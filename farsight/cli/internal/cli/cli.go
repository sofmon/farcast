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
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// Main is the CLI entry point. args is the full process argument list
// (program name at index 0). It returns the process exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, args, stdin, stdout, stderr)
}

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
	if err := cfs.Parse(rest[1:]); err != nil {
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

	dir, err := config.Resolve(opts.config)
	if err != nil {
		printer.PrintError(err.Error(), 1)
		return 1
	}
	cfg, err := config.Load(dir)
	if err != nil {
		printer.PrintError(err.Error(), 1)
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
	}

	if err := cmd.Run(ctx, env, cfs.Args()); err != nil {
		if _, ok := errors.AsType[*usageError](err); ok {
			fprintf(stderr, "farcast %s: %v\nRun 'farcast help %s' for usage.\n", name, err, name)
			return 2
		}
		printer.PrintError(err.Error(), 1)
		return 1
	}
	return 0
}

func defaultRegistry() *Registry {
	reg := NewRegistry()

	reg.Register(versionCommand{})
	help := &helpCommand{}
	reg.Register(help)
	help.reg = reg

	reg.Register(&installCommand{})
	reg.Register(newStub("release", "Destroy an instance and clean up local state", "1.4"))
	reg.Register(newStub("connect", "Open a FatLine tunnel to an instance", "2.3"))
	reg.Register(newStub("run", "Deploy a Git repository to an instance", "4.3"))
	reg.Register(newStub("ps", "List running applications", "4.3"))
	reg.Register(newStub("logs", "Stream an application's logs", "4.3"))
	reg.Register(newStub("costs", "Show spending and distance to the cost limit", "4.3"))
	reg.Register(newStub("storage", "Manage instance storage (ls, cp)", "3.3"))
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
