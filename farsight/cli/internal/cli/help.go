package cli

import (
	"context"
	"flag"
	"io"
)

type helpCommand struct {
	reg *Registry
}

func (h *helpCommand) Name() string     { return "help" }
func (h *helpCommand) Synopsis() string { return "Show help for farcast or a command" }

func (h *helpCommand) Usage() string {
	return "Usage: farcast help [command]\n\nShow general help, or detailed help for a specific command."
}

func (h *helpCommand) SetFlags(*flag.FlagSet) {}

func (h *helpCommand) Run(_ context.Context, env *Env, args []string) error {
	if len(args) == 0 {
		renderRootHelp(env.Out, h.reg)
		return nil
	}
	cmd, ok := h.reg.Lookup(args[0])
	if !ok {
		return usagef("unknown command %q", args[0])
	}
	renderCommandHelp(env.Out, cmd)
	return nil
}

func renderRootHelp(w io.Writer, reg *Registry) {
	fprintln(w, "farcast — the operator CLI for FarCast")
	fprintln(w)
	fprintln(w, "Usage:")
	fprintln(w, "  farcast [global flags] <command> [command flags] [arguments]")
	fprintln(w)
	fprintln(w, "Commands:")
	width := 0
	for _, c := range reg.Commands() {
		if n := len(c.Name()); n > width {
			width = n
		}
	}
	for _, c := range reg.Commands() {
		fprintf(w, "  %-*s   %s\n", width, c.Name(), c.Synopsis())
	}
	fprintln(w)
	fprintln(w, "Global flags:")
	fprintln(w, "  -o, --output {human|json}   Result format (default human)")
	fprintln(w, "  -v, --verbose               Diagnostic logging on stderr")
	fprintln(w, "      --config <dir>          Override the config directory")
	fprintln(w, "  -h, --help                  Show this help")
	fprintln(w)
	fprintln(w, `Run "farcast help <command>" for details on a command.`)
}

func renderCommandHelp(w io.Writer, c Command) {
	fprintln(w, c.Usage())
}
