package cli

import (
	"flag"
	"io"
	"log/slog"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// Env is the ambient context handed to every command.
type Env struct {
	Out io.Writer
	Err io.Writer
	In  io.Reader

	Printer   *output.Printer
	Config    *config.Config
	ConfigDir config.Dir
	Verbose   bool
	Log       *slog.Logger

	// Argv is the command line after the program name, verbatim: the global
	// flags before the command name included. Flags is the command's own
	// flag set, parsed. A plan's confirm line is rebuilt from the two by the
	// parser's own rules (confirmLine, ADR 0023 M2.6). Both are nil when a
	// test calls a command's Run directly.
	Argv  []string
	Flags *flag.FlagSet
}
