package cli

import (
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
}
