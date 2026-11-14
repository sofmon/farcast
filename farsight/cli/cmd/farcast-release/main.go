// Command farcast-release builds a FarCast release: the four components with
// exactly go.mod's toolchain Go, their layers and digest table, and farcast with
// them embedded (ADR 0023 decision 4). Run it as
//
//	GOTOOLCHAIN=<pin> go run ./farsight/cli/cmd/farcast-release <subcommand> [flags]
//
// It is never part of farcast.
package main

import (
	"context"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/sofmon/farcast/farsight/cli/internal/execgate"
	"github.com/sofmon/farcast/farsight/cli/internal/release"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	args := os.Args[1:]
	var code int
	if len(args) > 0 && args[0] == "execsites" {
		code = execgate.Run(ctx, args[1:], os.Environ(), os.Stdout, os.Stderr)
	} else {
		code = release.Run(ctx, args, os.Environ(), os.Stdout, os.Stderr, runtime.Version())
	}
	stop()
	os.Exit(code)
}
