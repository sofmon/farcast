// Command farcast is the operator CLI for FarCast — the command line face of
// FarSight. See farsight/cli/README.md for the specification.
package main

import (
	"os"

	"github.com/sofmon/farcast/farsight/cli/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args, os.Stdin, os.Stdout, os.Stderr))
}
