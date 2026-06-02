package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"runtime"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
)

type versionCommand struct{}

func (versionCommand) Name() string     { return "version" }
func (versionCommand) Synopsis() string { return "Print version information" }

func (versionCommand) Usage() string {
	return "Usage: farcast version\n\nPrint version, build, and runtime information."
}

func (versionCommand) SetFlags(*flag.FlagSet) {}

func (versionCommand) Run(_ context.Context, env *Env, _ []string) error {
	info := buildinfo.Get()
	return env.Printer.Print(versionResult{
		Version: info.Version,
		Commit:  info.Commit,
		Built:   info.Date,
		Go:      runtime.Version(),
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	})
}

type versionResult struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Built   string `json:"built"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

func (r versionResult) Human(w io.Writer) error {
	_, err := fmt.Fprintf(w,
		"farcast %s\n  commit:   %s\n  built:    %s\n  go:       %s\n  os/arch:  %s/%s\n",
		r.Version, r.Commit, r.Built, r.Go, r.OS, r.Arch)
	return err
}
