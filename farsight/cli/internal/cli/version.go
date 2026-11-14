package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"runtime"
	"sort"

	"github.com/sofmon/farcast/farsight/cli/internal/buildinfo"
	"github.com/sofmon/farcast/farsight/cli/internal/components"
	"github.com/sofmon/farcast/farsight/cli/internal/image"
)

type versionCommand struct {
	// info is the build stamp; nil reads the binary's own. A seam so the
	// version vector does not change with the build that checks it.
	info func() buildinfo.Info
	// carried is what this farcast carries (ADR 0023 decision 4); nil reads
	// the components package. A seam so an untagged test binary, which carries
	// nothing, can print what a release prints.
	carried func() (embedded bool, base string, arts []components.Artifact)
}

func (versionCommand) Name() string     { return "version" }
func (versionCommand) Synopsis() string { return "Print version information" }

func (versionCommand) Usage() string {
	return "Usage: farcast version\n\nPrint version, build, and runtime information, and the Go version and digests of\neach component this farcast carries."
}

func (versionCommand) SetFlags(*flag.FlagSet) {}

func (c versionCommand) Run(_ context.Context, env *Env, _ []string) error {
	get := c.info
	if get == nil {
		get = buildinfo.Get
	}
	carried := c.carried
	if carried == nil {
		carried = func() (bool, string, []components.Artifact) {
			return components.Embedded(), components.Base(), components.Artifacts()
		}
	}
	info := get()
	embedded, base, arts := carried()
	res := versionResult{
		Version:    info.Version,
		Commit:     info.Commit,
		Built:      info.Date,
		Go:         runtime.Version(),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Embedded:   embedded,
		Base:       base,
		Components: []versionComponent{},
	}
	for _, a := range arts {
		res.Components = append(res.Components, versionComponent{
			Name: a.Name, Go: a.GoVersion, Manifest: a.Manifest, Config: a.Config,
			Layer: a.Layer, DiffID: a.DiffID, BinarySHA256: a.BinarySHA256,
		})
	}
	sort.Slice(res.Components, func(i, j int) bool { return res.Components[i].Name < res.Components[j].Name })
	return env.Printer.Print(res)
}

type versionResult struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Built   string `json:"built"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`

	// Embedded, Base and Components are what this farcast carries: each
	// component's Go version and digests, so an operator can see which Go a
	// release froze into the components and compare a rebuild against them
	// (ADR 0023 decisions 4 and 6). A source build carries none.
	Embedded   bool               `json:"embedded"`
	Base       string             `json:"base"`
	Components []versionComponent `json:"components"`
}

type versionComponent struct {
	Name         string `json:"name"`
	Go           string `json:"go"`
	Manifest     string `json:"manifest"`
	Config       string `json:"config"`
	Layer        string `json:"layer"`
	DiffID       string `json:"diff_id"`
	BinarySHA256 string `json:"binary_sha256"`
}

func (r versionResult) Human(w io.Writer) error {
	if _, err := fmt.Fprintf(w,
		"farcast %s\n  commit:   %s\n  built:    %s\n  go:       %s\n  os/arch:  %s/%s\n",
		r.Version, r.Commit, r.Built, r.Go, r.OS, r.Arch); err != nil {
		return err
	}
	if !r.Embedded || len(r.Components) == 0 {
		_, err := fmt.Fprintln(w, "  components: none carried (a source build: a missing image is compiled from a farcast checkout)")
		return err
	}
	if _, err := fmt.Fprintf(w, "  components (%s/%s, on %s):\n",
		image.ComponentPlatform.OS, image.ComponentPlatform.Architecture, r.Base); err != nil {
		return err
	}
	for _, c := range r.Components {
		if _, err := fmt.Fprintf(w, "    %-11s  %s  %s\n", c.Name, c.Go, c.Manifest); err != nil {
			return err
		}
	}
	return nil
}
