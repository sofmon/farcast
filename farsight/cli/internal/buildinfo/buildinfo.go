// Package buildinfo carries version metadata stamped into the binary at
// build time, with a fallback to the VCS information Go embeds.
package buildinfo

import "runtime/debug"

// These are populated by the linker:
//
//	go build -ldflags "-X .../buildinfo.Version=1.0.0 \
//	                   -X .../buildinfo.Commit=abc1234 \
//	                   -X .../buildinfo.Date=2026-06-02T10:00:00Z"
var (
	Version string
	Commit  string
	Date    string
)

// Info is resolved build metadata.
type Info struct {
	Version string
	Commit  string
	Date    string
}

// Get returns the build metadata, filling any gaps from the embedded VCS
// build info and then from defaults. Commit is shortened to 7 characters.
func Get() Info {
	v, c, d := Version, Commit, Date
	if v == "" || c == "" || d == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if c == "" {
						c = s.Value
					}
				case "vcs.time":
					if d == "" {
						d = s.Value
					}
				}
			}
			if v == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
				v = bi.Main.Version
			}
		}
	}
	if v == "" {
		v = "dev"
	}
	if c == "" {
		c = "none"
	}
	if d == "" {
		d = "unknown"
	}
	if c != "none" && len(c) > 7 {
		c = c[:7]
	}
	return Info{Version: v, Commit: c, Date: d}
}
