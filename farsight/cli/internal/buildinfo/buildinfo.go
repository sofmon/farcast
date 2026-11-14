// Package buildinfo carries version metadata stamped into the binary at
// build time, with a fallback to the VCS information Go embeds.
package buildinfo

import (
	"errors"
	"runtime/debug"
	"strings"
)

// These are populated by the linker:
//
//	go build -ldflags "-X .../buildinfo.Version=1.0.0 \
//	                   -X .../buildinfo.Commit=abc1234 \
//	                   -X .../buildinfo.Date=2026-06-02T10:00:00Z"
//
// A release is not built that way: farcast-release stamps farcast with
// -buildvcs=true and no -X, so Version is Go's own (an exact tag, or a
// pseudo-version) and Revision and Modified come from the same stamp (ADR 0023
// M1).
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

	// Revision is the full vcs.revision from the build info. It is never the
	// -X Commit: a version or commit set with -X and no VCS stamp leaves it
	// empty, and a farcast that carries components then refuses to push them,
	// because nothing binds those components to the commit it was built at.
	Revision string

	// Modified is vcs.modified=true in the build info: the tree had
	// uncommitted changes when this binary was built.
	Modified bool
}

// ErrNotRelease is wrapped by every refusal CheckRelease returns.
var ErrNotRelease = errors.New("buildinfo: not a release build")

// NotReleaseError is CheckRelease's refusal. Reason says why, in words an
// operator can act on; it wraps ErrNotRelease.
type NotReleaseError struct {
	Version string
	Reason  string
}

func (e *NotReleaseError) Error() string {
	return "buildinfo: version " + e.Version + " is not a release build (" + e.Reason + ")"
}

func (e *NotReleaseError) Unwrap() error { return ErrNotRelease }

// CheckRelease is nil when Version can tag FarCast's own images. Otherwise it
// is a *NotReleaseError wrapping ErrNotRelease, naming the reason: Version is
// "", "dev", "(devel)" or "unknown"; Version contains "+" (Go's "+dirty", or
// any build metadata); or Modified.
//
// It reads the raw Version, never the tag a version is folded into: "+dirty"
// becomes "-dirty" in a tag, and a check on the tag would pass it.
func (i Info) CheckRelease() error {
	var reason string
	switch {
	case i.Version == "", i.Version == "dev", i.Version == "(devel)", i.Version == "unknown":
		reason = "a build with no version stamped"
	case strings.Contains(i.Version, "+"):
		reason = "the version carries build metadata, such as +dirty from a tree with uncommitted changes"
	case i.Modified:
		reason = "built from a tree with uncommitted changes"
	default:
		return nil
	}
	return &NotReleaseError{Version: i.Version, Reason: reason}
}

// Get returns the build metadata, filling any gaps from the embedded VCS
// build info and then from defaults. Commit is shortened to 7 characters;
// Revision is kept whole.
func Get() Info {
	bi, ok := debug.ReadBuildInfo()
	return fromBuildInfo(bi, ok)
}

// fromBuildInfo is Get's body, with the build info passed in so a test can
// give it any.
func fromBuildInfo(bi *debug.BuildInfo, ok bool) Info {
	v, c, d := Version, Commit, Date
	var revision string
	var modified bool
	if ok && bi != nil {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
				if c == "" {
					c = s.Value
				}
			case "vcs.time":
				if d == "" {
					d = s.Value
				}
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
		if v == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			v = bi.Main.Version
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
	return Info{Version: v, Commit: c, Date: d, Revision: revision, Modified: modified}
}
