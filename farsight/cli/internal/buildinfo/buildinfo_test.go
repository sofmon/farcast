package buildinfo

import (
	"errors"
	"runtime/debug"
	"testing"
)

func TestGetDefaultsNonEmpty(t *testing.T) {
	info := Get()
	if info.Version == "" || info.Commit == "" || info.Date == "" {
		t.Errorf("Get returned empty field(s): %+v", info)
	}
}

func TestGetShortensCommit(t *testing.T) {
	old := Commit
	defer func() { Commit = old }()

	Commit = "abcdef1234567890abcdef"
	if got := Get().Commit; got != "abcdef1" {
		t.Errorf("Commit = %q, want abcdef1", got)
	}
}

// stamp sets the three -X variables for one test and restores them after.
func stamp(t *testing.T, v, c, d string) {
	t.Helper()
	ov, oc, od := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = ov, oc, od })
	Version, Commit, Date = v, c, d
}

const fullRevision = "006e479afcf0f6f2a3a1b8a4c4f1b9c3d2e1f0a9"

func vcsInfo(version string, settings ...debug.BuildSetting) *debug.BuildInfo {
	return &debug.BuildInfo{Main: debug.Module{Path: "github.com/sofmon/farcast", Version: version}, Settings: settings}
}

func TestCheckRelease(t *testing.T) {
	for _, tc := range []struct {
		info Info
		ok   bool
	}{
		{Info{Version: ""}, false},
		{Info{Version: "dev"}, false},
		{Info{Version: "(devel)"}, false},
		{Info{Version: "unknown"}, false},
		{Info{Version: "v0.0.0-20261113155828-006e479afcf0+dirty"}, false},
		{Info{Version: "v0.1.0", Modified: true}, false},
		{Info{Version: "v0.0.0-20261113155828-006e479afcf0"}, true},
		{Info{Version: "v0.1.0"}, true},
	} {
		err := tc.info.CheckRelease()
		if tc.ok {
			if err != nil {
				t.Errorf("CheckRelease(%+v) = %v, want a release", tc.info, err)
			}
			continue
		}
		if !errors.Is(err, ErrNotRelease) {
			t.Errorf("CheckRelease(%+v) = %v, want an error wrapping ErrNotRelease", tc.info, err)
			continue
		}
		var nr *NotReleaseError
		if !errors.As(err, &nr) || nr.Reason == "" || nr.Version != tc.info.Version {
			t.Errorf("CheckRelease(%+v) = %#v, want a NotReleaseError naming the version and a reason", tc.info, err)
		}
	}
}

func TestFromBuildInfoReadsModified(t *testing.T) {
	stamp(t, "", "", "")
	for _, tc := range []struct {
		value string
		want  bool
	}{{"true", true}, {"false", false}} {
		info := fromBuildInfo(vcsInfo("v0.1.0",
			debug.BuildSetting{Key: "vcs.revision", Value: fullRevision},
			debug.BuildSetting{Key: "vcs.modified", Value: tc.value},
		), true)
		if info.Modified != tc.want {
			t.Errorf("vcs.modified=%s read as Modified=%v", tc.value, info.Modified)
		}
		if info.Version != "v0.1.0" {
			t.Errorf("Version = %q, want the build info's", info.Version)
		}
	}
	// No build info at all: nothing is modified, and the defaults stand.
	if info := fromBuildInfo(nil, false); info.Modified || info.Version != "dev" || info.Revision != "" {
		t.Errorf("no build info gave %+v", info)
	}
}

func TestRevisionIsTheFullVCSRevisionOnly(t *testing.T) {
	stamp(t, "", "", "")
	info := fromBuildInfo(vcsInfo("v0.1.0", debug.BuildSetting{Key: "vcs.revision", Value: fullRevision}), true)
	if info.Revision != fullRevision {
		t.Errorf("Revision = %q, want the full %q", info.Revision, fullRevision)
	}
	if info.Commit != fullRevision[:7] {
		t.Errorf("Commit = %q, want the 7-character %q", info.Commit, fullRevision[:7])
	}

	// A version and commit set with -X, and no VCS stamp: the commit is
	// printed, and Revision stays empty.
	stamp(t, "v9.9.9", "abcdef1234567", "2026-11-13T00:00:00Z")
	info = fromBuildInfo(vcsInfo("(devel)"), true)
	if info.Revision != "" {
		t.Errorf("Revision = %q from -X alone; it comes from the VCS stamp only", info.Revision)
	}
	if info.Commit != "abcdef1" || info.Version != "v9.9.9" {
		t.Errorf("the -X stamp was not kept: %+v", info)
	}
}
