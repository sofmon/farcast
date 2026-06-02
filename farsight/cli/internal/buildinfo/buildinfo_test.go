package buildinfo

import "testing"

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
