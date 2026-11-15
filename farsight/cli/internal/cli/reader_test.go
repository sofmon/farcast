package cli

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// The reader's account ID is "farcast-reader-" and the first 8 hex of the
// instance name's SHA-256: 23 characters for every name, a 32-character one
// included, inside Google's rule for an account ID.
func TestReaderNameIsTheHashedInstanceName(t *testing.T) {
	googleAccountID := regexp.MustCompile(`^[a-z]([-a-z0-9]*[a-z0-9])$`)
	seen := map[string]string{}
	for _, name := range []string{"atlas", "prod", "a", strings.Repeat("x", maxInstanceName), "farcast-reader-atlas"} {
		got := readerName(name)
		want := "farcast-reader-" + fmt.Sprintf("%x", sha256.Sum256([]byte(name)))[:8]
		if got != want {
			t.Errorf("readerName(%q) = %q, want %q", name, got, want)
		}
		if len(got) != 23 || !googleAccountID.MatchString(got) {
			t.Errorf("readerName(%q) = %q (%d characters) is not a Google account ID of 6 to 30", name, got, len(got))
		}
		if len(name) > 8 && strings.Contains(got, name) {
			t.Errorf("readerName(%q) = %q embeds the name", name, got)
		}
		if other, dup := seen[got]; dup {
			t.Errorf("readerName(%q) = readerName(%q) = %q", name, other, got)
		}
		seen[got] = name
	}
	if got, want := readerEmail("atlas", "proj-test1"), readerName("atlas")+"@proj-test1.iam.gserviceaccount.com"; got != want {
		t.Errorf("readerEmail = %q, want %q", got, want)
	}
}

// checkedReader makes exactly four checks, and everything it returns is
// built from checked values: the name passes validateInstanceName, the
// project has Google's project-ID shape, the email is rebuilt from those two
// (the recorded one is never read), and a stored key id is 40 lowercase hex.
func TestCheckedReaderReturnsOnlyCheckedValues(t *testing.T) {
	const keyID = "c7b74879da78e4cdcbe7e1bf5e129375c0bfa8d0"
	record := func(name, project string, r *config.Reader) *config.InstanceMetadata {
		return &config.InstanceMetadata{Name: name, Project: project, Reader: r}
	}
	unsafe := &config.Reader{Email: "x@y$(id).iam.gserviceaccount.com", KeyID: keyID}

	// Good records, the recorded email ignored.
	for _, row := range []struct {
		name string
		meta *config.InstanceMetadata
		key  string
	}{
		{"a recorded reader", record("atlas", "proj-test1", &config.Reader{Email: readerEmail("atlas", "proj-test1"), KeyID: keyID}), keyID},
		{"a reader not yet uploaded", record("atlas", "proj-test1", &config.Reader{Email: readerEmail("atlas", "proj-test1")}), ""},
		{"no reader", record("atlas", "proj-test1", nil), ""},
		{"an unsafe recorded email", record("atlas", "proj-test1", unsafe), keyID},
		{"the longest project ID", record("atlas", "p"+strings.Repeat("0", 28)+"z", nil), ""},
	} {
		project, email, gotKey, err := checkedReader(row.meta)
		if err != nil {
			t.Errorf("%s: %v", row.name, err)
			continue
		}
		if project != row.meta.Project || email != readerEmail(row.meta.Name, row.meta.Project) || gotKey != row.key {
			t.Errorf("%s: %q, %q, %q", row.name, project, email, gotKey)
		}
	}

	// Each check refuses on its own, naming the field and quoting the value.
	for _, row := range []struct {
		name  string
		meta  *config.InstanceMetadata
		field string
		value string
	}{
		{"a quote in the name", record("atlas'", "proj-test1", nil), "name", "atlas'"},
		{"a $( in the name", record("a$(id)", "proj-test1", nil), "name", "a$(id)"},
		{"an empty name", record("", "proj-test1", nil), "name", ""},
		{"a quote in the project", record("atlas", "proj-test1'", nil), "project ID", "proj-test1'"},
		{"a $( in the project", record("atlas", "proj-$(id)", nil), "project ID", "proj-$(id)"},
		{"a project too short", record("atlas", "proj", nil), "project ID", "proj"},
		{"a project ending in a hyphen", record("atlas", "proj-test-", nil), "project ID", "proj-test-"},
		{"an upper-case project", record("atlas", "Proj-test1", nil), "project ID", "Proj-test1"},
		{"no project", record("atlas", "", nil), "project ID", ""},
		{"a ; in the key id", record("atlas", "proj-test1", &config.Reader{Email: readerEmail("atlas", "proj-test1"), KeyID: keyID[:39] + ";"}), "key id", keyID[:39] + ";"},
		{"an upper-case key id", record("atlas", "proj-test1", &config.Reader{KeyID: strings.ToUpper(keyID)}), "key id", strings.ToUpper(keyID)},
		{"a short key id", record("atlas", "proj-test1", &config.Reader{KeyID: keyID[:39]}), "key id", keyID[:39]},
	} {
		project, email, gotKey, err := checkedReader(row.meta)
		want := fmt.Sprintf("instance %q's record holds a %s that is not one Google issues (%q); farcast renders nothing from it", row.meta.Name, row.field, row.value)
		if err == nil || err.Error() != want || project != "" || email != "" || gotKey != "" {
			t.Errorf("%s: %q, %q, %q, %v; want %q", row.name, project, email, gotKey, err, want)
		}
	}
}
