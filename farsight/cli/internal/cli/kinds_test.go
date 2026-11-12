package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// The README's table of error kinds is the contract; this list is the code's.
// They are held to each other, so a kind cannot ship undocumented, and a
// documented one cannot be dropped.
func TestTheREADMEDocumentsEveryErrorKind(t *testing.T) {
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)
	start := strings.Index(readme, "### Error kinds")
	if start < 0 {
		t.Fatal("the README has no Error kinds section")
	}
	section := readme[start:]
	if end := strings.Index(section[len("### Error kinds"):], "\n### "); end > 0 {
		section = section[:end+len("### Error kinds")]
	}
	var documented []string
	for _, line := range strings.Split(section, "\n") {
		if strings.HasPrefix(line, "| `") {
			documented = append(documented, strings.Trim(strings.SplitN(line, "|", 3)[1], " `"))
		}
	}
	if fmt.Sprint(documented) != fmt.Sprint(errorKinds) {
		t.Errorf("the README documents %v\nthe code has         %v", documented, errorKinds)
	}
	if strings.Contains(section, "| `usage`") {
		t.Error("usage is not a kind: exit 2 has no envelope")
	}
}

// Every command that loads an instance record that is not there reports
// not_found — inferred by the router, since none of them named it.
func TestAMissingRecordIsNotFoundForEveryCommand(t *testing.T) {
	dir := vectorConfigDir(t)
	for _, args := range [][]string{{"ps", "nowhere"}, {"costs", "nowhere"}, {"usage", "nowhere"}, {"world", "nowhere"}} {
		out, code := runRouter(t, append([]string{"--config", dir.Path(), "-o", "json"}, args...)...)
		var env struct {
			Error struct {
				Kind string `json:"kind"`
				Code int    `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(out, &env); err != nil {
			t.Fatalf("%v: not an envelope: %v\n%s", args, err, out)
		}
		if env.Error.Kind != kindNotFound || env.Error.Code != code || code != 1 {
			t.Errorf("%v: kind %q code %d exit %d", args, env.Error.Kind, env.Error.Code, code)
		}
	}
}

// Exit 2 has no envelope, in JSON mode as in human mode.
func TestUsageErrorsHaveNoEnvelope(t *testing.T) {
	dir := vectorConfigDir(t)
	for _, args := range [][]string{{"world"}, {"world", "--no-such-flag", "x"}, {"frobnicate"}, {"instances", "extra"}} {
		out, code := runRouter(t, append([]string{"--config", dir.Path(), "-o", "json"}, args...)...)
		if code != 2 || len(out) != 0 {
			t.Errorf("%v: exit %d, stdout %q; want exit 2 and nothing on stdout", args, code, out)
		}
	}
}

func TestKindsAreFoundThroughWrapping(t *testing.T) {
	err := fmt.Errorf("outer: %w", withKind(kindTimeout, errors.New("inner")))
	if kindOf(err) != kindTimeout || err.Error() != "outer: inner" {
		t.Errorf("kind %q, text %q", kindOf(err), err)
	}
	if kindOf(errors.New("plain")) != kindInternal || withKind(kindTimeout, nil) != nil {
		t.Error("a plain error is internal, and a nil one stays nil")
	}
	// A named kind is never overridden by the router's inference.
	named := withKind(kindRecordUnreadable, fmt.Errorf("x: %w", config.ErrNoInstanceRecord))
	if kindOf(classified(named)) != kindRecordUnreadable {
		t.Error("the router overrode a kind a command named")
	}
}

// The costs report reads the same checkpoint the same way, and its version
// refusal now carries the kind world reports.
func TestCostsAndWorldShareTheCheckpointReader(t *testing.T) {
	_, _, err := decodeCheckpoint(`{"version":99}`)
	if kindOf(err) != kindVersionSkew || !strings.Contains(err.Error(), "ledger version 99 and this build reads 1") {
		t.Errorf("version: %v (%s)", err, kindOf(err))
	}
	if _, _, err := decodeCheckpoint(`not json`); kindOf(err) != kindKubectlFailed || !strings.HasPrefix(err.Error(), "decode the kernel's ledger") {
		t.Errorf("garbage: %v (%s)", err, kindOf(err))
	}
	if got := notMeteredFacts(); len(got) != 5 || !strings.Contains(got[3], "$37/month") {
		t.Errorf("not metered: %q", got)
	}
}
