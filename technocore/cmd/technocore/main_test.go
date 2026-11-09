package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/technocore/kernel"
)

// A value outside the bounds is refused before the kernel reaches for the
// cluster: these run outside one, so getting as far as the in-cluster client
// would fail with something else entirely.
func TestServeRefusesAnIntervalOrCooldownOutsideTheBounds(t *testing.T) {
	base := []string{"serve", "--instance=x", "--cost-limit=1"}
	for flag, value := range map[string]string{
		"--interval":       "1s",
		"--adapt-cooldown": "10s",
	} {
		err := run(append(base, flag+"="+value))
		if err == nil || !strings.Contains(err.Error(), flag) {
			t.Errorf("%s=%s = %v; want a refusal naming the flag", flag, value, err)
		}
	}
	if err := run(append(base, "--interval=-1s")); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Errorf("a negative interval = %v; want it refused", err)
	}
}

// A tick where every reading was one the metrics server had not refreshed is
// the dedupe working, and it has to reach the log for anyone to see it.
func TestATickOfUnrefreshedReadingsIsLogged(t *testing.T) {
	var buf bytes.Buffer
	s := &supervisor{
		log:             slog.New(slog.NewTextHandler(&buf, nil)),
		reconciler:      &kernel.Reconciler{},
		checkpointEvery: time.Hour,
		lastCheckpoint:  time.Now(),
	}
	s.observe(kernel.Report{UsageRepeated: 3}, nil)
	if !strings.Contains(buf.String(), "observed usage") || !strings.Contains(buf.String(), "unrefreshed=3") {
		t.Errorf("a tick of unrefreshed readings was not logged:\n%s", buf.String())
	}
}
