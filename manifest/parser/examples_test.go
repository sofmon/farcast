package parser

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// An example that idles must stop on SIGTERM. A shell started as PID 1 by
// `sh -c "… && sleep N"` has no handler for it, so the kernel drops the signal
// and the Pod bills through its whole grace period: the 2026-11-10 walk saw
// the egress fixture at the old pod count for three ticks after a stop. The
// shape that stops installs a TERM trap before it idles, and idles in `wait`,
// which returns the moment a trapped signal arrives.
//
// A container cannot be run as PID 1 in a unit test, so this checks the
// shape; the next live walk's stop step is the behavioural check.
func TestExampleContainersStopOnSIGTERM(t *testing.T) {
	instr := regexp.MustCompile(`(?im)^\s*(CMD|ENTRYPOINT)\s+(.*)$`)
	trap := regexp.MustCompile(`trap\s+'[^']*'\s+([A-Z ]*\bTERM\b[A-Z ]*);`)
	idle := regexp.MustCompile(`\bsleep\s+\d+\s*&\s*wait\b`)
	checked := 0
	err := filepath.WalkDir("../examples", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasPrefix(d.Name(), "Containerfile") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range instr.FindAllStringSubmatch(string(data), -1) {
			line := m[2]
			if !strings.Contains(line, "sleep") {
				continue
			}
			checked++
			at := trap.FindStringIndex(line)
			if at == nil || !idle.MatchString(line) || strings.Index(line, "sleep") < at[0] {
				t.Errorf("%s: %s %s idles without stopping on SIGTERM; trap TERM first, then 'sleep N & wait'", path, m[1], line)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no example idles, so this check checked nothing; the egress and with-build fixtures do")
	}
}
