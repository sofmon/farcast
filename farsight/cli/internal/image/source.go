package image

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FindSource locates the farcast repository checkout containing dir (walking
// up to a go.mod declaring module github.com/sofmon/farcast).
//
// The checkout is the build's source of truth (ADR 0007: everything the
// instance runs is derived from Git by the operator's machine), so the image
// path needs to know where it is. The walk keeps going past a go.mod that
// declares some other module — sdk/go is its own module inside this very
// repository — and an empty dir means the working directory.
func FindSource(dir string) (string, error) {
	if dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("image: determine working directory: %w", err)
		}
		dir = wd
	}
	start, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("image: resolve %s: %w", dir, err)
	}
	for at := start; ; {
		data, err := os.ReadFile(filepath.Join(at, "go.mod"))
		if err == nil && modulePath(data) == Module {
			return at, nil
		}
		parent := filepath.Dir(at)
		if parent == at {
			return "", fmt.Errorf("image: no farcast checkout at or above %s (looked for a go.mod declaring module %s)", start, Module)
		}
		at = parent
	}
}

// modulePath extracts the module path from go.mod, or "" if there is none.
func modulePath(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		rest, ok := strings.CutPrefix(line, "module")
		if !ok || (rest != "" && !isSpace(rest[0])) {
			continue
		}
		if i := strings.Index(rest, "//"); i >= 0 {
			rest = rest[:i]
		}
		return strings.Trim(strings.TrimSpace(rest), `"`)
	}
	return ""
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' }
