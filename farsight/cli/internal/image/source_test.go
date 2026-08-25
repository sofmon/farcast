package image

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindSourceWalksUpToTheFarcastModule(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module "+Module+"\n\ngo 1.26\n")
	nested := filepath.Join(root, "farsight", "cli", "internal", "image")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := FindSource(nested)
	if err != nil {
		t.Fatal(err)
	}
	if !sameDir(t, got, root) {
		t.Fatalf("FindSource = %q, want %q", got, root)
	}
}

func TestFindSourceSkipsForeignModules(t *testing.T) {
	// sdk/go is its own module inside this very repository, so the walk must
	// keep going past a go.mod that declares something else rather than
	// mistaking it for the checkout root.
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module "+Module+"\n")
	inner := filepath.Join(root, "sdk", "go")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(inner, "go.mod"), "module "+Module+"/sdk/go // the public SDK\n")

	got, err := FindSource(inner)
	if err != nil {
		t.Fatal(err)
	}
	if !sameDir(t, got, root) {
		t.Fatalf("FindSource = %q, want the outer checkout %q", got, root)
	}
}

func TestFindSourceFailsOutsideACheckout(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/unrelated\n")

	_, err := FindSource(dir)
	if err == nil {
		t.Fatal("expected an error outside a farcast checkout")
	}
	// The message has to say what was looked for: without a checkout there is
	// nothing to build from, and the operator needs to know why.
	if !strings.Contains(err.Error(), Module) {
		t.Fatalf("err = %v, want it to name the module it looked for", err)
	}
}

func TestFindSourceFindsThisRepository(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root, err := FindSource(wd)
	if err != nil {
		t.Fatalf("FindSource from the package's own directory: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if modulePath(data) != Module {
		t.Fatalf("go.mod at %s declares %q", root, modulePath(data))
	}
}

func TestModulePath(t *testing.T) {
	tests := map[string]string{
		"module github.com/sofmon/farcast\n\ngo 1.26\n":      Module,
		"// header\nmodule  \"github.com/sofmon/farcast\"\n": Module,
		"module github.com/sofmon/farcast // comment\n":      Module,
		"modulefoo bar\n": "",
		"go 1.26\n":       "",
	}
	for in, want := range tests {
		if got := modulePath([]byte(in)); got != want {
			t.Errorf("modulePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// sameDir compares two paths after resolving symlinks, so a macOS /var →
// /private/var temp directory does not fail a correct answer.
func sameDir(t *testing.T, a, b string) bool {
	t.Helper()
	ra, err := filepath.EvalSymlinks(a)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := filepath.EvalSymlinks(b)
	if err != nil {
		t.Fatal(err)
	}
	return ra == rb
}
