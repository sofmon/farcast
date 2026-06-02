package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveOverride(t *testing.T) {
	d, err := Resolve("/custom/dir")
	if err != nil {
		t.Fatal(err)
	}
	if d.Path() != "/custom/dir" {
		t.Errorf("Path = %q, want /custom/dir", d.Path())
	}
}

func TestResolveEnv(t *testing.T) {
	t.Setenv(EnvConfigHome, "/env/dir")
	d, err := Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if d.Path() != "/env/dir" {
		t.Errorf("Path = %q, want /env/dir", d.Path())
	}
}

func TestResolveDefault(t *testing.T) {
	t.Setenv(EnvConfigHome, "")
	d, err := Resolve("")
	if err != nil {
		t.Skipf("user config dir unavailable: %v", err)
	}
	if !strings.HasSuffix(d.Path(), "farcast") {
		t.Errorf("default path %q should end in farcast", d.Path())
	}
}

func TestEnsureCreatesSecureDir(t *testing.T) {
	dir := Dir(filepath.Join(t.TempDir(), "farcast"))
	if err := dir.Ensure(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir.Path())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("dir perm = %#o, want no group/world bits", perm)
	}
}

func TestEnsureRejectsPermissiveDir(t *testing.T) {
	dir := Dir(filepath.Join(t.TempDir(), "farcast"))
	if err := os.MkdirAll(dir.Path(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir.Path(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := dir.Ensure(); err == nil {
		t.Error("Ensure accepted a 0755 directory; want error")
	}
}

func TestLoadAbsentReturnsDefaults(t *testing.T) {
	c, err := Load(Dir(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if c.DefaultOutput != "" {
		t.Errorf("DefaultOutput = %q, want empty", c.DefaultOutput)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := Dir(filepath.Join(t.TempDir(), "farcast"))
	if err := (&Config{DefaultOutput: "json"}).Save(dir); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir.Path(), fileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("config file perm = %#o, want no group/world bits", perm)
	}

	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.DefaultOutput != "json" {
		t.Errorf("DefaultOutput = %q, want json", got.DefaultOutput)
	}
}

func TestLoadMalformed(t *testing.T) {
	dir := Dir(filepath.Join(t.TempDir(), "farcast"))
	if err := dir.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir.Path(), fileName), []byte("foo: {bar"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("Load accepted malformed YAML; want error")
	}
}
