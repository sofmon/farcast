package rehearsal

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// TestResolvePathThroughTheDeepestAncestor: a path that does not exist yet
// resolves through the part that does, so $TMPDIR's /var and /private/var
// spellings, and a symlinked alias, come out as one path.
func TestResolvePathThroughTheDeepestAncestor(t *testing.T) {
	tmp := t.TempDir()
	real, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolvePath(filepath.Join(tmp, "not", "yet"))
	if err != nil || got != filepath.Join(real, "not", "yet") {
		t.Errorf("resolvePath = %q, %v; want %q", got, err, filepath.Join(real, "not", "yet"))
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(tmp, alias); err != nil {
		t.Fatal(err)
	}
	if got, err := resolvePath(filepath.Join(alias, ".kube", "r")); err != nil || got != filepath.Join(real, ".kube", "r") {
		t.Errorf("through an alias: %q, %v", got, err)
	}
	// A dangling link is walked past, not trusted.
	dangling := filepath.Join(tmp, "dangling")
	if err := os.Symlink(filepath.Join(tmp, "gone"), dangling); err != nil {
		t.Fatal(err)
	}
	if got, err := resolvePath(filepath.Join(dangling, "x")); err != nil || got != filepath.Join(real, "dangling", "x") {
		t.Errorf("through a dangling link: %q, %v", got, err)
	}
}

func TestOverlaps(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"/u/h/.kube", "/u/h/.kube", true},
		{"/u/h/.kube/r", "/u/h/.kube", true},
		{"/u/h", "/u/h/.kube", true},
		{"/u/h/.KUBE/r", "/u/h/.kube", true},
		{"/u/h/.kubex", "/u/h/.kube", false},
		{"/u/h/.kub", "/u/h/.kube", false},
		{"/tmp/r", "/u/h/.kube", false},
		{"/anything", "/", true},
	} {
		if got := overlaps(c.a, c.b); got != c.want {
			t.Errorf("overlaps(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestRelateByIdentity: two spellings of one directory are one directory,
// whether the second goes through a symlink or, on macOS, through a firmlink
// (/System/Volumes/Data/private is /private, and no symlink says so); the
// parts that do not exist yet are compared by name, case ignored.
func TestRelateByIdentity(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(home, alias); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	spellings := map[string]string{"plain": home, "alias": alias}
	if real, err := filepath.EvalSymlinks(home); err == nil {
		data := filepath.Join("/System/Volumes/Data", real)
		a, errA := os.Stat(real)
		b, errB := os.Stat(data)
		if errA == nil && errB == nil && os.SameFile(a, b) {
			spellings["data volume"] = data
		}
	}
	rel := func(a, b string) relation {
		t.Helper()
		la, err := locate(a)
		if err != nil {
			t.Fatal(err)
		}
		lb, err := locate(b)
		if err != nil {
			t.Fatal(err)
		}
		r, err := relate(la, lb)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	kube := filepath.Join(home, ".kube")
	gcloud := filepath.Join(home, ".config", "gcloud")
	for name, h := range spellings {
		for _, c := range []struct {
			a, b string
			want relation
		}{
			{filepath.Join(h, ".kube", "r"), kube, inside},
			{filepath.Join(h, ".KUBE", "r"), kube, inside},
			{filepath.Join(h, ".kube"), kube, same},
			{h, kube, holds},
			{filepath.Join(h, ".config"), gcloud, holds},
			{filepath.Join(h, ".config", "gcloud", "r"), gcloud, inside},
			{filepath.Join(h, ".kubex"), kube, apart},
			{filepath.Join(h, ".config", "other"), gcloud, apart},
			{filepath.Join(other, ".kube", "r"), kube, apart},
			{kube, filepath.Join(h, ".kube", "r"), holds},
		} {
			if got := rel(c.a, c.b); got != c.want {
				t.Errorf("%s: relate(%s, %s) = %v, want %v", name, c.a, c.b, got, c.want)
			}
		}
	}
	if len(spellings) < 3 {
		t.Log("no data-volume spelling here; the firmlink cases did not run")
	}
}

func TestCompareRest(t *testing.T) {
	for _, c := range []struct {
		a, b []string
		want relation
	}{
		{nil, nil, same},
		{[]string{"x"}, nil, inside},
		{nil, []string{"x"}, holds},
		{[]string{"Kube", "r"}, []string{"kube"}, inside},
		{[]string{"kube"}, []string{"kubex"}, apart},
		{[]string{"a", "b"}, []string{"a", "c"}, apart},
	} {
		if got := compareRest(c.a, c.b); got != c.want {
			t.Errorf("compareRest(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestProtectedDirsHoldTheDefaultFarcastDirectory: the default farcast
// directory is the one config.Resolve gives without $FARCAST_CONFIG_HOME, it
// is protected whether or not that variable is set, and it is never one the
// environment names, so it is never let through as a rehearsal's own.
func TestProtectedDirsHoldTheDefaultFarcastDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", home)
	t.Setenv("CLOUDSDK_CONFIG", "")
	t.Setenv("KUBECONFIG", "")
	t.Setenv(config.EnvConfigHome, "")
	want, err := config.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(want.Path(), home+string(filepath.Separator)) {
		t.Fatalf("the default farcast directory %s is not in the fake home", want.Path())
	}
	find := func(prot []protectedDir, path string) (protectedDir, bool) {
		for _, p := range prot {
			if p.path == path {
				return p, true
			}
		}
		return protectedDir{}, false
	}
	prot, err := protectedDirs(home)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := find(prot, want.Path()); !ok || p.fromEnv {
		t.Errorf("without $%s: the default %s is %+v, %v; want it protected, not as one the environment names", config.EnvConfigHome, want.Path(), p, ok)
	}
	elsewhere := filepath.Join(t.TempDir(), "farcast")
	t.Setenv(config.EnvConfigHome, elsewhere)
	if prot, err = protectedDirs(home); err != nil {
		t.Fatal(err)
	}
	if p, ok := find(prot, want.Path()); !ok || p.fromEnv {
		t.Errorf("with $%s elsewhere: the default %s is %+v, %v; want it still protected", config.EnvConfigHome, want.Path(), p, ok)
	}
	if p, ok := find(prot, elsewhere); !ok || !p.fromEnv {
		t.Errorf("with $%s: %s is %+v, %v; want it protected as one the environment names", config.EnvConfigHome, elsewhere, p, ok)
	}
}

func TestToolMainLeavesOtherNamesAlone(t *testing.T) {
	var out, errb bytes.Buffer
	for _, argv0 := range []string{"/usr/local/bin/farcast", "farcast-rehearsal", "/x/kubectl.exe", ""} {
		if code, ok := ToolMain(argv0, nil, nil, &out, &errb); ok || code != 0 {
			t.Errorf("ToolMain(%q) ran as a tool", argv0)
		}
	}
	if out.Len() != 0 || errb.Len() != 0 {
		t.Errorf("ToolMain wrote %q %q", out.String(), errb.String())
	}
}

// TestSpecRefusesWhatAGCloudFileCannotCarry: the account and project are
// written into a gcloud configuration file, so neither may add a line or a
// section to it.
func TestSpecRefusesWhatAGCloudFileCannotCarry(t *testing.T) {
	for _, v := range []string{"", "a\nproject = x", "[auth]", "a=b", "x\x00y"} {
		if err := validINIValue("account", v); err == nil {
			t.Errorf("validINIValue accepted %q", v)
		}
	}
	if err := validINIValue("account", "operator@rehearsal.invalid"); err != nil {
		t.Error(err)
	}
	for _, n := range []string{"", "Rehearsal", "-a", "a-", "a/b", "a_b", "abcdefghijklmnopqrstuvwxyz0123456"} {
		if validInstance(n) == nil {
			t.Errorf("validInstance accepted %q", n)
		}
	}
}
