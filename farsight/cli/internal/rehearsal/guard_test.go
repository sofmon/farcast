package rehearsal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// TestSpecHoldsTheReadersProjectShape: the project is held to the shape
// farcast's reader checks (checkedReader) at creation and on every load, so a
// rehearsal never records one its own reads would refuse; the instance name
// to the rule 'farcast install' applies.
func TestSpecHoldsTheReadersProjectShape(t *testing.T) {
	for _, p := range []string{"", "rehea", "Rehearsal-project", "1rehearsal", "rehearsal-", "re_hearsal",
		"rehearsal project", "rehearsal\nproject", "abcdefghijklmnopqrstuvwxyz01234"} {
		if validProject(p) == nil {
			t.Errorf("validProject accepted %q", p)
		}
	}
	for _, p := range []string{DefaultProject, "abcdef", "proj-123", "abcdefghijklmnopqrstuvwxyz0123"} {
		if err := validProject(p); err != nil {
			t.Error(err)
		}
	}
	for _, n := range []string{"", "Rehearsal", "-a", "a-", "a/b", "a_b", "abcdefghijklmnopqrstuvwxyz0123456"} {
		if validInstance(n) == nil {
			t.Errorf("validInstance accepted %q", n)
		}
	}
	dir := filepath.Join(t.TempDir(), "r")
	if r, err := Start(t.Context(), Options{Dir: dir, Home: t.TempDir(), Project: "Not_A_Project"}); err == nil {
		_ = r.Close()
		t.Error("Start accepted a project farcast's reader refuses")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("Start made its directory before refusing the project: %v", err)
	}
	s := Spec{Instance: DefaultInstance, Project: "Not_A_Project", Scenario: ScenarioHealthy, Started: time.Now(), Dirs: dirsUnder("/r")}
	if s.validate() == nil {
		t.Error("a spec with a project farcast's reader refuses validated")
	}
}

// TestACallLineStaysOneLine: a calls.log line holds a path and its query
// as they are, and Go-quotes any argument that could end or split a line.
func TestACallLineStaysOneLine(t *testing.T) {
	if got, want := quoteArgs([]string{"GET", "/api/v1/namespaces?labelSelector=a%2Fb%3Dc&limit=500", "as", "reader"}),
		"GET /api/v1/namespaces?labelSelector=a%2Fb%3Dc&limit=500 as reader"; got != want {
		t.Errorf("quoteArgs = %q, want %q", got, want)
	}
	if got, want := quoteArgs([]string{"GET", "/a b\nc", ""}), `GET "/a b\nc" ""`; got != want {
		t.Errorf("quoteArgs = %q, want %q", got, want)
	}
}
