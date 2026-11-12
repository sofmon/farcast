package rehearsal

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
)

// The guard: a rehearsal never reads, writes or stats anything under the
// operator's real gcloud, kube or farcast directories (D3). Start and
// SetScenario refuse, before they write anything, a directory that is one of
// them, is inside one, or holds one.

// protectedDir is one of the operator's real directories, and what it is.
// fromEnv marks one an environment variable names, rather than one at a
// fixed place.
type protectedDir struct {
	path, what string
	fromEnv    bool
}

// defaultConfigName is the directory config.Resolve joins to the user
// configuration directory when neither --config nor $FARCAST_CONFIG_HOME is
// given (TestProtectedDirsHoldTheDefaultFarcastDirectory holds the two
// together).
const defaultConfigName = "farcast"

// protectedDirs are the directories a rehearsal must never touch:
// <home>/.config/gcloud, <home>/.kube, this machine's default farcast
// configuration directory (<UserConfigDir>/farcast, whatever
// $FARCAST_CONFIG_HOME says: exporting it does not make the default one any
// less real), the directory $FARCAST_CONFIG_HOME names, and the directories
// $CLOUDSDK_CONFIG and $KUBECONFIG name, when set. home "" is the user's own.
func protectedDirs(home string) ([]protectedDir, error) {
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot find the home directory whose gcloud, kube and farcast directories a rehearsal must never touch: %w", err)
		}
		home = h
	}
	out := []protectedDir{
		{path: filepath.Join(home, ".config", "gcloud"), what: "gcloud's configuration directory"},
		{path: filepath.Join(home, ".kube"), what: "kubectl's directory"},
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("cannot find this machine's default farcast configuration directory, which a rehearsal must never touch: %w", err)
	}
	out = append(out, protectedDir{path: filepath.Join(base, defaultConfigName), what: "this machine's default farcast configuration directory"})
	if os.Getenv(config.EnvConfigHome) != "" {
		d, err := config.Resolve("")
		if err != nil {
			return nil, fmt.Errorf("cannot find the farcast configuration directory $%s names, which a rehearsal must never touch: %w", config.EnvConfigHome, err)
		}
		out = append(out, protectedDir{path: d.Path(), what: "the farcast configuration directory $" + config.EnvConfigHome + " names", fromEnv: true})
	}
	if v := os.Getenv("CLOUDSDK_CONFIG"); v != "" {
		out = append(out, protectedDir{path: v, what: "the directory $CLOUDSDK_CONFIG names", fromEnv: true})
	}
	for _, kc := range filepath.SplitList(os.Getenv("KUBECONFIG")) {
		if kc != "" {
			out = append(out, protectedDir{path: filepath.Dir(kc), what: "the directory of a kubeconfig $KUBECONFIG names", fromEnv: true})
		}
	}
	return out, nil
}

// guard refuses dir when it overlaps any protected directory: the same
// directory, one inside the other, either way round. The two are compared by
// what they are on disk, not by how they are spelled (relate), so a /var path
// and its /private/var spelling, a path reached through a symlinked alias, and
// one reached through a macOS firmlink (/System/Volumes/Data/Users is /Users,
// with no symlink to say so) are one directory.
//
// One overlap is not a refusal: a directory $CLOUDSDK_CONFIG, $KUBECONFIG or
// $FARCAST_CONFIG_HOME names strictly inside a directory that already holds
// a rehearsal made there. That is the rehearsal's own — what an operator
// exports to run farcast against it from a terminal — and refusing it would
// refuse every scenario switch and restart in that shell. A new directory
// has no rehearsal yet, so it is always held to every directory.
func guard(dir, home string) error {
	target, err := locate(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve %s: %w", dir, err)
	}
	prot, err := protectedDirs(home)
	if err != nil {
		return err
	}
	var inside []error
	for _, p := range prot {
		pl, err := locate(p.path)
		if err != nil {
			return fmt.Errorf("cannot resolve %s (%s), so cannot tell whether %s is clear of it: %w", p.path, p.what, dir, err)
		}
		rel, err := relate(target, pl)
		if err != nil {
			return fmt.Errorf("cannot tell whether %s is clear of %s (%s): %w", dir, p.path, p.what, err)
		}
		if rel == apart {
			continue
		}
		refusal := fmt.Errorf("%s overlaps %s (%s), which a rehearsal never touches; choose a new directory elsewhere, or leave --dir out for a temporary one",
			dir, p.what, pl.path)
		if !p.fromEnv || rel != holds {
			return refusal
		}
		inside = append(inside, refusal)
	}
	// Only now, with target clear of every directory it could be inside,
	// is anything in it read.
	if len(inside) > 0 {
		if s, err := LoadSpec(target.path); err != nil || s.Dirs.Root != target.path {
			return inside[0]
		}
	}
	return nil
}

// located is a path resolved through its deepest existing ancestor: base is
// that ancestor with its symlinks resolved, rest the components below it
// that do not exist yet, and path the two joined.
type located struct {
	path, base string
	rest       []string
}

// resolvePath makes p absolute and resolves it through its deepest existing
// ancestor (locate).
func resolvePath(p string) (string, error) {
	l, err := locate(p)
	return l.path, err
}

// locate makes p absolute and resolves it through its deepest existing
// ancestor: filepath.EvalSymlinks of that ancestor, with the components that
// do not exist yet joined back on. EvalSymlinks alone fails on a path that
// does not exist, and comparing one resolved side with one unresolved side
// misses /var → /private/var on macOS.
//
// It stats only the path's own ancestors, one Lstat each, and reads nothing.
func locate(p string) (located, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return located{}, err
	}
	cur := abs
	var rest []string
	for {
		if _, err := os.Lstat(cur); err == nil {
			// A dangling link, or a component that cannot be searched,
			// is treated as not existing: the walk goes on up.
			if real, err := filepath.EvalSymlinks(cur); err == nil {
				return newLocated(real, rest), nil
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return newLocated(cur, rest), nil
		}
		rest = append(rest, filepath.Base(cur))
		cur = parent
	}
}

// newLocated builds a located from its base and the components below it,
// collected deepest first.
func newLocated(base string, reversed []string) located {
	rest := make([]string, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		rest = append(rest, reversed[i])
	}
	return located{path: filepath.Join(append([]string{base}, rest...)...), base: base, rest: rest}
}

// relation is how one directory stands to another.
type relation int

const (
	apart  relation = iota
	same            // one directory
	inside          // the first is strictly inside the second
	holds           // the first strictly holds the second
)

// relate says how a stands to b, comparing what they are on disk, not how
// they are spelled. Two spellings of one directory — a symlinked alias, a
// macOS firmlink, another case on a case-insensitive volume — have the same
// file identity (os.SameFile), so the existing parts are matched by identity:
// when b's base is a's base or one of its ancestors, a is spelled from there
// and the two are compared component by component, and the same the other
// way round. The parts that do not exist yet have no identity, so they are
// compared by name, ignoring case: macOS volumes are case-insensitive by
// default, and elsewhere this only refuses a little more.
//
// The spellings are compared too (overlaps), so relate never finds less than
// a comparison of resolved paths would. Where the two disagree, the stricter
// answer is kept: anything but holds is never read as holds.
//
// Not covered, and not reachable by a rehearsal: a directory that holds a
// firmlink without being one of its spellings' ancestors, such as
// /System/Volumes/Data itself. Such a directory already exists and is not
// empty, so Start refuses it as not its own, and it holds no rehearsal, so
// SetScenario refuses it too.
func relate(a, b located) (relation, error) {
	byName := spelled(a.path, b.path)
	ai, err := os.Lstat(a.base)
	if err != nil {
		return apart, err
	}
	bi, err := os.Lstat(b.base)
	if err != nil {
		return apart, err
	}
	byID := apart
	if aFromB, ok, err := spelledFrom(a, bi); err != nil {
		return apart, err
	} else if ok {
		byID = compareRest(aFromB, b.rest)
	} else if bFromA, ok, err := spelledFrom(b, ai); err != nil {
		return apart, err
	} else if ok {
		byID = compareRest(a.rest, bFromA)
	}
	switch {
	case byID == apart:
		return byName, nil
	case byName == apart || byName == byID:
		return byID, nil
	default:
		// The two disagree on how, not on whether: never read that as
		// holds, the one relation that can be let through.
		return same, nil
	}
}

// spelledFrom finds anchor among l's base and its ancestors, by identity,
// and returns the components that lead from it down to l. ok is false when
// anchor is none of them.
func spelledFrom(l located, anchor os.FileInfo) (down []string, ok bool, err error) {
	cur := l.base
	var up []string
	for {
		fi, err := os.Lstat(cur)
		if err != nil {
			return nil, false, err
		}
		if os.SameFile(fi, anchor) {
			down = make([]string, 0, len(up)+len(l.rest))
			for i := len(up) - 1; i >= 0; i-- {
				down = append(down, up[i])
			}
			return append(down, l.rest...), true, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil, false, nil
		}
		up = append(up, filepath.Base(cur))
		cur = parent
	}
}

// compareRest says how a stands to b, given each as the components below one
// common directory, compared by name with case ignored.
func compareRest(a, b []string) relation {
	n := min(len(a), len(b))
	for i := range n {
		if !strings.EqualFold(a[i], b[i]) {
			return apart
		}
	}
	switch {
	case len(a) == len(b):
		return same
	case len(a) > len(b):
		return inside
	default:
		return holds
	}
}

// spelled says how a stands to b by their resolved spellings alone, case
// ignored.
func spelled(a, b string) relation {
	a, b = strings.ToLower(filepath.Clean(a)), strings.ToLower(filepath.Clean(b))
	switch {
	case a == b:
		return same
	case within(a, b):
		return inside
	case within(b, a):
		return holds
	default:
		return apart
	}
}

// overlaps reports whether two resolved paths are one, or one holds the
// other, by their spellings. Case is ignored: macOS volumes are
// case-insensitive by default, so ~/.KUBE is ~/.kube there, and treating them
// as one elsewhere only refuses a little more.
func overlaps(a, b string) bool {
	return spelled(a, b) != apart
}

// within reports whether p is strictly inside dir.
func within(p, dir string) bool {
	sep := string(filepath.Separator)
	if dir == sep {
		return p != sep
	}
	return strings.HasPrefix(p, dir+sep)
}
