package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/sofmon/farcast/datasphere"
)

// Which key spaces a listing consults. Getting any of these wrong loses objects
// from a listing — objects that are still stored, still billed, and still
// readable by their owner, but invisible to the operator's own tooling.
func TestSpaceCanHold(t *testing.T) {
	scopes := []string{"app/"}

	cases := []struct {
		name        string
		spacePrefix string
		requested   string
		want        bool
	}{
		// The bucket root spans everything.
		{"master holds the root", "", "", true},
		{"scope holds the root", "app/", "", true},

		// A request inside the scope: the scope answers, the master must not
		// even be consulted — its keyring can only fail on objects that are
		// not its own, which would read as corruption.
		{"scope holds its own prefix", "app/", "app/", true},
		{"scope holds a key inside it", "app/", "app/reports/", true},
		{"master skipped inside a scope", "", "app/", false},
		{"master skipped deeper inside a scope", "", "app/reports/q3.csv", false},

		// A request outside every scope belongs to the master alone.
		{"master holds its own keys", "", "system/", true},
		{"scope skipped for a foreign prefix", "app/", "system/", false},

		// A partial segment is not containment: "a" does not sit inside
		// "app/", and "app/" does start with "a".
		{"scope holds a prefix that contains it", "app/", "a", true},
		{"master holds a prefix that merely looks scoped", "", "a", true},
		{"master holds application-like keys", "", "application/x", true},
		{"scope skipped for application-like keys", "app/", "application/x", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := spaceCanHold(tc.spacePrefix, tc.requested, scopes); got != tc.want {
				t.Errorf("spaceCanHold(%q, %q) = %v, want %v", tc.spacePrefix, tc.requested, got, tc.want)
			}
		})
	}
}

// With no scopes at all, every request belongs to the master — the behaviour
// every instance had before 3.2 and must keep.
func TestSpaceCanHoldWithoutScopes(t *testing.T) {
	for _, requested := range []string{"", "app/", "system/x"} {
		if !spaceCanHold("", requested, nil) {
			t.Errorf("master skipped for %q on an instance with no scopes", requested)
		}
	}
}

// A listing spans every key space that could hold the prefix, and each is
// expected to fail on the others' objects — that is what a scope IS. Only an
// object NO key space could name is worth telling an operator about.
//
// The Phase 4.3 walk spent its time hunting corruption that did not exist
// because this warned about the routine case.
func TestOnlyObjectsNoKeySpaceCouldNameAreReported(t *testing.T) {
	foreign := func(stored string) error {
		return &datasphere.NameError{Stored: stored, Err: datasphere.ErrForeignObject}
	}

	t.Run("another key space named it", func(t *testing.T) {
		errs := []error{errors.Join(foreign("aaa/bbb"), foreign("ccc/ddd"))}
		named := map[string]bool{"aaa/bbb": true, "ccc/ddd": true}
		if err := unnamedOnly(errs, named); err != nil {
			t.Errorf("reported %v for objects another key space resolved", err)
		}
	})

	t.Run("nobody named it", func(t *testing.T) {
		errs := []error{foreign("aaa/bbb")}
		err := unnamedOnly(errs, map[string]bool{"ccc/ddd": true})
		if err == nil {
			t.Fatal("an object no key space could name was suppressed")
		}
		if !strings.Contains(err.Error(), "aaa/bbb") {
			t.Errorf("the error does not name the stored object: %v", err)
		}
	})

	t.Run("a mixture", func(t *testing.T) {
		errs := []error{errors.Join(foreign("aaa/bbb"), foreign("eee/fff"))}
		err := unnamedOnly(errs, map[string]bool{"aaa/bbb": true})
		if err == nil {
			t.Fatal("the unnamed object was suppressed along with the named one")
		}
		if strings.Contains(err.Error(), "aaa/bbb") {
			t.Errorf("a resolved object was still reported: %v", err)
		}
		if !strings.Contains(err.Error(), "eee/fff") {
			t.Errorf("the unresolved object was not reported: %v", err)
		}
	})

	t.Run("a failure that is not about a name survives", func(t *testing.T) {
		// A provider error is not a key-space mismatch and must never be
		// filtered away by one.
		errs := []error{errors.New("list: the cloud said no")}
		if err := unnamedOnly(errs, map[string]bool{}); err == nil {
			t.Fatal("a provider failure was suppressed")
		}
	})
}
