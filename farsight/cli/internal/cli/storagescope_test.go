package cli

import "testing"

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
