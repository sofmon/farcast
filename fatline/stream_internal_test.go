package fatline

import "testing"

// resolve is where a caller-supplied ordinal becomes an address, so the range
// check is pinned here rather than end-to-end.
//
// An end-to-end test cannot prove this on its own: an out-of-range ordinal
// usually resolves to an address nothing is listening on, so the relay fails
// either way and a missing range check looks identical to a working one.
func TestStreamRouteResolve(t *testing.T) {
	single := StreamRoute{Name: "one", Addr: "svc:9443"}
	replicas := StreamRoute{Name: "many", Addr: "svc-{ordinal}.headless:9443", Ordinals: 3}

	t.Run("no ordinals", func(t *testing.T) {
		got, err := single.resolve("")
		if err != nil || got != "svc:9443" {
			t.Fatalf("resolve(\"\") = %q, %v", got, err)
		}
		if _, err := single.resolve("0"); err == nil {
			t.Error("a route with no ordinals accepted one")
		}
	})

	t.Run("in range", func(t *testing.T) {
		for i, want := range map[string]string{
			"0": "svc-0.headless:9443",
			"1": "svc-1.headless:9443",
			"2": "svc-2.headless:9443",
		} {
			got, err := replicas.resolve(i)
			if err != nil || got != want {
				t.Errorf("resolve(%q) = %q, %v; want %q", i, got, err, want)
			}
		}
	})

	// Every one of these must be refused by the RANGE CHECK, not by a failed
	// dial later on. An unbounded ordinal would let a caller aim the relay at
	// an address the operator never configured.
	t.Run("refused", func(t *testing.T) {
		for _, ordinal := range []string{"", "3", "4", "99", "-1", "0x0", "1.0", " 1", "1 ", "+1", "٢", "1e0", "９"} {
			if got, err := replicas.resolve(ordinal); err == nil {
				t.Errorf("resolve(%q) = %q, want a refusal", ordinal, got)
			}
		}
	})
}
