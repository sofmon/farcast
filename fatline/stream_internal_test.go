package fatline

import (
	"strings"
	"testing"
	"unicode/utf8"
)

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

// An unknown route's name is the peer's own text, and the record of it is
// bounded: cut to maxRecordedRoute bytes, never inside a character, and
// marked so a reader knows it was cut.
func TestRecordedRouteIsBounded(t *testing.T) {
	for _, name := range []string{"", "keyholder", "\x1b[8m", strings.Repeat("a", maxRecordedRoute)} {
		if got := recordedRoute(name); got != name {
			t.Errorf("recordedRoute(%q) = %q; a name within the bound is recorded as sent", name, got)
		}
	}

	for _, tc := range []struct {
		what, name string
		keep       int // bytes of the name kept
	}{
		{"one byte over", strings.Repeat("a", maxRecordedRoute+1), maxRecordedRoute},
		{"a megabyte of control text", strings.Repeat("\x1b[2J", 1<<18), maxRecordedRoute},
		// 3-byte characters: the bound falls inside the 22nd, which is dropped.
		{"multibyte", strings.Repeat("€", 30), 63},
		// 2-byte characters ending exactly on the bound.
		{"on the bound", strings.Repeat("é", 40), maxRecordedRoute},
		// Invalid bytes are each their own rune; cutting between them is fine.
		{"invalid UTF-8", strings.Repeat("\xff", 100), maxRecordedRoute},
	} {
		got := recordedRoute(tc.name)
		kept, marked := strings.CutSuffix(got, routeCutMarker)
		if !marked {
			t.Errorf("%s: %q is not marked as cut", tc.what, got)
			continue
		}
		if len(kept) != tc.keep || !strings.HasPrefix(tc.name, kept) {
			t.Errorf("%s: kept %d bytes %q, want the first %d", tc.what, len(kept), kept, tc.keep)
		}
		if utf8.ValidString(tc.name) && !utf8.ValidString(kept) {
			t.Errorf("%s: the cut split a character: %q", tc.what, kept)
		}
	}
}
