package tier

import "testing"

func TestOfReadsTheLabel(t *testing.T) {
	cases := map[string]Tier{
		"kernel": Kernel, "system": System, "app": App,
		"": Unknown, "System": Unknown, "database": Unknown, "APP": Unknown,
	}
	for label, want := range cases {
		if got := Of(map[string]string{Label: label}); got != want {
			t.Errorf("Of(%q) = %q, want %q", label, got, want)
		}
	}
	if got := Of(nil); got != Unknown {
		t.Errorf("Of(nil) = %q, want Unknown", got)
	}
	if got := Of(map[string]string{"other": "app"}); got != Unknown {
		t.Errorf("a different label must not classify: got %q", got)
	}
}

// The asymmetry that matters. Stopping a mislabelled application costs a
// little money; stopping a system component whose label was lost costs an
// instance nobody can unseal while it carries on billing. The tie goes to not
// stopping.
func TestOnlyApplicationsAreStoppableByACostShutdown(t *testing.T) {
	stoppable := map[Tier]bool{App: true, System: false, Kernel: false, Unknown: false}
	for tr, want := range stoppable {
		if got := tr.Stoppable(); got != want {
			t.Errorf("%q.Stoppable() = %v, want %v", tr, got, want)
		}
	}
}

// A case-mangled or misspelled tier must not fall through to something
// stoppable: an unrecognised value is Unknown, and Unknown is protected.
func TestAnUnrecognisedTierIsProtectedNotStopped(t *testing.T) {
	for _, label := range []string{"Application", "apps", "SYSTEM", " app", "app "} {
		if Of(map[string]string{Label: label}).Stoppable() {
			t.Errorf("tier %q was treated as stoppable", label)
		}
	}
}

func TestRankStopsApplicationsFirstAndTheKernelLast(t *testing.T) {
	if !(App.Rank() < Unknown.Rank() && Unknown.Rank() < System.Rank() && System.Rank() < Kernel.Rank()) {
		t.Errorf("ranks out of order: app=%d unknown=%d system=%d kernel=%d",
			App.Rank(), Unknown.Rank(), System.Rank(), Kernel.Rank())
	}
	// Everything the kernel may stop must rank ahead of everything it may not.
	for _, protected := range []Tier{Unknown, System, Kernel} {
		if App.Rank() >= protected.Rank() {
			t.Errorf("App must be stopped before %q", protected)
		}
	}
}

func TestValid(t *testing.T) {
	for _, tr := range []Tier{Kernel, System, App} {
		if !tr.Valid() {
			t.Errorf("%q should be valid", tr)
		}
	}
	for _, tr := range []Tier{Unknown, "database", "APP"} {
		if tr.Valid() {
			t.Errorf("%q should not be valid", tr)
		}
	}
}
