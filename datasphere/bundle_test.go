package datasphere

import (
	"errors"
	"strings"
	"testing"
)

func TestBundleRoundTrips(t *testing.T) {
	scope := mustScope(t, "app", "app/")
	b, err := NewBundle("prod", 7, []Scope{scope})
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	wire, err := b.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := ParseBundle(wire)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if back.Instance() != "prod" || back.Generation() != 7 {
		t.Errorf("instance/generation = %q/%d, want prod/7", back.Instance(), back.Generation())
	}
	got := back.Scopes()
	if len(got) != 1 || got[0].Name != "app" || got[0].Prefix != "app/" {
		t.Fatalf("scopes did not survive: %v", got)
	}
	wk, _ := scope.Keyring().ActiveKEK()
	gk, _ := got[0].Keyring().ActiveKEK()
	if gk.ID != wk.ID || string(gk.key) != string(wk.key) {
		t.Error("scope key material did not survive the bundle round trip")
	}
}

func TestNewBundleRefuses(t *testing.T) {
	app := mustScope(t, "app", "app/")
	cases := []struct {
		name     string
		instance string
		scopes   []Scope
	}{
		{"empty instance", "", []Scope{app}},
		{"blank instance", "   ", []Scope{app}},
		{"no scopes", "prod", nil},
		{"duplicate scope name", "prod", []Scope{app, mustScope(t, "app", "elsewhere/")}},
		{"overlapping scopes", "prod", []Scope{app, mustScope(t, "other", "app/inner/")}},
		{"invalid scope", "prod", []Scope{{Name: "app", Prefix: "app/"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewBundle(tc.instance, 1, tc.scopes); err == nil {
				t.Fatal("NewBundle accepted an unusable bundle")
			}
		})
	}
}

func TestParseBundleRefusesUnknownVersion(t *testing.T) {
	b, err := NewBundle("prod", 1, []Scope{mustScope(t, "app", "app/")})
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	wire, err := b.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	bumped := strings.Replace(string(wire), "version: 1", "version: 99", 1)
	if _, err := ParseBundle([]byte(bumped)); !errors.Is(err, ErrBundleInvalid) {
		t.Fatalf("ParseBundle accepted version 99: %v", err)
	}
}

// A bundle is key material end to end, so a parse failure must never echo the
// payload — not even the window a YAML parser would normally quote.
func TestParseBundleErrorDoesNotEchoPayload(t *testing.T) {
	secret := "SUPERSECRETKEYMATERIALDONOTLOG=="
	malformed := []byte("version: 1\ninstance: prod\nscopes:\n  - name: app\n     key: " + secret + "\n\t bad indent\n")
	_, err := ParseBundle(malformed)
	if err == nil {
		t.Fatal("ParseBundle accepted malformed YAML")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the parse error quoted the payload: %v", err)
	}
}

func TestBundleStringRedacts(t *testing.T) {
	scope := mustScope(t, "app", "app/")
	kek, _ := scope.Keyring().ActiveKEK()
	b, err := NewBundle("prod", 3, []Scope{scope})
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	rendered := b.String()
	if strings.Contains(rendered, string(kek.key)) {
		t.Fatal("Bundle.String leaked key material")
	}
	for _, want := range []string{"prod", "app", "3"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("Bundle.String should still report %q: %s", want, rendered)
		}
	}
}

func TestBundleZeroWipesMaterial(t *testing.T) {
	scope := mustScope(t, "app", "app/")
	kek, _ := scope.Keyring().ActiveKEK()
	// Hold a reference to the same backing array the bundle carries.
	material := kek.key
	if allZero(material) {
		t.Fatal("guard: freshly minted key material is already zero")
	}
	b, err := NewBundle("prod", 1, []Scope{scope})
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	b.Zero()
	if !allZero(material) {
		t.Error("Zero left key material in the heap")
	}
	if _, err := b.Marshal(); !errors.Is(err, ErrBundleInvalid) {
		t.Error("a zeroed bundle must refuse to marshal")
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
