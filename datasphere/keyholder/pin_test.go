package keyholder

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/sofmon/farcast/datasphere"
)

func keyID(t *testing.T, s string) datasphere.KeyID {
	t.Helper()
	id, err := datasphere.ParseKeyID(s)
	if err != nil {
		t.Fatalf("ParseKeyID(%q): %v", s, err)
	}
	return id
}

func TestParsePin(t *testing.T) {
	a, b := "00000000000000aa", "00000000000000bb"
	for _, raw := range []string{"", "  \n\t"} {
		if _, present, err := ParsePin(raw); present || err != nil {
			t.Errorf("ParsePin(%q) = present %v, %v; want absent", raw, present, err)
		}
	}
	p, present, err := ParsePin(`{"version":1,"require":["` + b + `","` + a + `","` + a + `"],"retired":null,"later":"ignored"}`)
	if err != nil || !present {
		t.Fatalf("a valid pin: present %v, %v", present, err)
	}
	if len(p.Require) != 2 || p.Require[0].String() != a || p.Require[1].String() != b || len(p.Retired) != 0 {
		t.Errorf("parsed %+v; want the two ids sorted and deduplicated, nothing retired", p)
	}
	for name, raw := range map[string]string{
		"not json":      `{"version":1,`,
		"version 2":     `{"version":2,"require":[],"retired":[]}`,
		"no version":    `{"require":[],"retired":[]}`,
		"short id":      `{"version":1,"require":["aa"],"retired":[]}`,
		"non-hex id":    `{"version":1,"require":[],"retired":["zzzzzzzzzzzzzzzz"]}`,
		"oversize":      `{"version":1,"require":[],"retired":[],"pad":"` + strings.Repeat("x", MaxPinBytes) + `"}`,
		"wrong type":    `{"version":1,"require":"` + a + `","retired":[]}`,
		"a bare string": `"` + a + `"`,
	} {
		if _, present, err := ParsePin(raw); err == nil || !present {
			t.Errorf("%s: present %v, err %v; want present and refused", name, present, err)
		}
	}
}

// Two pins that admit the same bundles are the same bytes: the CLI compares
// before it writes, and the ConfigMap is compared-and-swapped on its value.
func TestPinMarshalIsCanonical(t *testing.T) {
	a, b := keyID(t, "00000000000000aa"), keyID(t, "00000000000000bb")
	one := Pin{Require: []datasphere.KeyID{b, a, b}}
	two := Pin{Require: []datasphere.KeyID{a, b}, Retired: []datasphere.KeyID{}}
	if one.Marshal() != two.Marshal() {
		t.Errorf("%s != %s", one.Marshal(), two.Marshal())
	}
	want := `{"version":1,"require":["00000000000000aa","00000000000000bb"],"retired":[]}`
	if got := one.Marshal(); got != want {
		t.Errorf("Marshal = %s, want %s", got, want)
	}
	back, present, err := ParsePin(one.Marshal())
	if err != nil || !present || !back.Equal(one) {
		t.Errorf("round trip = %+v, %v, %v", back, present, err)
	}
	if u := one.Union(Pin{Retired: []datasphere.KeyID{a}}); len(u.Require) != 2 || len(u.Retired) != 1 {
		t.Errorf("Union = %+v", u)
	}
	if one.Equal(Pin{Require: []datasphere.KeyID{a}}) {
		t.Error("pins requiring different keys compare equal")
	}
}

func TestPinAdmits(t *testing.T) {
	a, b, c := "00000000000000aa", "00000000000000bb", "00000000000000cc"
	keys := map[string][]string{"app-apps-web": {b, a}, "app-apps-api": {c}}

	if err := (Pin{}).Admits(keys); err != nil {
		t.Errorf("an empty pin refused: %v", err)
	}
	if err := (Pin{}).Admits(nil); err != nil {
		t.Errorf("an empty pin refused an empty bundle: %v", err)
	}
	full := Pin{Require: []datasphere.KeyID{keyID(t, a), keyID(t, b), keyID(t, c)}, Retired: []datasphere.KeyID{keyID(t, a)}}
	if err := full.Admits(keys); err != nil {
		t.Errorf("a bundle holding every pinned key, writing under none retired, was refused: %v", err)
	}

	missing := Pin{Require: []datasphere.KeyID{keyID(t, "00000000000000dd")}}
	if err := missing.Admits(keys); !errors.Is(err, ErrBelowPin) || !strings.Contains(err.Error(), "00000000000000dd") {
		t.Errorf("a bundle lacking a pinned key = %v; want ErrBelowPin naming it", err)
	}
	retired := Pin{Retired: []datasphere.KeyID{keyID(t, b)}}
	if err := retired.Admits(keys); !errors.Is(err, ErrBelowPin) || !strings.Contains(err.Error(), b) {
		t.Errorf("a scope writing under a retired key = %v; want ErrBelowPin naming it", err)
	}
	// Retired constrains the ACTIVE key only. An older key stays held so
	// that what was written under it stays readable.
	if err := (Pin{Retired: []datasphere.KeyID{keyID(t, a)}}).Admits(keys); err != nil {
		t.Errorf("a retired key held but not active was refused: %v", err)
	}
}

// The pin's limit, pinned so that nobody claims otherwise. A key ID is a label,
// not a commitment to a key: a bundle with junk material under a pinned ID is
// admitted. What refuses that from a keeper is the bundle binding on its leaf
// (TestAKeeperPushesOnlyTheBundleItsLeafBinds), not the pin.
func TestThePinAdmitsAForgedKeyUnderAPinnedLabel(t *testing.T) {
	k := appKeyring(t, "apps", "web")
	current, rotations, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	pinned := rotations[0].Active
	pin := Pin{Require: []datasphere.KeyID{pinned}}
	if err := pin.Admits(KeysOf(bundleOf(t, 1, current))); err != nil {
		t.Fatalf("the honest bundle was refused: %v", err)
	}

	// A stale keyring rotated by someone else: its new key is junk, and its
	// label is replaced with the pinned one.
	var forged *datasphere.Bundle
	for range 32 {
		junk, junkRot, err := k.RotateScopeKEKs()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := bundleOf(t, 1, junk).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		raw = bytes.ReplaceAll(raw, []byte(junkRot[0].Active.String()), []byte(pinned.String()))
		if forged, err = datasphere.ParseBundle(raw); err == nil {
			break
		}
		// An all-digit ID is quoted in YAML and the swap breaks it; mint
		// another.
	}
	if forged == nil {
		t.Fatal("could not build the forged bundle")
	}
	if err := pin.Admits(KeysOf(forged)); err != nil {
		t.Errorf("the forged bundle was refused (%v) — if the pin now binds material, update ADR 0008 and this test", err)
	}
}
