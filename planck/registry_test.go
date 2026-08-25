package planck

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRegistryTokenStringRedactsPassword(t *testing.T) {
	tok := RegistryToken{
		Username: "oauth2accesstoken",
		Password: "ya29.SUPER-SECRET-ACCESS-TOKEN",
		Expiry:   time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
	}
	s := tok.String()
	if strings.Contains(s, "SUPER-SECRET-ACCESS-TOKEN") {
		t.Errorf("String() leaked the password: %s", s)
	}
	if !strings.Contains(s, "oauth2accesstoken") {
		t.Errorf("String() = %q, want the username", s)
	}
	if !strings.Contains(s, "2026-08-25") {
		t.Errorf("String() = %q, want the expiry", s)
	}
}

// TestRegistryTokenStringEmpty guards the zero value: a token nobody minted
// must not render as if it carried a credential.
func TestRegistryTokenStringEmpty(t *testing.T) {
	if s := (RegistryToken{}).String(); !strings.Contains(s, "<none>") {
		t.Errorf("String() = %q, want it to report an absent password", s)
	}
}

func TestErrRegistryUnsupported(t *testing.T) {
	err := errors.New("wrapped: " + ErrRegistryUnsupported.Error())
	if errors.Is(err, ErrRegistryUnsupported) {
		t.Fatal("a same-text error must not satisfy errors.Is — the sentinel is identity, not text")
	}
	if !errors.Is(ErrRegistryUnsupported, ErrRegistryUnsupported) {
		t.Fatal("the sentinel must match itself")
	}
}

// TestProviderMayNotImplementRegistryProvider pins the capability's optional
// shape: a plain Provider stays valid and callers detect the gap by assertion.
func TestProviderMayNotImplementRegistryProvider(t *testing.T) {
	var p Provider = fakeProvider{name: "plain"}
	if _, ok := p.(RegistryProvider); ok {
		t.Fatal("fakeProvider should not satisfy RegistryProvider")
	}
}
