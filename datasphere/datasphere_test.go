package datasphere

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/sofmon/farcast/datasphere/internal/crypto"
)

// Register mutates package state that no test can undo, so every test here
// registers under a name derived from its own t.Name() and prefixed out of the
// namespace any real adapter would ever claim. Nothing in this file may assume
// it is alone in the registry.
const testProviderPrefix = "test-only-"

func testProviderName(t *testing.T) string {
	t.Helper()
	return testProviderPrefix + t.Name()
}

func registerFake(t *testing.T, name string) {
	t.Helper()
	Register(name, func(Config) (Provider, error) { return newFakeProvider(), nil })
}

func TestRegisterAndOpen(t *testing.T) {
	name := testProviderName(t)
	registerFake(t, name)

	p, err := Open(name, Config{Project: "proj"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if p == nil {
		t.Fatal("Open returned no provider and no error")
	}
	if p.Name() != "fake" {
		t.Errorf("Name() = %q, want the provider the factory built", p.Name())
	}
}

func TestOpenPassesTheConfigToTheFactory(t *testing.T) {
	name := testProviderName(t)
	var got Config
	Register(name, func(cfg Config) (Provider, error) {
		got = cfg
		return newFakeProvider(), nil
	})

	want := Config{
		Credentials: []byte("service-account-json"),
		Project:     "farcast-demo",
		Location:    "europe-west1",
		Extra:       map[string]string{"endpoint": "https://storage.example"},
	}
	if _, err := Open(name, want); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got.Credentials) != string(want.Credentials) || got.Project != want.Project ||
		got.Location != want.Location || got.Extra["endpoint"] != want.Extra["endpoint"] {
		t.Errorf("factory received %+v, want the config Open was called with", got)
	}
}

func TestOpenPropagatesFactoryErrors(t *testing.T) {
	name := testProviderName(t)
	sentinel := errors.New("no usable credentials")
	Register(name, func(Config) (Provider, error) { return nil, sentinel })

	p, err := Open(name, Config{})
	if !errors.Is(err, sentinel) {
		t.Errorf("Open error = %v, want the factory's error", err)
	}
	if p != nil {
		t.Error("Open returned a provider alongside its error")
	}
}

// TestOpenUnknownNamesTheRegisteredSet is the difference between a usable error
// and a dead end: "unknown provider" alone leaves the operator guessing whether
// they mistyped the name or forgot the blank import.
func TestOpenUnknownNamesTheRegisteredSet(t *testing.T) {
	registered := testProviderName(t)
	registerFake(t, registered)

	_, err := Open(testProviderPrefix+"absent", Config{})
	if err == nil {
		t.Fatal("Open of an unregistered provider returned no error")
	}
	msg := err.Error()
	for _, want := range []string{"unknown provider", testProviderPrefix + "absent", registered} {
		if !strings.Contains(msg, want) {
			t.Errorf("error = %q, want it to mention %q", msg, want)
		}
	}
}

func TestProvidersListsRegisteredNamesSorted(t *testing.T) {
	// Registered out of order on purpose: the sort is Providers's job.
	second := testProviderName(t) + "-zulu"
	first := testProviderName(t) + "-alpha"
	registerFake(t, second)
	registerFake(t, first)

	names := Providers()
	if !slices.IsSorted(names) {
		t.Errorf("Providers() = %v, want sorted output", names)
	}
	for _, want := range []string{first, second} {
		if !slices.Contains(names, want) {
			t.Errorf("Providers() = %v, missing %q", names, want)
		}
	}
	// The returned slice is the caller's: mutating it must not reach the
	// registry.
	names[0] = "clobbered"
	if again := Providers(); slices.Contains(again, "clobbered") {
		t.Error("Providers() handed out a slice aliasing the registry")
	}
}

func TestRegisterPanics(t *testing.T) {
	duplicate := testProviderName(t) + "-duplicate"
	registerFake(t, duplicate)

	tests := []struct {
		name string
		call func()
	}{
		{"duplicate name", func() { registerFake(t, duplicate) }},
		{"empty name", func() { Register("", func(Config) (Provider, error) { return newFakeProvider(), nil }) }},
		{"nil factory", func() { Register(testProviderName(t)+"-nil", nil) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("Register with a %s did not panic", tc.name)
				}
			}()
			tc.call()
		})
	}
}

// TestErrorSentinelsAreDistinct guards the vocabulary 3.2 will branch on. The
// pair that matters most is ErrUnknownKey and ErrIntegrity: "your keyring is
// missing a key" and "the stored data was tampered with" demand different
// operator responses, and an adversary picks which one fires, so collapsing
// them would make the two indistinguishable to code as well as to people.
func TestErrorSentinelsAreDistinct(t *testing.T) {
	sentinels := map[string]error{
		"ErrObjectNotFound":  ErrObjectNotFound,
		"ErrIntegrity":       ErrIntegrity,
		"ErrUnknownKey":      ErrUnknownKey,
		"ErrTooLarge":        ErrTooLarge,
		"ErrInvalidKey":      ErrInvalidKey,
		"ErrNotOwned":        ErrNotOwned,
		"ErrRetentionForced": ErrRetentionForced,
		"ErrKeyringInvalid":  ErrKeyringInvalid,
	}
	for aName, a := range sentinels {
		if a == nil {
			t.Errorf("%s is nil", aName)
			continue
		}
		for bName, b := range sentinels {
			if aName == bName {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("errors.Is(%s, %s) is true; the two cannot be told apart", aName, bName)
			}
		}
	}

	// The crypto layer's errors are re-exported by identity rather than
	// wrapped, so a caller classifying against either name gets the same
	// answer.
	if !errors.Is(ErrIntegrity, crypto.ErrIntegrity) ||
		!errors.Is(ErrUnknownKey, crypto.ErrUnknownKey) ||
		!errors.Is(ErrTooLarge, crypto.ErrTooLarge) ||
		!errors.Is(ErrInvalidKey, crypto.ErrInvalidKey) {
		t.Error("the re-exported crypto sentinels are not the same errors")
	}
}

// TestConfigStringRedactsCredentials is the Config half of the redaction
// discipline: a credential that reaches a log has left the operator's control,
// and %v on a struct is the easiest way in the language to put one there.
func TestConfigStringRedactsCredentials(t *testing.T) {
	const secret = "{\"type\":\"service_account\",\"private_key\":\"SUPER-SECRET-PEM\"}"
	cfg := Config{
		Credentials: []byte(secret),
		Project:     "farcast-demo",
		Location:    "europe-west1",
		Extra:       map[string]string{"endpoint": "https://storage.example"},
	}
	secrets := append(secretForms([]byte(secret)), secretForms([]byte("SUPER-SECRET-PEM"))...)

	for _, verb := range []string{"%v", "%s", "%+v"} {
		rendered := fmt.Sprintf(verb, cfg)
		assertNoSecrets(t, "Config "+verb, rendered, secrets)
		if !strings.Contains(rendered, "redacted") {
			t.Errorf("Config %s = %q, want it to say the credentials were redacted", verb, rendered)
		}
		// Redaction has to leave the diagnosable fields behind, or the next
		// engineer reaches for %+v on the struct's fields instead.
		for _, want := range []string{"farcast-demo", "europe-west1"} {
			if !strings.Contains(rendered, want) {
				t.Errorf("Config %s = %q, want it to carry %q", verb, rendered, want)
			}
		}
	}

	// A pointer renders through the same String method — the shape most
	// logging call sites actually take.
	assertNoSecrets(t, "Config pointer %v", fmt.Sprintf("%v", &cfg), secrets)

	// And the zero value renders rather than panicking: redaction that only
	// works on well-formed values fails in exactly the moment something is
	// already going wrong.
	for _, verb := range []string{"%v", "%s", "%+v"} {
		got := fmt.Sprintf(verb, Config{})
		if !strings.Contains(got, "Config{") {
			t.Errorf("zero Config %s = %q, want a rendered Config", verb, got)
		}
		if !strings.Contains(got, "<none>") {
			t.Errorf("zero Config %s = %q, want absent credentials reported as <none>", verb, got)
		}
	}
}
