package farcast

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// fakeStore is the substrate a secretsClient reads through.
type fakeStore struct {
	objects map[string][]byte
	err     error
	read    []string
}

func (f *fakeStore) Read(_ context.Context, key string) ([]byte, error) {
	f.read = append(f.read, key)
	if f.err != nil {
		return nil, f.err
	}
	data, ok := f.objects[key]
	if !ok {
		return nil, ErrObjectNotFound
	}
	return data, nil
}

func (f *fakeStore) Write(context.Context, string, []byte) error    { return ErrPermission }
func (f *fakeStore) List(context.Context, string) ([]string, error) { return nil, ErrPermission }
func (f *fakeStore) Delete(context.Context, string) error           { return ErrPermission }

func testSecrets(objects map[string][]byte) (*secretsClient, *fakeStore) {
	store := &fakeStore{objects: objects}
	return &secretsClient{prefix: "app/secrets/api/", store: store}, store
}

func TestSecretsGetReadsItsOwnSubtree(t *testing.T) {
	c, store := testSecrets(map[string][]byte{"app/secrets/api/DB_PASSWORD": []byte("hunter2")})

	got, err := c.Get(context.Background(), "DB_PASSWORD")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Reveal() != "hunter2" {
		t.Errorf("Reveal = %q, want hunter2", got.Reveal())
	}
	if len(store.read) != 1 || store.read[0] != "app/secrets/api/DB_PASSWORD" {
		t.Errorf("read %v, want the name under the platform's prefix", store.read)
	}
}

// Absence is absence. The substrate's vocabulary stops at the capability
// boundary so the store underneath can change without breaking applications.
func TestSecretsAbsenceIsItsOwnSentinel(t *testing.T) {
	c, _ := testSecrets(nil)

	_, err := c.Get(context.Background(), "DB_PASSWORD")
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("Get err = %v, want ErrSecretNotFound", err)
	}
	if errors.Is(err, ErrObjectNotFound) {
		t.Error("the storage sentinel crossed into the secrets capability")
	}
}

// A sealed instance must not read as "no such secret": one says wait, the
// other says proceed without it.
func TestSecretsPassSealAndFailureThrough(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"sealed", ErrStorageSealed},
		{"unavailable", ErrStorageUnavailable},
		{"permission", ErrPermission},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStore{err: tc.err}
			c := &secretsClient{prefix: "app/secrets/api/", store: store}
			_, err := c.Get(context.Background(), "TOKEN")
			if !errors.Is(err, tc.err) {
				t.Errorf("Get err = %v, want %v", err, tc.err)
			}
			if errors.Is(err, ErrSecretNotFound) {
				t.Error("a failure was reported as absence")
			}
		})
	}
}

// A name is appended to the prefix, so a separator in it addresses a subtree
// this application was not given. It is refused locally, before any call.
func TestSecretsRefuseMalformedNamesWithoutCalling(t *testing.T) {
	bad := []string{
		"", "../../master/key", "a/b", "DB PASSWORD", "sh|ell",
		".hidden", "trailing.", "a..b", strings.Repeat("x", MaxSecretNameLen+1),
	}
	for _, name := range bad {
		c, store := testSecrets(nil)
		_, err := c.Get(context.Background(), name)
		if err == nil {
			t.Errorf("Get(%q) succeeded, want a refusal", name)
		}
		// Not absence: a malformed name is a programming error, and an
		// application that read it as "no such secret" would carry on.
		if errors.Is(err, ErrSecretNotFound) {
			t.Errorf("Get(%q) reported absence", name)
		}
		if len(store.read) != 0 {
			t.Errorf("Get(%q) reached the keyholder: %v", name, store.read)
		}
	}
	for _, name := range []string{"A", "DB_PASSWORD", "api.key", "token-2", "x"} {
		if !validSecretName(name) {
			t.Errorf("validSecretName(%q) = false, want true", name)
		}
	}
}

// Every route fmt, slog and encoding/json take to a value.
func TestSecretRedactsEverywhere(t *testing.T) {
	s := NewSecret("hunter2")

	for _, format := range []string{"%v", "%s", "%q", "%d", "%#v", "%+v", "%x"} {
		out := fmt.Sprintf(format, s)
		if strings.Contains(out, "hunter2") {
			t.Errorf("%s printed the value: %s", format, out)
		}
		if !strings.Contains(out, Redacted) {
			t.Errorf("%s = %q, want it redacted", format, out)
		}
	}
	if got := s.String(); got != Redacted {
		t.Errorf("String = %q, want %q", got, Redacted)
	}
	// A Secret nested in a struct printed with %v is the realistic accident.
	holder := struct{ Token Secret }{Token: s}
	if out := fmt.Sprintf("%v %+v %#v", holder, holder, holder); strings.Contains(out, "hunter2") {
		t.Errorf("a nested Secret printed the value: %s", out)
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "token", s, "any", slog.AnyValue(s))
	if strings.Contains(buf.String(), "hunter2") {
		t.Errorf("slog logged the value: %s", buf.String())
	}
}

// Marshalling fails rather than redacting: a well-formed document containing
// "[redacted]" where a working value was meant is discovered at the far end of
// whatever consumed it.
func TestSecretRefusesToSerialize(t *testing.T) {
	s := NewSecret("hunter2")

	if _, err := json.Marshal(s); !errors.Is(err, ErrSecretSerialization) {
		t.Errorf("json.Marshal err = %v, want ErrSecretSerialization", err)
	}
	blob, err := json.Marshal(struct {
		Token Secret `json:"token"`
	}{Token: s})
	if err == nil {
		t.Errorf("marshalling a struct containing a Secret succeeded: %s", blob)
	}
	if _, err := s.MarshalText(); !errors.Is(err, ErrSecretSerialization) {
		t.Errorf("MarshalText err = %v, want ErrSecretSerialization", err)
	}
}

func TestSecretEqualAndEmpty(t *testing.T) {
	s := NewSecret("hunter2")
	if !s.Equal("hunter2") {
		t.Error("Equal = false for the same value")
	}
	if s.Equal("hunter3") || s.Equal("") || s.Equal("hunter22") {
		t.Error("Equal = true for a different value")
	}
	if s.Empty() {
		t.Error("Empty = true for a set secret")
	}
	if !(Secret{}).Empty() {
		t.Error("Empty = false for the zero Secret")
	}
}

func TestSecretsWiringFromTheEnvironment(t *testing.T) {
	t.Run("no prefix is the stub", func(t *testing.T) {
		t.Setenv(envSecretsPrefix, "")
		if _, ok := newSecretsFromEnv().(secretsStub); !ok {
			t.Error("an unset prefix did not yield the stub")
		}
	})

	t.Run("a prefix without the reserved segment is refused", func(t *testing.T) {
		// The segment is what the keyholder keys its write refusal on. A
		// prefix without it points this capability at ordinary storage while
		// still calling itself Secrets.
		for _, prefix := range []string{"app/", "app/config/api/", "app/secrets/api", "app//secrets/api/", "app/../secrets/"} {
			if err := validSecretsPrefix(prefix); err == nil {
				t.Errorf("validSecretsPrefix(%q) = nil, want a refusal", prefix)
			}
		}
		if err := validSecretsPrefix("app/secrets/api/"); err != nil {
			t.Errorf("validSecretsPrefix on a well-formed prefix: %v", err)
		}
	})

	t.Run("a prefix with no keyholder is broken, not unimplemented", func(t *testing.T) {
		t.Setenv(envSecretsPrefix, "app/secrets/api/")
		t.Setenv(envStorageEndpoint, "")
		// Storage() memoizes, so the wiring is exercised through the same
		// decision newSecretsFromEnv makes rather than through the accessor.
		if _, unwired := newStorageFromEnv().(storageStub); !unwired {
			t.Fatal("the test environment has storage wired; this case needs it absent")
		}
		s := newSecretsFromEnv()
		_, err := s.Get(context.Background(), "TOKEN")
		if errors.Is(err, ErrNotImplemented) {
			t.Error("a configured secrets prefix with no keyholder reported ErrNotImplemented, which sends an operator to the roadmap instead of to the missing variable")
		}
		if !errors.Is(err, ErrStorageUnavailable) {
			t.Errorf("Get err = %v, want ErrStorageUnavailable", err)
		}
		if !strings.Contains(err.Error(), envStorageEndpoint) {
			t.Errorf("the error does not name the missing variable: %v", err)
		}
	})
}
