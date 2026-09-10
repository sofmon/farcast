package farcast

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// SecretsAPI provides read access to this application's secrets.
//
// A secret is provisioned by the operator and stored in DataSphere, so it is
// encrypted before the cloud sees it and it never exists as a Kubernetes
// Secret — which is base64 in etcd, encrypted at rest by a key the cloud
// provider holds. See docs/adr/0017-application-secrets.md for what that does
// and does not protect against; the short version is that the boundary this
// buys is the INSTANCE, not the application.
//
// The interface has one method on purpose. Applications fake it in their own
// tests, so every method added here breaks every one of those fakes, and a
// read is the only thing an application does with a secret: provisioning is an
// operator act (`farcast secret set`), and the keyholder refuses writes to the
// secrets subtree from the application data path.
type SecretsAPI interface {
	// Get returns the secret stored under name.
	//
	// It reports ErrSecretNotFound when there is no such secret, and
	// ErrStorageSealed while the instance's keyholder holds no key material —
	// a normal, temporary state that clears when an operator (or, from 5.4, a
	// keeper device) unseals. Neither is a reason to proceed without the
	// secret.
	Get(ctx context.Context, name string) (Secret, error)
}

// Secret is a secret value that refuses to print itself.
//
// It is a distinct type rather than a string because the overwhelmingly common
// way a secret escapes is not an attacker — it is a log line, an error
// message, or a struct that got marshalled into a response. Every route fmt,
// slog and encoding/json take to a value is closed here: printing yields
// "[redacted]", logging yields "[redacted]", and marshalling FAILS rather than
// quietly emitting either the value or a placeholder that a caller might ship
// to a client as if it were real.
//
// Reveal is the one way out, and it is deliberately a verb an author has to
// type — and that a reviewer can grep for.
type Secret struct{ value string }

// NewSecret wraps a value that is already in hand.
//
// It exists so an application can fake SecretsAPI in its own tests, and so
// code that obtains a secret by some other route (a file it was handed, a
// value from another library) can put it behind the same redaction.
func NewSecret(value string) Secret { return Secret{value: value} }

// Reveal returns the secret value.
func (s Secret) Reveal() string { return s.value }

// Empty reports whether the secret holds no value.
func (s Secret) Empty() bool { return s.value == "" }

// Equal reports whether the secret equals want, in constant time.
//
// It is here so the common comparison — an inbound token against a stored one
// — does not need Reveal, and does not leak the answer through how long it
// took. Length is not secret: the comparison is over the raw bytes and an
// unequal length is reported without reading them.
func (s Secret) Equal(want string) bool {
	return subtle.ConstantTimeCompare([]byte(s.value), []byte(want)) == 1
}

// Redacted is what a Secret prints as, everywhere.
const Redacted = "[redacted]"

// String implements fmt.Stringer.
func (Secret) String() string { return Redacted }

// GoString implements fmt.GoStringer, which is what %#v uses. Without it the
// verb prints the struct's fields — the one printing route a String method
// does not cover.
func (Secret) GoString() string { return "farcast.Secret{" + Redacted + "}" }

// Format implements fmt.Formatter so that EVERY verb redacts, not just the
// ones that consult Stringer. %d on a Secret is a programming error, and it
// must not answer it by dumping the value.
func (s Secret) Format(f fmt.State, verb rune) {
	switch verb {
	case 'q':
		_, _ = fmt.Fprintf(f, "%q", Redacted)
	case 'v':
		if f.Flag('#') {
			_, _ = f.Write([]byte(s.GoString()))
			return
		}
		_, _ = f.Write([]byte(Redacted))
	default:
		_, _ = f.Write([]byte(Redacted))
	}
}

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// ErrSecretSerialization is returned by a Secret's marshallers.
//
// Redacting instead would be worse than failing: the caller would ship a
// well-formed document containing "[redacted]" where a working value was
// meant, and discover it at the far end of whatever consumed it. Failing says
// so at the point the mistake was made.
var ErrSecretSerialization = errors.New("farcast: a Secret must not be serialized; call Reveal explicitly if that is what you mean")

// MarshalJSON refuses. See ErrSecretSerialization.
func (Secret) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText refuses, which also covers encoders that reach for it — YAML,
// TOML, and url.Values among them.
func (Secret) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

var (
	_ fmt.Stringer   = Secret{}
	_ fmt.GoStringer = Secret{}
	_ fmt.Formatter  = Secret{}
	_ slog.LogValuer = Secret{}
)

// Secrets returns the secrets capability.
//
// It is configured from the environment on first use. Outside a FarCast
// instance — or in a build the platform has not wired secrets into — Get
// reports ErrNotImplemented, so an application compiles and runs against the
// full surface before any secret exists.
func Secrets() SecretsAPI {
	secretsOnce.Do(func() { secretsCapability = newSecretsFromEnv() })
	return secretsCapability
}

var (
	secretsOnce       sync.Once
	secretsCapability SecretsAPI
)

var _ SecretsAPI = secretsStub{}

type secretsStub struct{}

func (secretsStub) Get(context.Context, string) (Secret, error) {
	return Secret{}, ErrNotImplemented
}

// MaxSecretNameLen bounds a secret's name. A name is an identifier an
// application types into its own source, not a filing system.
const MaxSecretNameLen = 128

// validSecretName reports whether name is one this SDK will send.
//
// The rules are checked locally and before any network call, and the one that
// carries weight is the absence of "/": a secret's name is appended to the
// prefix the platform gave this application, and a name containing a separator
// would address a different subtree. The rest keeps names to something an
// operator can type into a shell without quoting, which is where they are set.
func validSecretName(name string) bool {
	if name == "" || len(name) > MaxSecretNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_' || c == '-' || c == '.':
			// Never at the edges: a leading dot hides a name and a trailing
			// one reads as a truncation.
			if i == 0 || i == len(name)-1 {
				return false
			}
		default:
			return false
		}
	}
	return !strings.Contains(name, "..")
}
