package farcast

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// ConfigAPI provides access to non-secret configuration: environment
// defaults and per-application values. Secrets are a separate capability
// (farcast.Secrets) and never flow through configuration.
type ConfigAPI interface {
	// Get returns the raw string value for key and whether it was present.
	Get(key string) (string, bool)
	// GetString returns the value for key, or def if it is absent.
	GetString(key, def string) string
	// GetInt returns the value for key parsed as an int, or def if it is
	// absent or unparseable.
	GetInt(key string, def int) int
	// GetBool returns the value for key parsed as a bool, or def if it is
	// absent or unparseable.
	GetBool(key string, def bool) bool
	// Require returns the value for key, or an error if it is absent.
	Require(key string) (string, error)
}

// Config returns the configuration capability: the process environment, which
// is where the platform puts an application's configuration (Planck renders a
// ConfigMap per application and hands it to the container wholesale).
//
// It reads the environment on every call rather than snapshotting it at first
// use. Nothing in a container changes an environment variable after start, so
// the two are the same in production; reading live is what makes an
// application's own tests able to set a variable and see it.
func Config() ConfigAPI { return envConfig{} }

var _ ConfigAPI = envConfig{}

type envConfig struct{}

// reservedPrefix is the platform's own namespace in the environment.
//
// Config refuses to return anything under it, and the refusal is a security
// boundary rather than tidiness. FARCAST_FATLINE_PROXY carries this
// application's egress credential (ADR 0013) — it is injected from a
// Kubernetes Secret precisely because it is one — and a capability documented
// as "non-secret configuration" that hands it back is a capability that will
// eventually log it. The rest of the namespace is wiring the accessors
// already expose properly: identity through AppName and InstanceID, the
// keyholder through Storage, the secrets prefix through Secrets.
//
// So an application cannot reach the platform's variables through Config. It
// can still call os.Getenv — this is a guard rail on the SDK's own surface,
// not a sandbox, and claiming otherwise would be the kind of security theatre
// that makes a reader trust the wrong thing.
const reservedPrefix = "FARCAST_"

// Reserved reports whether key belongs to the platform's namespace, and is
// therefore not readable through Config.
//
// It is exported so an application that builds its own configuration layer
// over os.Environ can exclude the same set — a "dump my configuration"
// endpoint is the classic way an injected credential reaches a log.
func Reserved(key string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(key)), reservedPrefix)
}

// lookup is the one place a value is read, so every method shares one answer
// to "what counts as present".
//
// A variable set to the empty string counts as ABSENT. That is a deliberate
// reading: an empty value is what a mis-rendered template, an unset shell
// variable, or a ConfigMap key with nothing after the colon produces, and it
// is essentially never what someone meant to configure. Treating it as
// present would make Require — whose entire job is to catch configuration
// that did not arrive — hand back "" and let the application start with an
// empty database URL. Every caller would then have to re-check for "".
func (envConfig) lookup(key string) (string, bool) {
	if key == "" || Reserved(key) {
		return "", false
	}
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return "", false
	}
	return v, true
}

func (c envConfig) Get(key string) (string, bool) { return c.lookup(key) }

func (c envConfig) GetString(key, def string) string {
	if v, ok := c.lookup(key); ok {
		return v
	}
	return def
}

// GetInt parses the value as a base-10 integer.
//
// Surrounding whitespace is trimmed before parsing but never trimmed from
// what GetString returns: an invisible trailing space is a transcription
// artefact when a number was meant, and possibly meaningful when a string
// was.
func (c envConfig) GetInt(key string, def int) int {
	v, ok := c.lookup(key)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		unparseable(key, "an integer")
		return def
	}
	return n
}

// GetBool parses the value with strconv.ParseBool: 1, t, T, TRUE, true, True
// and their false counterparts.
func (c envConfig) GetBool(key string, def bool) bool {
	v, ok := c.lookup(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		unparseable(key, "a boolean")
		return def
	}
	return b
}

func (c envConfig) Require(key string) (string, error) {
	if v, ok := c.lookup(key); ok {
		return v, nil
	}
	if Reserved(key) {
		// The distinction is worth spending an error message on: the variable
		// may well be set, and an operator told "not set" would go and set it
		// again.
		return "", fmt.Errorf("farcast: config %q: %w", key, ErrConfigReserved)
	}
	return "", fmt.Errorf("farcast: config %q: %w", key, ErrConfigMissing)
}

// warned remembers which keys have already been reported, so a getter called
// once per request reports a misconfiguration once rather than once per
// request. A bad value is a fact about the deployment, not about the call.
var warned sync.Map

// unparseable reports a value that was present and could not be read.
//
// Falling back to the default silently is what the frozen ConfigAPI contract
// requires — these getters return no error — but doing it in silence makes a
// typo undiagnosable: the application runs on a default it was explicitly
// told not to use, and nothing anywhere says so.
//
// The KEY is named and the VALUE never is. Config is documented as non-secret
// and the reserved namespace is refused, but an application's own
// configuration is the application's business, and a warning is not the place
// to decide that some operator's connection string is safe to print.
func unparseable(key, want string) {
	if _, dup := warned.LoadOrStore(key, struct{}{}); dup {
		return
	}
	Log().Warn(context.Background(),
		"configuration value could not be parsed; using the default",
		"key", key, "want", want)
}
