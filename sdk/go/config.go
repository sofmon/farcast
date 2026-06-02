package farcast

import "fmt"

// ConfigAPI provides access to non-secret configuration: environment
// defaults and per-application values. Secrets are a separate capability
// (farcast.Secrets, a later phase) and never flow through configuration.
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

// Config returns the configuration capability.
//
// Implementation lands in a later phase; until then this returns a stub
// whose getters yield their defaults and whose Require yields
// ErrNotImplemented.
func Config() ConfigAPI {
	return configStub{}
}

var _ ConfigAPI = configStub{}

type configStub struct{}

func (configStub) Get(string) (string, bool)       { return "", false }
func (configStub) GetString(_, def string) string  { return def }
func (configStub) GetInt(_ string, def int) int    { return def }
func (configStub) GetBool(_ string, def bool) bool { return def }
func (configStub) Require(key string) (string, error) {
	return "", fmt.Errorf("farcast: config %q: %w", key, ErrNotImplemented)
}
