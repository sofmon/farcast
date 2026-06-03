// Package planck is FarCast's compute abstraction over managed Kubernetes.
// It exposes a single cloud-agnostic Provider interface for the lifecycle of
// a managed cluster, plus a small registry so adapters (GKE first; EKS, AKS
// later) self-register and are reached through Open.
//
// See README.md in this directory and docs/adr/0003-gke-autopilot.md for the
// design and the GKE Autopilot decision.
package planck

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// ErrClusterNotFound is returned by status queries for a cluster that does
// not exist.
var ErrClusterNotFound = errors.New("planck: cluster not found")

// Factory builds a Provider from its configuration.
type Factory func(cfg Config) (Provider, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register adds a provider factory under name. Adapters call it from their
// init(). It panics on an empty name, a nil factory, or a duplicate — all
// programmer errors.
func Register(name string, f Factory) {
	if name == "" || f == nil {
		panic("planck: Register requires a non-empty name and non-nil factory")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[name]; dup {
		panic("planck: duplicate provider " + name)
	}
	registry[name] = f
}

// Open constructs the registered provider named name with cfg.
func Open(name string, cfg Config) (Provider, error) {
	registryMu.RLock()
	f, ok := registry[name]
	registryMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("planck: unknown provider %q (registered: %v); did you blank-import planck/providers?", name, Providers())
	}
	return f(cfg)
}

// Providers returns the registered provider names, sorted.
func Providers() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
