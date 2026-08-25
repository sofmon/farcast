package planck

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrRegistryUnsupported is returned when a provider has no instance registry.
//
// RegistryProvider is optional, so callers type-assert a Provider and return
// this when the assertion fails. Failing here — at install, on the operator's
// machine — is far better than the alternative: a cluster that only reveals it
// has nowhere to pull images from when the first Pod hits ImagePullBackOff.
var ErrRegistryUnsupported = errors.New("planck: provider does not support an instance registry")

// RegistryProvider is an optional Provider capability: the per-instance
// container image registry the instance owns (ADR 0007).
//
// It exists because zero-central-dependency forbids the instance from pulling
// its own system images out of a feed a third party controls — that would make
// FarCast's security boundary depend on someone else's artifact server. Instead
// each instance owns a registry inside its own cloud project, the operator's
// machine builds from Git and pushes to it, and only the instance's own cluster
// pulls from it.
//
// The surface is deliberately three methods wide, and what it promises is an
// image-path *prefix* plus a credential — not "one repository object". That is
// what lets a future ECR adapter (repo-per-image, no single container resource)
// realize the same contract without changing any caller.
//
// A cloud whose adapter cannot host images stays a perfectly valid Provider;
// callers degrade with ErrRegistryUnsupported rather than losing the cluster
// lifecycle.
type RegistryProvider interface {
	// EnsureRegistry idempotently creates the instance's registry and grants
	// the cluster's nodes read access to it. Safe to call repeatedly.
	//
	// Repeatable by design: `farcast install` ensures the registry once, and
	// every later `farcast connect` re-ensures it defensively, so an instance
	// created before it had a registry converges on the next reconnect instead
	// of breaking.
	EnsureRegistry(ctx context.Context, spec RegistrySpec) (*Registry, error)

	// DeleteRegistry removes the registry and everything in it. Deleting an
	// absent registry is not an error (idempotent teardown).
	//
	// Nothing sovereign is lost: every image in it is derivable from Git. What
	// would be lost by *keeping* it is money — a registry that outlives its
	// instance is billable storage nobody is watching, which the cost pillar
	// does not tolerate.
	DeleteRegistry(ctx context.Context, ref RegistryRef) error

	// RegistryToken mints a short-lived credential for pushing to and pulling
	// from the instance's registry.
	//
	// Short-lived and in-process is the contract, not an implementation
	// detail: the caller pushes with it and drops it. It is never written to a
	// container engine's credential store, a temp file, or a command line —
	// a push credential for the instance's registry is a supply-chain foothold
	// on everything the cluster runs.
	RegistryToken(ctx context.Context) (RegistryToken, error)
}

// RegistrySpec describes the registry to ensure.
type RegistrySpec struct {
	Name     string            // instance name; the registry is named for it
	Location string            // region; the provider default applies if empty
	Cluster  ClusterRef        // the cluster whose nodes must be able to pull
	Labels   map[string]string // optional cloud resource labels
}

// RegistryRef identifies a registry for teardown.
type RegistryRef struct {
	Name     string
	Location string
}

// Registry is an ensured instance registry.
type Registry struct {
	Ref    RegistryRef
	Prefix string // image-path prefix, e.g. us-central1-docker.pkg.dev/proj/farcast-x
	Puller string // principal granted pull access, recorded for transparency
}

// RegistryToken is a short-lived registry credential. Password is sensitive.
type RegistryToken struct {
	Username string
	Password string
	Expiry   time.Time
}

// String renders the token without leaking the password, so accidental logging
// (%v/%s) cannot expose a credential that can push images into the instance's
// registry — the one place from which the cluster runs code.
func (t RegistryToken) String() string {
	pw := "<none>"
	if t.Password != "" {
		pw = fmt.Sprintf("<redacted %d bytes>", len(t.Password))
	}
	return fmt.Sprintf("RegistryToken{Username:%s Password:%s Expiry:%s}",
		t.Username, pw, t.Expiry.Format(time.RFC3339))
}
