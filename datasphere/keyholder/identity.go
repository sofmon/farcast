package keyholder

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/sofmon/farcast/datasphere"
)

// Identity on the data path — ADR 0018 decision 1.
//
// Until this file existed the data listener authenticated the server only, and
// a caller was admitted by network position: a NetworkPolicy limited the port
// to application pods, and the scope a request named travelled in a header
// every application was given identically. ADR 0017 drew the consequence —
// applications in one instance could read each other's objects, and no scheme
// that handed out more scope NAMES could fix it, because a name the caller
// declares is a label, not a boundary.
//
// Now the caller presents a leaf from the instance CA, the leaf's URI names a
// role, and what the caller may reach is derived from the role. The scope
// header remains as a cross-check the keyholder refuses on mismatch; it is no
// longer an authorization input. The formats mirror fatline/identity — the
// modules mirror shapes, they do not import each other — and a test asserts
// the two agree.

// Role is what a leaf's URI says its holder is.
type Role string

const (
	// RoleOperator is the operator's own machine: the CA key and the keyring
	// live beside this leaf, so it is served everything the keyholder holds.
	RoleOperator Role = "operator"
	// RoleKeeper is a keeper device. It re-seeds and reports, and is REFUSED
	// on the data path: a keeper leaf never reads (ADR 0018 decision 2).
	RoleKeeper Role = "keeper"
	// RoleDevice is a thin device — a tablet, a second machine — holding a
	// leaf and no keyring. Served every scope the keyholder holds, and never
	// admitted to the control surface: a data leaf never pushes.
	RoleDevice Role = "device"
	// RoleApp is a deployed application, served the scope its identity is
	// entitled to and nothing else.
	RoleApp Role = "app"
)

// Identity is a parsed leaf URI.
type Identity struct {
	Role     Role
	Instance string
	// Name is the device name for a keeper or device, and the application
	// name for an app. Namespace is set for an app only.
	Name      string
	Namespace string
}

// ErrNotAuthorized reports a caller the data path identified and will not
// serve for this key. It reaches an application as the frozen "permission"
// code: this caller may not touch that key.
var ErrNotAuthorized = errors.New("keyholder: this identity is not authorized for that key")

// ErrNoIdentity reports a data-path request that carried no client leaf.
//
// It can only arise when the listener was configured without mutual TLS —
// DataTLS makes the handshake itself refuse — so it is the guard against a
// composition root wiring the handler behind the wrong listener, rather than
// a condition an application should ever see.
var ErrNoIdentity = errors.New("keyholder: the data path requires a client identity")

// ParseIdentity reads a leaf URI for one instance.
//
// A URI for another instance is refused twice over. The prefix check below
// refuses it by name, with an error that says so; and even without that check
// the shape switch would refuse it, because a URI whose prefix was not
// stripped matches no role. Mutation testing found the first is therefore not
// load-bearing for refusal — only for the message — and that is recorded here
// rather than left to look like a boundary. The boundary against another
// instance is the CA: a leaf minted for staging never verifies against prod's.
func ParseIdentity(uri, instance string) (Identity, error) {
	prefix := "farcast://" + instance + "/"
	rest, ok := strings.CutPrefix(uri, prefix)
	if !ok || instance == "" {
		return Identity{}, fmt.Errorf("%w: not an identity for this instance", ErrNotAuthorized)
	}
	parts := strings.Split(rest, "/")
	switch {
	case rest == string(RoleOperator):
		return Identity{Role: RoleOperator, Instance: instance}, nil
	case len(parts) == 2 && parts[0] == string(RoleKeeper) && parts[1] != "":
		return Identity{Role: RoleKeeper, Instance: instance, Name: parts[1]}, nil
	case len(parts) == 2 && parts[0] == string(RoleDevice) && parts[1] != "":
		return Identity{Role: RoleDevice, Instance: instance, Name: parts[1]}, nil
	case len(parts) == 3 && parts[0] == string(RoleApp) && parts[1] != "" && parts[2] != "":
		return Identity{Role: RoleApp, Instance: instance, Namespace: parts[1], Name: parts[2]}, nil
	}
	// An unnamed keeper or device, an app with no namespace, an unknown role:
	// all refused. Every principal is named so that one can be revoked alone.
	return Identity{}, fmt.Errorf("%w: unrecognized identity shape", ErrNotAuthorized)
}

// AllowData authorizes the identities admitted to the data path at all.
//
// Operator, device and application leaves are admitted; a keeper leaf is not,
// and the refusal is deliberate rather than an omission. What each admitted
// role may then reach is decided per request by Identity.MayReach — this
// answers only "may this peer speak to storage".
func AllowData(instance string) func(uri string) bool {
	return func(uri string) bool {
		id, err := ParseIdentity(uri, instance)
		if err != nil {
			return false
		}
		return id.Role != RoleKeeper
	}
}

// MayReach reports whether this identity may touch keys in the named scope.
//
// The operator and a device reach every scope the keyholder holds. An
// application reaches the scope it is entitled to — today the shared
// application scope, because that is the only one there is. ADR 0018 decision
// 5 replaces that entitlement with a scope per application; this is the one
// line it changes.
func (id Identity) MayReach(scopeName string) bool {
	switch id.Role {
	case RoleOperator, RoleDevice:
		return true
	case RoleApp:
		return scopeName == datasphere.DefaultScopeName
	default:
		return false
	}
}

// MayTouchSecret reports whether this identity may reach a key under a scope's
// secrets subtree.
//
// The secrets layout is the one subtree whose second segment already names an
// application — <scope>/secrets/<app>/<name> — so it is the one place the data
// path can enforce a per-application boundary before decision 5 gives every
// application its own scope. An application reaches its own secrets and
// nobody else's; the operator and a device reach all of them.
//
// The match is on the application's NAME rather than on namespace and name,
// because that is how `farcast secret set` files them: secrets are per
// instance and application, not per deployment. Two deployments of one
// application share a subtree, and this check does not pretend otherwise.
func (id Identity) MayTouchSecret(scopePrefix, key string) bool {
	if !datasphere.IsSecretsKey(scopePrefix, key) {
		return true
	}
	switch id.Role {
	case RoleOperator, RoleDevice:
		return true
	case RoleApp:
		rest := strings.TrimPrefix(key, scopePrefix+datasphere.SecretsSegment+datasphere.ScopePrefixSuffix)
		owner, _, _ := strings.Cut(rest, datasphere.ScopePrefixSuffix)
		return owner == id.Name
	default:
		return false
	}
}

// identityFrom reads the caller's identity from the TLS connection.
//
// The leaf has already been verified against the instance CA by the
// listener, and its URI already admitted by AllowData, so this is a parse and
// not a check. A request with no peer certificate is refused: it means the
// handler is behind a listener that did not demand one, which is the
// fail-open ADR 0018 decision 1 says must not exist.
func identityFrom(r *http.Request, instance string) (Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return Identity{}, ErrNoIdentity
	}
	for _, u := range r.TLS.PeerCertificates[0].URIs {
		if id, err := ParseIdentity(u.String(), instance); err == nil {
			return id, nil
		}
	}
	return Identity{}, fmt.Errorf("%w: the client leaf carries no identity for this instance", ErrNotAuthorized)
}
