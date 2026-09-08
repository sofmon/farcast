// Package policy is the per-application egress policy an instance's FatLine
// enforces: which applications exist, what each may reach, and the credential
// that identifies each one.
//
// It is the document [ADR 0013] decision 5 puts in a ConfigMap. The operator's
// machine writes it at `farcast run`; FatLine reads it from a mounted file and
// reloads on change. Both sides import this package so the writer and the
// reader cannot disagree about the format — the same reasoning that made
// JobName exported in planck/build.
//
// It carries hashes, never credentials ([ADR 0013] decision 3), so the document
// itself holds no secret material and may be a ConfigMap rather than a Secret.
//
// [ADR 0013]: ../../docs/adr/0013-per-application-egress-identity.md
package policy

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/sofmon/farcast/manifest/parser"
)

// Version is the shape of the document. A FatLine that reads a version it does
// not know refuses the whole document rather than enforcing part of one: a
// partially understood egress policy is a policy nobody can reason about.
const Version = 1

// CredentialBytes is the size of an application's egress credential.
//
// 256 bits, which is what makes decision 3's plain SHA-256 correct rather than
// lazy: at this entropy an offline search is infeasible, so the slow KDF that
// protects a human-chosen password would buy nothing while sitting on the
// per-connection path.
const CredentialBytes = 32

// Document is the whole policy: every application on the instance.
type Document struct {
	Version int   `json:"version"`
	Apps    []App `json:"apps"`
}

// App is one application's identity and its declarations.
type App struct {
	// Name and Namespace identify the application. Namespace is the
	// deployment's namespace, so two deployments may each have an "api".
	Name      string `json:"name"`
	Namespace string `json:"namespace"`

	// CredentialSHA256 is the lowercase hex SHA-256 of the credential this
	// application presents. The credential itself lives only in the
	// application's own Secret and is never written here.
	CredentialSHA256 string `json:"credential_sha256"`

	// External is what this application declared, and the whole of what it may
	// reach. An empty list means it reaches nothing outside the instance,
	// which is a real and common answer rather than a missing one.
	External []parser.External `json:"external,omitempty"`
}

// Tenant is the key an App is enforced under.
//
// Namespaced, because a manifest's top-level name is only unique within an
// instance once the namespace is included — and `farcast run --namespace`
// exists precisely so the same manifest can be deployed twice.
func (a App) Tenant() string { return a.Namespace + "/" + a.Name }

// NewCredential mints an application's egress credential.
func NewCredential() (string, error) {
	b := make([]byte, CredentialBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("policy: mint an egress credential: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashCredential is what the document records for a credential.
func HashCredential(credential string) string {
	sum := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(sum[:])
}

// Identify returns the application a credential belongs to.
//
// The comparison is constant-time over every entry, and it does NOT stop at the
// first match: returning early would make the time taken depend on how far down
// the list the caller's application sits, which leaks the position of a valid
// credential to anything that can time a request.
//
// A username may accompany the credential on the wire and is deliberately
// ignored. It is the caller's own claim about who they are, useful only for
// reading a packet capture, and trusting it would make the credential
// decorative.
func (d *Document) Identify(credential string) (App, bool) {
	if credential == "" {
		return App{}, false
	}
	want := HashCredential(credential)
	var found App
	var ok bool
	for _, app := range d.Apps {
		if subtle.ConstantTimeCompare([]byte(app.CredentialSHA256), []byte(want)) == 1 {
			found, ok = app, true
		}
	}
	return found, ok
}

// ByTenant is the per-tenant declaration map FatLine's allowlist is built from.
func (d *Document) ByTenant() map[string][]parser.External {
	out := make(map[string][]parser.External, len(d.Apps))
	for _, app := range d.Apps {
		out[app.Tenant()] = app.External
	}
	return out
}

// Marshal renders the document, with applications in a stable order so an
// unchanged policy produces an unchanged ConfigMap and a redeploy does not look
// like a change.
func (d *Document) Marshal() ([]byte, error) {
	out := Document{Version: Version, Apps: append([]App(nil), d.Apps...)}
	sort.Slice(out.Apps, func(i, j int) bool { return out.Apps[i].Tenant() < out.Apps[j].Tenant() })
	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("policy: encode: %w", err)
	}
	return append(body, '\n'), nil
}

// Parse reads a document and refuses one it cannot fully enforce.
func Parse(data []byte) (*Document, error) {
	var d Document
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("policy: decode: %w", err)
	}
	if d.Version != Version {
		return nil, fmt.Errorf("policy: document version %d, this build enforces %d; "+
			"refusing to enforce part of a policy it does not fully understand", d.Version, Version)
	}
	seen := map[string]string{}
	for i, app := range d.Apps {
		switch {
		case app.Name == "":
			return nil, fmt.Errorf("policy: apps[%d] has no name", i)
		case app.Namespace == "":
			return nil, fmt.Errorf("policy: app %q has no namespace", app.Name)
		case !isSHA256Hex(app.CredentialSHA256):
			return nil, fmt.Errorf("policy: app %q has no usable credential hash; "+
				"an application FatLine cannot identify would be denied on every request", app.Tenant())
		}
		// Two applications sharing a credential hash would make one of them
		// silently enforce the other's declarations — the exact confusion this
		// whole decision exists to prevent.
		if other, dup := seen[app.CredentialSHA256]; dup {
			return nil, fmt.Errorf("policy: %q and %q share a credential", other, app.Tenant())
		}
		seen[app.CredentialSHA256] = app.Tenant()
	}
	return &d, nil
}

func isSHA256Hex(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := range len(s) {
		switch c := s[i]; {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// ProxyURL is the value an application receives as FARCAST_FATLINE_PROXY.
//
// The credential rides as userinfo, which is the universal HTTP proxy
// convention: Go's net/http sets Proxy-Authorization from it automatically, as
// do curl, requests and Node. That is what makes decision 2 true — an
// application does exactly what it did before, which is read one variable.
//
// The username is the application's name. It authorises nothing and exists so
// that a human reading a connection can tell who it claims to be.
func ProxyURL(scheme, host string, port int, app, credential string) string {
	return fmt.Sprintf("%s://%s:%s@%s:%d", scheme, urlSafe(app), credential, host, port)
}

// urlSafe keeps a name that would need percent-encoding out of the userinfo.
// Manifest names are DNS labels, so this never fires on a valid manifest; it is
// here so that a future name shape cannot silently produce a malformed URL.
func urlSafe(s string) string {
	var b strings.Builder
	for i := range len(s) {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
			b.WriteByte(c)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}
