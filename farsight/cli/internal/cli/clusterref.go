package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strings"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
)

// errCredentialMissing marks a refusal for want of a credential the call
// can use: no reader recorded or uploaded, a reader not yet verified
// read-only, a reader email that is not the derived one, or a missing key
// file. ADR 0023 M2.4 gives it the kind credential_missing.
var errCredentialMissing = errors.New("no usable stored credential")

// clusterRef is what every command hands its cluster seam (ADR 0023 M2,
// design §2.6).
type clusterRef struct {
	Dir      config.Dir
	Meta     *config.InstanceMetadata
	Identity kube.Identity
	Warn     io.Writer // env.Err
	// Verifying lets a reader that is not yet verified read-only open (§3.5).
	// Only readerGrantCommand.newReader's default sets it, for reader grant's
	// own verifying read and reviews (§7.2).
	Verifying bool
}

// refusal is an error whose text is exactly its message and which matches
// its sentinel with errors.Is: openCluster's refusals keep the words §3.5
// gives them, and a caller still tells them apart by sentinel.
type refusal struct {
	msg      string
	sentinel error
}

func (r *refusal) Error() string { return r.msg }
func (r *refusal) Unwrap() error { return r.sentinel }

func refuse(sentinel error, format string, a ...any) error {
	return &refusal{msg: fmt.Sprintf(format, a...), sentinel: sentinel}
}

// openCluster is the one place an instance's cluster client is built (ADR
// 0023 M2, design §3.5). Its steps, in order:
//
//  1. the record must name an endpoint;
//  2. cluster-ca.crt is read, if it exists;
//  3. the endpoint is classified against the region and that CA
//     (kube.ParseEndpoint), refusing anything the endpoint rule does not
//     accept;
//  4. the identity's credential is loaded: for the reader, only once the
//     record names the reader farcast derives for this instance, its key is
//     uploaded, and 'reader grant' has verified it read-only (unless
//     r.Verifying), and then reader.key;
//  5. cluster.Open pairs the endpoint and the credential and builds the
//     client. Nothing is sent before a method is called.
//
// Every refusal before step 5 sends nothing. The writer opens in-process
// from ADR 0023 M2.5; until then this refuses it.
func openCluster(r clusterRef) (*cluster.Client, error) {
	if r.Meta == nil {
		return nil, errors.New("cli: openCluster needs the instance's record")
	}
	meta := r.Meta
	name := meta.Name

	// 1. ADR 0023 M2.4 gives this the kind endpoint_refused, never
	// not_connected, which means no FatLine is recorded.
	if meta.Endpoint == "" {
		return nil, refuse(kube.ErrEndpointRefused, "instance %q records no cluster endpoint; 'farcast install' records one; nothing was sent", name)
	}
	// 2.
	ca, ok, err := r.Dir.LoadClusterCA(name)
	if err != nil {
		return nil, err
	}
	if !ok {
		ca = nil
	}
	// 3.
	ep, err := kube.ParseEndpoint(meta.Endpoint, meta.Region, ca)
	if err != nil {
		return nil, err
	}
	// 4.
	var cred kube.Credential
	switch r.Identity {
	case kube.Reader:
		if cred, err = readerCredential(r, ep); err != nil {
			return nil, err
		}
	case kube.Writer:
		return nil, errors.New("cli: the writer opens in-process from ADR 0023 M2.5")
	default:
		return nil, fmt.Errorf("cli: %q is not one of an instance's identities", r.Identity)
	}
	// 5. The reader passes no legacy kubeconfig: only the writer's
	// transitional kubectl Apply reads one (ADR 0023 M2.5 to M2.7).
	return cluster.Open(kube.Config{Endpoint: ep, Credential: cred, Identity: r.Identity}, r.Warn, "")
}

// readerCredential is openCluster's step 4 for the reader.
func readerCredential(r clusterRef, ep kube.Endpoint) (kube.Credential, error) {
	meta := r.Meta
	name := meta.Name
	if meta.Reader == nil {
		return kube.Credential{}, refuse(errCredentialMissing, "instance %q has no reader identity; run 'farcast reader init %s'", name, name)
	}
	// A certificate uploaded to the installer's account, or a hand-edited
	// email, never makes a "reader" read an admin read.
	if derived, ok := derivedReader(meta.Reader.Email, name, meta.Project, ep.Mode); !ok {
		return kube.Credential{}, refuse(errCredentialMissing, "instance %q records the reader %s, which is not the reader farcast derives for it (%s); nothing was sent", name, meta.Reader.Email, derived)
	}
	if meta.Reader.KeyID == "" {
		return kube.Credential{}, refuse(errCredentialMissing, "instance %q's reader key is not yet uploaded; run the printed Cloud Shell script, then 'farcast reader record %s --key-id <id>'", name, name)
	}
	// A reader whose read-only check failed, or never ran, reads nothing: an
	// IAM role stronger than clusterViewer, edited into the paste, would
	// otherwise read with write rights. Only reader grant's own verifying
	// read and reviews open it unverified.
	if meta.Reader.GrantedAt.IsZero() && !r.Verifying {
		return kube.Credential{}, refuse(errCredentialMissing, "instance %q's reader has not been verified read-only; run 'farcast reader grant %s'", name, name)
	}
	key, err := r.Dir.LoadReaderKey(name)
	if errors.Is(err, fs.ErrNotExist) {
		return kube.Credential{}, refuse(errCredentialMissing, "instances/%s/reader.key is missing; run 'farcast reader init %s --rotate'", name, name)
	}
	if err != nil {
		return kube.Credential{}, err
	}
	return kube.Credential{Email: meta.Reader.Email, PrivateKeyID: meta.Reader.KeyID, PrivateKeyPEM: key}, nil
}

// loopbackReaderDomain is the pattern of a loopback (test) reader's email
// domain: one or more DNS labels (lowercase letters, digits and interior
// hyphens) under .invalid, where kube's pairing rule puts every loopback
// identity. It is the same pattern the reader's RBAC renderers accept
// (readerSubjectShape), so a recorded domain holding a quote, a $( or a
// space is never the derived reader, and nothing is printed from it.
const loopbackReaderDomain = `(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+invalid`

var loopbackReaderDomainShape = regexp.MustCompile(`^` + loopbackReaderDomain + `$`)

// derivedReader reports whether email is the reader farcast derives for the
// instance, and names that reader for a refusal. In Google mode it is exactly
// readerEmail(name, project). In loopback mode, a test cluster's, it is
// readerName(name) at a name under .invalid (loopbackReaderDomain), the only
// emails a loopback endpoint pairs with.
func derivedReader(email, name, project string, mode kube.Mode) (derived string, ok bool) {
	if mode != kube.ModeLoopback {
		derived = readerEmail(name, project)
		return derived, email == derived
	}
	derived = readerName(name) + "@<a name under .invalid>"
	local, domain, found := strings.Cut(email, "@")
	return derived, found && local == readerName(name) && loopbackReaderDomainShape.MatchString(domain)
}
