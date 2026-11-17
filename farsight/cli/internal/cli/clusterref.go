package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// errCredentialMissing marks a refusal for want of a credential the call
// can use: no installer key (an instance installed with Application Default
// Credentials), a credentials.yaml that is missing, unreadable or does not
// parse, a stored key that is not a service-account key, no reader recorded
// or uploaded, a reader not yet verified read-only, a reader email that is
// not the derived one, a missing key file, or a record whose values farcast
// does not accept (checkedReader, a writer's unsafe name, or a record that
// names another instance). It is the kind credential_missing.
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

// recordNamed refuses a record whose name is not the one the command was
// given (ADR 0023 M2.4, A18-8). Every file a command touches is under the name
// given, and openCluster builds its paths and its messages from the recorded
// one, so the two must be the same before either is used.
func recordNamed(meta *config.InstanceMetadata, name string) error {
	if meta.Name != name {
		return refuse(errCredentialMissing, "instance %q's record names the instance %q; farcast renders nothing from it", name, meta.Name)
	}
	return nil
}

// openCluster is the one place an instance's cluster client is built (ADR
// 0023 M2, design §3.5). Its steps, in order:
//
//  1. the record must name an endpoint; for the reader, the record's values
//     must then pass checkedReader, and for the writer its name must pass
//     validateInstanceName, before any path is built from them or any of
//     them is printed (A18-8, A20-8);
//  2. cluster-ca.crt is read, if it exists; one that exists and cannot be
//     read is refused as the endpoint;
//  3. the endpoint is classified against the region and that CA
//     (kube.ParseEndpoint), refusing anything the endpoint rule does not
//     accept;
//  4. the identity's credential is loaded: for the reader, only once the
//     record names the reader farcast derives for this instance, its key is
//     uploaded, and 'reader grant' has verified it read-only (unless
//     r.Verifying), and then reader.key; for the writer, the installer's
//     service-account key in credentials.yaml (writerCredential);
//  5. cluster.Open pairs the endpoint and the credential and builds the
//     client. Nothing is sent before a method is called.
//
// Every refusal before step 5 sends nothing. Until ADR 0023 M2.7 a writer's
// Apply still runs kubectl, over the instance's kubeconfig.yaml and as the
// active gcloud configuration; everything else the writer does runs
// in-process as the installer's key.
func openCluster(r clusterRef) (*cluster.Client, error) {
	if r.Meta == nil {
		return nil, errors.New("cli: openCluster needs the instance's record")
	}
	meta := r.Meta
	name := meta.Name

	// 1. This is endpoint_refused, never not_connected, which means no
	// FatLine is recorded.
	if meta.Endpoint == "" {
		return nil, refuse(kube.ErrEndpointRefused, "instance %q records no cluster endpoint; 'farcast install' records one; nothing was sent", name)
	}
	// A read command calls this with the record as it was read, so a hostile
	// name, project or key id is refused here, quoted, before the name
	// becomes a path or anything recorded is printed.
	switch r.Identity {
	case kube.Reader:
		if _, _, _, err := checkedReader(meta); err != nil {
			return nil, err
		}
	case kube.Writer:
		// The writer reads credentials.yaml, and hands kubectl
		// kubeconfig.yaml, under the recorded name: one that is not a name
		// install accepts ("../other", a control character) never becomes
		// a path, and is printed only quoted.
		if validateInstanceName(name) != nil {
			return nil, refuse(errCredentialMissing, msgUnsafeRecord, name, "name", name)
		}
	}
	// 2.
	ca, ok, err := r.Dir.LoadClusterCA(name)
	if err != nil {
		return nil, refuse(kube.ErrEndpointRefused, "instance %q's cluster-ca.crt exists and cannot be read (%v); nothing was sent", name, err)
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
	legacy := ""
	switch r.Identity {
	case kube.Reader:
		if cred, err = readerCredential(r, ep); err != nil {
			return nil, err
		}
	case kube.Writer:
		if cred, err = writerCredential(r); err != nil {
			return nil, err
		}
		// 5, the writer's half: only its transitional kubectl Apply reads
		// a kubeconfig (ADR 0023 M2.5 to M2.7). The reader passes none.
		legacy = r.Dir.InstanceKubeconfigPath(name)
	default:
		return nil, fmt.Errorf("cli: %q is not one of an instance's identities", r.Identity)
	}
	// 5.
	return cluster.Open(kube.Config{Endpoint: ep, Credential: cred, Identity: r.Identity}, r.Warn, legacy)
}

// writerCredential is openCluster's step 4 for the writer: the installer's
// service-account key from credentials.yaml (design §3.5, A20-8), read by
// loadInstallerKey. A key that is not a service-account key keeps kube's
// text, which names the field and never its value. Each refusal matches
// errCredentialMissing and sends nothing.
func writerCredential(r clusterRef) (kube.Credential, error) {
	creds, err := loadInstallerKey(r.Dir, r.Meta.Name)
	if err != nil {
		return kube.Credential{}, err
	}
	cred, err := kube.ParseServiceAccountJSON([]byte(creds.ServiceAccountKey))
	if err != nil {
		return kube.Credential{}, refuse(errCredentialMissing, "%s", err)
	}
	return cred, nil
}

// loadInstallerKey reads the installer's service-account key from the
// instance's credentials.yaml, for the writer (writerCredential) and for
// what a command reads from Google with it (ADR 0023 M2.6, A23-24), so the
// two refuse with one text. That file holds the private key and nothing
// else of note, so no refusal quotes it: a file that does not parse is named
// by config.ParseFault's fault and position, never by the YAML library's
// text, which can echo the source lines. A missing, unreadable or
// unparsable file, and a blank key (an instance installed with Application
// Default Credentials), are each refused with errCredentialMissing, before
// anything is opened with the key.
func loadInstallerKey(dir config.Dir, name string) (*config.InstanceCredentials, error) {
	creds, err := dir.LoadInstanceCredentials(name)
	if err != nil {
		var pe *fs.PathError
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil, refuse(errCredentialMissing, "instances/%s/credentials.yaml is missing; this machine holds no installer key for instance %q; nothing was sent", name, name)
		case errors.As(err, &pe):
			// The system's error alone: the path is the instance's own.
			return nil, refuse(errCredentialMissing, "instance %q's credentials.yaml cannot be read (%v); nothing was sent", name, pe.Err)
		}
		fault, ok := config.ParseFault(err)
		if !ok {
			fault = "a YAML error"
		}
		return nil, refuse(errCredentialMissing, "instance %q's credentials.yaml does not parse (%s); nothing was sent", name, fault)
	}
	if strings.TrimSpace(creds.ServiceAccountKey) == "" {
		return nil, refuse(errCredentialMissing, "instance %q was installed without a service-account key (Application Default Credentials), "+
			"which farcast no longer uses for its cluster (ADR 0023 M2); release it ('farcast release %s') and install a new instance with --credentials", name, name)
	}
	return creds, nil
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
		return kube.Credential{}, refuse(errCredentialMissing, "instance %q records the reader %q, which is not the reader farcast derives for it (%s); nothing was sent", name, meta.Reader.Email, derived)
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

// msgReaderIAMRefused is what a 403 the reader met at the cluster's endpoint,
// rather than in Kubernetes' RBAC, says to do (design §8.1). What an IAM
// refusal looks like on the wire is not walked; the probe walk pins it.
const msgReaderIAMRefused = "the cluster's endpoint refused the identity (IAM); if the reader was just set up, IAM changes can take 7 minutes or longer, otherwise check the Cloud Shell step"

// readerRefused is err with one sentence appended when the cluster refused
// the instance's reader (403, tkube.ErrForbidden; design §8.1, A18-10): an
// RBAC refusal, a 403 whose body is a Kubernetes Status, says to run 'farcast
// reader grant'; any other 403 is the endpoint's IAM. Every other error, nil
// included, is returned as it is, and the result still matches everything err
// did. Only the read commands call it, which read as the reader and know the
// instance's name; a writer's 403 is writerRefused's.
func readerRefused(err error, name string) error {
	if !errors.Is(err, tkube.ErrForbidden) {
		return err
	}
	if forbiddenByRBAC(err) {
		return fmt.Errorf("%w; run 'farcast reader grant %s'", err, name)
	}
	return fmt.Errorf("%w; %s", err, msgReaderIAMRefused)
}

// writerRefused is err with one sentence appended when the cluster refused
// the instance's installer service account, the writer (403,
// tkube.ErrForbidden; ADR 0023 M2.5, A20-9): an RBAC refusal, a 403 whose
// body is a Kubernetes Status, or any other 403, which is the endpoint's IAM.
// Each writing command applies it once, to the error its Run returns; nothing
// else does, and classified never appends it. Every other error, nil
// included, is returned as it is, and so is any error when meta is nil (a
// command that failed before it read the record reached no cluster). What an
// IAM refusal looks like on the wire is not walked; the probe walk pins it.
// The transitional kubectl Apply's errors never carry tkube.ErrForbidden.
func writerRefused(err error, meta *config.InstanceMetadata) error {
	if meta == nil || !errors.Is(err, tkube.ErrForbidden) {
		return err
	}
	if forbiddenByRBAC(err) {
		return fmt.Errorf("%w; the cluster refused instance %q's installer service account (RBAC); check that it still holds roles/container.admin in project %q", err, meta.Name, meta.Project)
	}
	return fmt.Errorf("%w; the cluster's endpoint refused instance %q's installer service account (IAM); check that it still holds roles/container.admin in project %q", err, meta.Name, meta.Project)
}

// namespaceRefused is readerRefused for a namespace world marks as one the
// reader may not read (P5, A18-1), with the remedy that works for it. The
// reader is bound in farcast-system and the namespaces this machine records
// as metered only (P3), so for an RBAC 403 in any other namespace 'reader
// grant' binds nothing; 'kernel meter', which meters it and binds the reader
// beside the kernel once 'reader grant' recorded its scope, does. A recorded
// namespace refused by RBAC lost or never got its binding, which 'reader
// grant' applies again, and any other 403 is the endpoint's IAM, whatever
// the namespace: both are readerRefused's.
func namespaceRefused(err error, name, ns string, meta *config.InstanceMetadata) error {
	if forbiddenByRBAC(err) && (meta.Kernel == nil || !slices.Contains(meta.Kernel.Namespaces, ns)) {
		return fmt.Errorf("%w; the reader may read only farcast-system and the namespaces this machine records as metered: "+
			"run 'farcast kernel meter %s %s', which meters %s and binds the reader there", err, name, ns, ns)
	}
	return readerRefused(err, name)
}

// forbiddenByRBAC reports whether any error in err's tree is a 403 whose body
// was a Kubernetes Status (kube.APIError.KubernetesStatus): the API server's
// RBAC refused it, not the endpoint in front of it. It walks the whole tree,
// so a 403 among several namespaces' failures is found whatever came first.
func forbiddenByRBAC(err error) bool {
	if ae, ok := err.(*kube.APIError); ok && ae.Status.Code == http.StatusForbidden && ae.KubernetesStatus {
		return true
	}
	switch u := err.(type) {
	case interface{ Unwrap() error }:
		if inner := u.Unwrap(); inner != nil {
			return forbiddenByRBAC(inner)
		}
	case interface{ Unwrap() []error }:
		for _, inner := range u.Unwrap() {
			if forbiddenByRBAC(inner) {
				return true
			}
		}
	}
	return false
}
