package cli

import (
	"context"
	"errors"

	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/kube"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	tkube "github.com/sofmon/farcast/technocore/kube"
)

// Error kinds: a closed, stable set, carried in every JSON error envelope and
// in every section error of a world document (farsight/cli/README.md, "Error
// kinds"). A reader tells "no tunnel" from "no kernel" from "the reader's key
// was refused" by these, never by parsing prose — so a kind, once shipped,
// keeps its meaning, and a new failure gets a new kind rather than a reused
// one.
//
// There is no "usage" kind: a usage error, a flag that does not parse and an
// unknown command exit 2 with prose on stderr and no envelope at all.
const (
	kindRecordUnreadable   = "record_unreadable"
	kindNotFound           = "not_found"
	kindNotConnected       = "not_connected"
	kindTunnelUnreachable  = "tunnel_unreachable"
	kindKernelAbsent       = "kernel_absent"
	kindNotCheckpointed    = "not_checkpointed"
	kindVersionSkew        = "version_skew"
	kindCredentialMissing  = "credential_missing"
	kindCredentialRefused  = "credential_refused"
	kindUnsafeEnvironment  = "unsafe_environment"
	kindEndpointRefused    = "endpoint_refused"
	kindClusterUnreachable = "cluster_unreachable"
	kindUnauthorized       = "unauthorized"
	kindForbidden          = "forbidden"
	kindClusterRejected    = "cluster_rejected"
	kindDocumentUnreadable = "document_unreadable"
	kindRolloutStalled     = "rollout_stalled"
	kindPlanChanged        = "plan_changed"
	kindTimeout            = "timeout"
	kindInternal           = output.KindInternal
)

// errorKinds is the whole set, in the order the README lists it. A test holds
// the README and this list to each other.
var errorKinds = []string{
	kindRecordUnreadable, kindNotFound, kindNotConnected, kindTunnelUnreachable,
	kindKernelAbsent, kindNotCheckpointed, kindVersionSkew,
	kindCredentialMissing, kindCredentialRefused, kindUnsafeEnvironment, kindEndpointRefused,
	kindClusterUnreachable, kindUnauthorized, kindForbidden, kindClusterRejected,
	kindDocumentUnreadable, kindRolloutStalled, kindPlanChanged,
	kindTimeout, kindInternal,
}

// retiredKinds were shipped and are emitted no longer (ADR 0023 M2;
// not_migrated at M2.9a). A new kind never takes one of these names.
var retiredKinds = []string{"kubectl_missing", "kubectl_failed", "gcloud_mismatch", "gcloud_signed_out", "auth_tool_missing", "not_migrated"}

// kindError is an error that names its kind. It wraps, so whatever it wraps
// can still be matched, and its text is exactly the wrapped error's: giving an
// error a kind never changes what an operator reads.
type kindError struct {
	kind string
	err  error
}

func (e *kindError) Error() string     { return e.err.Error() }
func (e *kindError) Unwrap() error     { return e.err }
func (e *kindError) ErrorKind() string { return e.kind }

// withKind gives err a kind. A nil error stays nil.
func withKind(kind string, err error) error {
	if err == nil {
		return nil
	}
	return &kindError{kind: kind, err: err}
}

// kindOf is the kind err names anywhere in its chain, or internal.
func kindOf(err error) string { return output.KindOf(err) }

// classified is err with the kinds the router can infer for a command that
// did not name one: an instance with no record on this machine is not_found,
// a blank installer key refused where it is loaded is credential_missing,
// and a failure clusterKind knows (the in-process cluster client's, and the
// refusals of openCluster) carries that kind. Everything else unnamed is
// internal.
func classified(err error) error {
	if err == nil {
		return nil
	}
	var k output.Kinded
	if errors.As(err, &k) {
		return err
	}
	if errors.Is(err, config.ErrNoInstanceRecord) {
		return withKind(kindNotFound, err)
	}
	if errors.Is(err, config.ErrNoServiceAccountKey) {
		// ADR 0024 M3b.2: release, the storage and secret commands and
		// toolchain's registry ensure load the key themselves, under their own
		// words; the kind is the one loadInstallerKey's refusal of it names.
		return withKind(kindCredentialMissing, err)
	}
	if kind := clusterKind(err); kind != "" {
		return withKind(kind, err)
	}
	return err
}

// clusterKind is the kind of a failed cluster call (ADR 0023 M2.4, design
// §8.1), or "" when err is none it knows.
//
// Every kind is found with errors.Is or errors.As, never by matching a
// message, and the order is significant: an attempt that ran out of time
// is a timeout even though it also failed to reach the server; a refusal
// before anything was sent comes before anything the server said; and a
// kind a command named itself comes after every sentinel, so a cluster
// failure is never read as a kind that means something else.
func clusterKind(err error) string {
	var ae *kube.APIError
	var k output.Kinded
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, kube.ErrTimedOut):
		return kindTimeout
	case errors.Is(err, errCredentialMissing), errors.Is(err, kube.ErrCredentialInvalid):
		return kindCredentialMissing
	case errors.Is(err, kube.ErrUnsafeEnvironment):
		return kindUnsafeEnvironment
	case errors.Is(err, kube.ErrEndpointRefused):
		return kindEndpointRefused
	case errors.Is(err, kube.ErrTokenRefused):
		return kindCredentialRefused
	case errors.Is(err, kube.ErrUnreachable):
		return kindClusterUnreachable
	case errors.Is(err, tkube.ErrUnauthorized):
		return kindUnauthorized
	case errors.Is(err, tkube.ErrForbidden):
		return kindForbidden
	case errors.Is(err, kube.ErrUnreadable):
		return kindDocumentUnreadable
	case errors.Is(err, kube.ErrRolloutStalled):
		return kindRolloutStalled
	case errors.Is(err, kube.ErrRefusedDocument):
		// A document farcast rendered and its own checks refused: a bug in
		// farcast, not a cluster's answer.
		return kindInternal
	case errors.As(err, &ae):
		return kindClusterRejected
	case errors.As(err, &k):
		return k.ErrorKind()
	}
	return ""
}

// tunnelKind is the kind of a failed read through the FatLine tunnel.
func tunnelKind(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return kindTimeout
	}
	var k output.Kinded
	if errors.As(err, &k) {
		return k.ErrorKind()
	}
	return kindTunnelUnreachable
}
