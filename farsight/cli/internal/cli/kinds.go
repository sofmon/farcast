package cli

import (
	"context"
	"errors"

	"github.com/sofmon/farcast/farsight/cli/internal/cluster"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// Error kinds: a closed, stable set, carried in every JSON error envelope and
// in every section error of a world document (farsight/cli/README.md, "Error
// kinds"). A reader tells "no tunnel" from "no kernel" from "signed out of
// gcloud" by these, never by parsing prose — so a kind, once shipped, keeps
// its meaning, and a new failure gets a new kind rather than a reused one.
//
// There is no "usage" kind: a usage error, a flag that does not parse and an
// unknown command exit 2 with prose on stderr and no envelope at all.
const (
	kindRecordUnreadable  = "record_unreadable"
	kindNotFound          = "not_found"
	kindNotConnected      = "not_connected"
	kindTunnelUnreachable = "tunnel_unreachable"
	kindKernelAbsent      = "kernel_absent"
	kindNotCheckpointed   = "not_checkpointed"
	kindVersionSkew       = "version_skew"
	kindKubectlMissing    = "kubectl_missing"
	kindKubectlFailed     = "kubectl_failed"
	kindGCloudMismatch    = "gcloud_mismatch"
	kindGCloudSignedOut   = "gcloud_signed_out"
	kindAuthToolMissing   = "auth_tool_missing"
	kindTimeout           = "timeout"
	kindInternal          = output.KindInternal
)

// errorKinds is the whole set, in the order the README lists it. A test holds
// the README and this list to each other.
var errorKinds = []string{
	kindRecordUnreadable, kindNotFound, kindNotConnected, kindTunnelUnreachable,
	kindKernelAbsent, kindNotCheckpointed, kindVersionSkew, kindKubectlMissing,
	kindKubectlFailed, kindGCloudMismatch, kindGCloudSignedOut, kindAuthToolMissing,
	kindTimeout, kindInternal,
}

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
// did not name one. Only one is inferred today: an instance with no record on
// this machine is not_found. Everything else unnamed is internal.
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
	return err
}

// kubectlKind is the kind of a failed kubectl read.
//
// The cluster package marks what it can tell from the subprocess — kubectl
// absent, the auth plugin or gcloud absent, gcloud signed out — and wraps a
// context that ended, so every kind here is found with errors.Is, never by
// matching a message.
func kubectlKind(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return kindTimeout
	case errors.Is(err, cluster.ErrKubectlMissing):
		return kindKubectlMissing
	case errors.Is(err, cluster.ErrAuthToolMissing):
		return kindAuthToolMissing
	case errors.Is(err, cluster.ErrSignedOut):
		return kindGCloudSignedOut
	}
	var k output.Kinded
	if errors.As(err, &k) {
		return k.ErrorKind()
	}
	return kindKubectlFailed
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
