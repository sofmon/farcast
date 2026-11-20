package kube

import (
	"errors"
	"fmt"
	"net/http"

	tkube "github.com/sofmon/farcast/technocore/kube"
)

// The package's sentinels. A caller branches on them with errors.Is, and the
// CLI maps each to an error kind; the texts below are never parsed.
//
// tkube's own four, ErrNotFound, ErrForbidden, ErrUnauthorized and
// ErrConflict, are reached through APIError.Unwrap and are not repeated here.
var (
	ErrEndpointRefused   = errors.New("kube: the cluster endpoint and the credential do not pair")
	ErrCredentialInvalid = errors.New("kube: the stored credential is not one farcast can use")
	ErrTokenRefused      = errors.New("kube: Google's token endpoint refused to mint a token")
	ErrUnreachable       = errors.New("kube: the API server or the token endpoint could not be reached")
	ErrUnreadable        = errors.New("kube: an answer from the API server could not be read")
	ErrRefusedDocument   = errors.New("kube: a document is not one farcast applies")
	ErrTimedOut          = errors.New("kube: timed out waiting")
	ErrRolloutStalled    = errors.New("kube: the rollout exceeded its progress deadline")
	// ErrUnsafeEnvironment is a process environment under which a request
	// would print a secret, such as GODEBUG's http2debug. It is not
	// ErrEndpointRefused: the endpoint and the credential may pair perfectly.
	ErrUnsafeEnvironment = errors.New("kube: the process environment would print a secret")
)

// refusal is an error whose text is exactly its message and which unwraps to
// one of the sentinels above. The design pins each refusal's whole text, so
// the sentinel's own words are not prefixed to it.
type refusal struct {
	msg      string
	sentinel error
}

func (r *refusal) Error() string { return r.msg }
func (r *refusal) Unwrap() error { return r.sentinel }

// refuse builds a refusal wrapping sentinel, with the message format
// renders. A format must never carry a secret: key material, a token, an
// assertion or an annotation's value.
func refuse(sentinel error, format string, a ...any) error {
	return &refusal{msg: fmt.Sprintf(format, a...), sentinel: sentinel}
}

// Status is the API server's Status object, with the details tkube.Status leaves out.
type Status struct {
	tkube.Status
	Details *StatusDetails `json:"details,omitempty"`
}

// StatusDetails is meta/v1's StatusDetails, as far as farcast reads it.
type StatusDetails struct {
	Name   string        `json:"name,omitempty"`
	Group  string        `json:"group,omitempty"`
	Kind   string        `json:"kind,omitempty"`
	Causes []StatusCause `json:"causes,omitempty"`
}

// StatusCause is one cause of a Status. Its Type is meta/v1's CauseType,
// whose wire name is "reason".
type StatusCause struct {
	Type    string `json:"reason,omitempty"` // the wire name is "reason"
	Message string `json:"message,omitempty"`
	Field   string `json:"field,omitempty"`
}

// causeFieldManagerConflict is the cause type of a server-side apply conflict
// (meta/v1 CauseTypeFieldManagerConflict).
const causeFieldManagerConflict = "FieldManagerConflict"

// APIError is a non-2xx answer. Error() is "kube: <METHOD> <path>: <code> <reason>: <message>".
// Unwrap derives tkube's sentinel from the code, exactly as tkube.APIError does.
// KubernetesStatus is false when the body was not a Status object (kind "Status"),
// which is how a 403 from the endpoint's IAM check is told from an RBAC refusal (§8.3).
type APIError struct {
	Method, Path     string
	Status           Status
	KubernetesStatus bool
}

// Error renders the request and the server's own words. A Status without a
// reason is given the code's standard text, and one without a message ends
// at its reason, so no answer renders as an empty clause.
func (e *APIError) Error() string {
	reason := e.Status.Reason
	if reason == "" {
		reason = http.StatusText(e.Status.Code)
	}
	if e.Status.Message == "" {
		return fmt.Sprintf("kube: %s %s: %d %s", e.Method, e.Path, e.Status.Code, reason)
	}
	return fmt.Sprintf("kube: %s %s: %d %s: %s", e.Method, e.Path, e.Status.Code, reason, e.Status.Message)
}

// Unwrap is tkube.APIError's mapping, applied to this error's code, so a 404
// is tkube.ErrNotFound here exactly as it is in the kernel. A 409 unwraps to
// tkube.ErrConflict whatever its reason (AlreadyExists or Conflict); a caller
// that must tell them apart reads Status.Reason.
func (e *APIError) Unwrap() error {
	return (&tkube.APIError{Status: e.Status.Status}).Unwrap()
}

// FieldConflicts returns the causes of a server-side apply conflict (409 whose
// causes carry reason "FieldManagerConflict"), and whether err is one.
// Only the FieldManagerConflict causes are returned.
func FieldConflicts(err error) ([]StatusCause, bool) {
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status.Code != http.StatusConflict || ae.Status.Details == nil {
		return nil, false
	}
	var causes []StatusCause
	for _, c := range ae.Status.Details.Causes {
		if c.Type == causeFieldManagerConflict {
			causes = append(causes, c)
		}
	}
	return causes, len(causes) > 0
}
