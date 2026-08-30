package keyholder

import (
	"errors"
	"net/http"

	"github.com/sofmon/farcast/datasphere"
)

// Wire codes the keyholder reports, mirroring sdk/go/wire.go.
//
// The SDK is a separate Go module with no dependencies, so it cannot import
// this package and the list exists twice on purpose. A test asserts the two
// copies agree character for character; if it fails, the fix is to make them
// match, never to change the assertion — an application deployed today must
// still classify correctly against a keyholder built years later.
//
// The code, not the HTTP status, is authoritative. Statuses are coarse
// (several conditions share 403 and 503) and anything between an application
// and this process can produce one without the keyholder having run at all.
const (
	CodeSealed     = "sealed"
	CodeNotFound   = "not-found"
	CodeIntegrity  = "integrity"
	CodeInvalidKey = "invalid-key"
	CodeTooLarge   = "too-large"
	CodePermission = "permission"
)

// Control-plane codes. These answer the operator and the keeper, never an
// application, so they are deliberately outside the frozen SDK vocabulary.
const (
	CodeOperatorHold     = "operator-hold"
	CodeGenerationOld    = "generation-too-old"
	CodeInstanceMismatch = "instance-mismatch"
	CodeBadRequest       = "bad-request"
)

// errorResponse is the body every failure carries.
type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// classify maps an internal error onto the wire.
//
// It is exhaustive by construction: anything unrecognized becomes a 500 with
// no code rather than being guessed at, because the two nearest guesses —
// "no such object" and "sealed" — are the two an application acts on
// destructively.
func classify(err error) (status int, code string) {
	switch {
	case err == nil:
		return http.StatusOK, ""

	// A seal is not a failure; it is a documented state of a healthy
	// instance, and it must never reach an application as anything else.
	case errors.Is(err, ErrSealed):
		return http.StatusServiceUnavailable, CodeSealed

	case errors.Is(err, ErrOutOfScope):
		return http.StatusForbidden, CodePermission
	case errors.Is(err, datasphere.ErrObjectNotFound):
		return http.StatusNotFound, CodeNotFound

	// An unknown key id and a failed authentication are one flipped bit
	// apart in cloud-writable bytes, and an application can act on neither
	// distinction. Both arrive as integrity; the difference is logged here.
	case errors.Is(err, datasphere.ErrIntegrity), errors.Is(err, datasphere.ErrUnknownKey):
		return http.StatusBadGateway, CodeIntegrity

	case errors.Is(err, datasphere.ErrInvalidKey):
		return http.StatusBadRequest, CodeInvalidKey
	case errors.Is(err, datasphere.ErrTooLarge):
		return http.StatusRequestEntityTooLarge, CodeTooLarge

	// Control plane.
	case errors.Is(err, ErrOperatorHold):
		return http.StatusConflict, CodeOperatorHold
	case errors.Is(err, ErrGenerationTooOld):
		return http.StatusConflict, CodeGenerationOld
	case errors.Is(err, ErrInstanceMismatch):
		return http.StatusConflict, CodeInstanceMismatch
	case errors.Is(err, ErrEnvelopeInvalid):
		// One status and one code for every envelope failure, matching the
		// single error the opener returns: which check refused is not a
		// caller's business.
		return http.StatusForbidden, CodeBadRequest
	case errors.Is(err, datasphere.ErrBundleInvalid), errors.Is(err, datasphere.ErrKeyringInvalid):
		return http.StatusBadRequest, CodeBadRequest

	default:
		return http.StatusInternalServerError, ""
	}
}
