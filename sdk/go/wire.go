package farcast

// Wire codes for the storage capability.
//
// The keyholder reports a failure as a short stable string, and that string —
// not the HTTP status — is authoritative. Statuses are advisory because they
// are coarse (several distinct conditions share 403 or 503) and because
// anything between the application and the keyholder can produce one without
// the keyholder having run at all.
//
// This SDK is its own Go module with no dependencies, so it cannot import
// DataSphere's error vocabulary; the codes are the contract between them and
// DataSphere mirrors this list. They are frozen: an application deployed
// today must still classify correctly against a keyholder built years later,
// so a code may be added but never renamed or reused.
const (
	CodeSealed     = "sealed"
	CodeNotFound   = "not-found"
	CodeIntegrity  = "integrity"
	CodeInvalidKey = "invalid-key"
	CodeTooLarge   = "too-large"
	CodePermission = "permission"
)

// storageErrors maps every wire code to the sentinel applications branch on.
//
// DataSphere distinguishes a blob that names key material this instance does
// not hold from one that failed authentication. That distinction matters to
// an operator and is logged, but it does not cross to applications: an
// application cannot act on the difference, the two are one flipped bit apart
// in cloud-writable bytes, and naming it on the wire would report which key
// ids a keyholder holds. Both arrive as CodeIntegrity.
var storageErrors = map[string]error{
	CodeSealed:     ErrStorageSealed,
	CodeNotFound:   ErrObjectNotFound,
	CodeIntegrity:  ErrIntegrity,
	CodeInvalidKey: ErrInvalidKey,
	CodeTooLarge:   ErrTooLarge,
	CodePermission: ErrPermission,
}

// storageError classifies a wire code. The mapping is total: an unrecognized
// or empty code yields ErrStorageUnavailable, never ErrObjectNotFound and
// never ErrNotImplemented, because an application that mistakes an
// unparseable answer for absence or for permanent unavailability will do
// something destructive with it.
func storageError(code string) error {
	if err, ok := storageErrors[code]; ok {
		return err
	}
	return ErrStorageUnavailable
}
