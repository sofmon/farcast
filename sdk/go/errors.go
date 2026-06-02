package farcast

import "errors"

// ErrNotImplemented is returned by capability methods whose implementation
// has not yet landed. Application code can compile and run against the full
// SDK surface early; capabilities light up as their build phases complete.
//
// Classify it with errors.Is:
//
//	if _, err := farcast.Storage().Read(ctx, key); errors.Is(err, farcast.ErrNotImplemented) {
//		// capability not available in this build
//	}
var ErrNotImplemented = errors.New("farcast: capability not implemented")
