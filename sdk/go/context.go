package farcast

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// ctxKey is the unexported type for context keys defined by this package,
// preventing collisions with keys set by other packages.
type ctxKey int

const requestIDKey ctxKey = iota

// WithRequestID returns a copy of ctx that carries id. Every log record
// emitted with that ctx (or a context derived from it) includes
// "request_id": id. Set it once where a unit of work begins — an HTTP
// handler, a queue consumer, a CLI invocation — and the identifier
// propagates to every downstream log call without threading a logger
// through each function signature.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestID returns the request ID carried by ctx, or "" if none is set.
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// NewRequestID returns a new collision-resistant request ID: 128 bits of
// cryptographic randomness, hex-encoded. It uses only the standard library.
func NewRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand draws from the operating system CSPRNG, whose failure
		// is catastrophic and unrecoverable; Go's own crypto panics here too.
		panic("farcast: system CSPRNG unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
