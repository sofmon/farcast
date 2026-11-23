package devicekey

import (
	"errors"
	"fmt"
	"io"
)

// ObjectKind is a kind of Google object whose ID the device draws: a
// workload identity pool, a provider, or a service account.
type ObjectKind int

const (
	PoolID           ObjectKind = 1 // 32 characters
	ProviderID       ObjectKind = 2 // 32 characters
	ServiceAccountID ObjectKind = 3 // 30 characters
)

// The two alphabets an object ID is drawn from: a lowercase letter first,
// then lowercase letters and digits.
const (
	idFirstAlphabet = "abcdefghijklmnopqrstuvwxyz"
	idRestAlphabet  = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// maxObjectIDBytes bounds how many bytes one draw may read, rejected ones
// included. A uniform source exceeds it with a probability far below 2^-1000;
// a source that keeps giving the same high byte is refused rather than read
// for ever.
const maxObjectIDBytes = 1024

// objectIDLen is kind's length, the kind's maximum [MGMT]; 0 for no kind.
func objectIDLen(kind ObjectKind) int {
	switch kind {
	case PoolID, ProviderID:
		return 32
	case ServiceAccountID:
		return 30
	}
	return 0
}

// NewObjectID draws an ID for kind: a lowercase letter, then [a-z0-9] to the
// kind's length. It has no hyphen and no fixed prefix, and is never "gcp-".
// [MGMT]: pool and provider IDs are 4–32 of [a-z0-9-], not starting gcp-; an
// account ID is 6–30, a letter first. Each character is drawn by rejection
// sampling from rnd's bytes: a byte is used only below the largest multiple of
// the alphabet's size (26 for the first character, 36 after), so no character
// is likelier than another.
//
// The lengths are the kinds' maxima. A fixed length is one more profile trait
// (spec v2 §7, deviation 14).
//
// It reads, each round, as many bytes as characters are still to be drawn, so
// it never reads a byte past the last one it uses.
func NewObjectID(kind ObjectKind, rnd io.Reader) (string, error) {
	n := objectIDLen(kind)
	if n == 0 {
		return "", fmt.Errorf("devicekey: no object kind %d", int(kind))
	}
	if rnd == nil {
		return "", errors.New("devicekey: an object ID needs a random source")
	}
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	read := 0
	for len(out) < n {
		need := n - len(out)
		if read+need > maxObjectIDBytes {
			return "", errors.New("devicekey: the random source gave too many unusable bytes for an object ID")
		}
		if _, err := io.ReadFull(rnd, buf[:need]); err != nil {
			return "", fmt.Errorf("devicekey: draw an object ID: %w", err)
		}
		read += need
		for _, b := range buf[:need] {
			alphabet := idRestAlphabet
			if len(out) == 0 {
				alphabet = idFirstAlphabet
			}
			size := len(alphabet)
			if int(b) >= 256-256%size {
				continue // above the largest multiple of size: biased, so skipped
			}
			out = append(out, alphabet[int(b)%size])
		}
	}
	return string(out), nil
}
