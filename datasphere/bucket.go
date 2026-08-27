package datasphere

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Bucket naming. The rule lives here, in the module that owns the concept,
// rather than in whichever caller happens to need it first: the operator CLI
// mints and records a name at 3.3, the harness offers one now, and both must
// produce the same shape.
const (
	// BucketNamePrefix opens every FarCast bucket name, so an operator
	// auditing their cloud console recognises their own resources and an IAM
	// condition can scope the stored credential to them.
	BucketNamePrefix = "farcast-"

	// MaxBucketNameLen is GCS's cap, and the tighter of the two clouds this
	// module targets.
	MaxBucketNameLen = 63

	// bucketSuffixBytes is the entropy in a minted name: 32 bits, rendered as
	// 8 lowercase hex characters.
	bucketSuffixBytes = 4
)

// MintBucketName builds the name for an instance's bucket:
// farcast-<instance>-<8 random lowercase hex>, with the instance segment
// truncated if it would otherwise breach the length cap.
//
// The random suffix is not decoration. GCS bucket names are globally unique
// across all of Google Cloud, so a deterministic farcast-<instance> is both
// squattable — denial at best, and at worst an adoption bug writing the
// operator's ciphertext into a bucket a stranger can delete and watch — and
// probeable, confirming an instance's existence to anyone who guesses its
// name. Uniqueness rides the suffix; legibility rides the prefix.
//
// Because of the truncation clause the result is NOT invertible to the
// instance name. Every ownership check therefore takes the instance from the
// caller's local record, never from the bucket name — which is also why the
// name must be recorded BEFORE the bucket is created: the minted suffix exists
// nowhere else, and an unrecorded bucket is billable storage nobody is
// watching.
func MintBucketName(instance string) (string, error) {
	return mintBucketName(instance, rand.Reader)
}

func mintBucketName(instance string, rnd io.Reader) (string, error) {
	label := bucketLabel(instance)
	if label == "" {
		return "", errors.New("datasphere: instance name has no characters usable in a bucket name")
	}
	suffix := make([]byte, bucketSuffixBytes)
	if _, err := io.ReadFull(rnd, suffix); err != nil {
		return "", fmt.Errorf("datasphere: mint bucket suffix: %w", err)
	}
	tail := "-" + hex.EncodeToString(suffix)
	if room := MaxBucketNameLen - len(BucketNamePrefix) - len(tail); len(label) > room {
		// Trailing dashes are illegal in a bucket name, and truncation can
		// expose one.
		label = strings.TrimRight(label[:room], "-")
		if label == "" {
			return "", errors.New("datasphere: instance name leaves no room in a bucket name")
		}
	}
	return BucketNamePrefix + label + tail, nil
}

// bucketLabel renders an instance name into the character set a bucket name
// admits. Instance names are DNS labels already, so this is a guard rather
// than a transformation.
func bucketLabel(instance string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(instance) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
