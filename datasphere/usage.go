package datasphere

import (
	"context"
	"time"
)

// Usage is what a bucket physically holds.
type Usage struct {
	Objects     int64
	StoredBytes int64
	Oldest      time.Time
	Newest      time.Time
}

// BucketUsage reports what a bucket physically holds, over a Provider, with no
// keyring and nothing decrypted.
//
// It is a package function rather than a Store method on purpose. Store.List
// reports what the *keyring* can name; a teardown gate or a spend report built
// on that would announce an empty bucket while billable ciphertext sat in it,
// and would stop working entirely for the operator who has lost keys.yaml and
// most needs to see what they are still paying for. Whoever needs to know
// whether money is being spent must be able to ask without holding the keys.
//
// A divergence between this count and Store.List's is itself worth reporting:
// it means the bucket holds objects this instance's keyring cannot name.
func BucketUsage(ctx context.Context, p Provider, bucket string) (Usage, error) {
	infos, err := p.List(ctx, bucket, "")
	if err != nil {
		return Usage{}, err
	}
	var usage Usage
	for _, info := range infos {
		usage.Objects++
		usage.StoredBytes += info.Size
		if info.Created.IsZero() {
			continue
		}
		if usage.Oldest.IsZero() || info.Created.Before(usage.Oldest) {
			usage.Oldest = info.Created
		}
		if info.Created.After(usage.Newest) {
			usage.Newest = info.Created
		}
	}
	return usage, nil
}
