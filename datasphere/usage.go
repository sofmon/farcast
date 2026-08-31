package datasphere

import (
	"context"
	"fmt"
	"time"
)

// Usage is what a bucket physically holds.
type Usage struct {
	Objects     int64
	StoredBytes int64
	Oldest      time.Time
	Newest      time.Time

	// Sizes is the distribution of stored object sizes, in power-of-two
	// buckets, smallest first. Only non-empty buckets appear.
	//
	// It is reported because the provider can already see every one of these
	// sizes exactly, so surfacing their shape to the operator gives away
	// nothing and answers a question the operator otherwise cannot: what does
	// my storage look like from outside? It is also the measurement any future
	// decision about size-hiding needs — a padding lattice cannot be chosen
	// without knowing where the objects actually cluster, and a distribution
	// gathered from the first real workload is worth more than an assumption.
	Sizes []SizeBucket
}

// SizeBucket counts the objects whose stored size falls in one power-of-two
// band.
type SizeBucket struct {
	// UpTo is the inclusive upper bound in bytes. Zero means the open-ended
	// final band: larger than the last bound.
	UpTo    int64
	Objects int64
	Bytes   int64
}

// Label renders the bucket's bound for display.
func (b SizeBucket) Label() string {
	if b.UpTo == 0 {
		return "larger"
	}
	return "<=" + humanSize(b.UpTo)
}

// sizeBounds are the band edges: 1 KiB doubling to 64 MiB, then open-ended.
// Powers of two rather than a coarser scale because the interesting clustering
// for small objects — the ones whose size can equal their content — happens
// well below a megabyte.
var sizeBounds = func() []int64 {
	var out []int64
	for n := int64(1024); n <= 64<<20; n *= 2 {
		out = append(out, n)
	}
	return out
}()

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%dM", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%dK", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
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
	counts := make([]int64, len(sizeBounds)+1)
	bytes := make([]int64, len(sizeBounds)+1)
	for _, info := range infos {
		usage.Objects++
		usage.StoredBytes += info.Size
		band := len(sizeBounds)
		for i, bound := range sizeBounds {
			if info.Size <= bound {
				band = i
				break
			}
		}
		counts[band]++
		bytes[band] += info.Size
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
	for i, n := range counts {
		if n == 0 {
			continue
		}
		var upTo int64
		if i < len(sizeBounds) {
			upTo = sizeBounds[i]
		}
		usage.Sizes = append(usage.Sizes, SizeBucket{UpTo: upTo, Objects: n, Bytes: bytes[i]})
	}
	return usage, nil
}
