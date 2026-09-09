// Package usage keeps a bounded, rolling picture of what applications
// actually use, as distinct from what they reserve.
//
// [ADR 0014] is the specification. Three of its decisions shape everything
// here and are worth stating where the code is:
//
//   - A profile describes one POD, not one application. Summing replicas and
//     recommending the total as a request would be wrong by the replica count.
//   - History is a bounded rolling distribution, never a sample log. The size
//     is fixed by the window, not by uptime, and a thirty-second series of
//     per-application CPU would be a timeline of when the operator is awake.
//   - Nothing in here enforces anything. The cost meter reads requests and
//     only requests; usage that cannot be read means a resize declines, which
//     is the safe direction.
//
// [ADR 0014]: ../../docs/adr/0014-observed-usage.md
package usage

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"strconv"
)

// MaxSample is the largest value a histogram will record. Above it a sample
// is clamped rather than refused: a reading that implausibly large is either
// a unit mistake upstream or a genuinely enormous pod, and neither is worth
// losing the rest of the distribution over. It is 16 Gi in whatever unit the
// caller is using — 16777 cores, or 16 TiB of memory.
const MaxSample = 1 << 24

// The bucket scheme: values below 32 are exact, and every octave above that
// is split into sixteen. That bounds the error of a quantile at 6.25% above
// the value it reports, while keeping the whole range to a few hundred
// buckets — small enough that a quantile can walk them all rather than
// sorting anything, and small enough that the encoded form of a steady
// application is a couple of hundred bytes.
//
// Exactness at the bottom is not a nicety. A sidecar idling at 3 millicores
// and one at 11 are the difference between a request that is nearly right and
// one that is nearly four times too big, and a purely logarithmic scheme
// would put both in the same bucket.
const (
	subBits  = 4
	subCount = 1 << subBits // 16 sub-buckets per octave
	exact    = 2 * subCount // values below this are their own bucket
)

// numBuckets is one past the bucket MaxSample lands in.
var numBuckets = bucketOf(MaxSample) + 1

// bucketOf returns the bucket holding v.
func bucketOf(v int) int {
	if v < 0 {
		v = 0
	}
	if v > MaxSample {
		v = MaxSample
	}
	if v < exact {
		return v
	}
	mag := bits.Len(uint(v)) - 1 // floor(log2(v)), at least subBits+1
	sub := (v >> (mag - subBits)) - subCount
	return exact + (mag-subBits-1)*subCount + sub
}

// upperBound returns the largest value bucket i holds. A quantile reports
// this rather than a bucket midpoint: the number exists to be turned into a
// resource request, and a request below what was observed is the one mistake
// that shows up as a crash rather than as a bill.
func upperBound(i int) int {
	if i < exact {
		return i
	}
	j := i - exact
	mag := subBits + 1 + j/subCount
	sub := j % subCount
	return ((subCount + sub + 1) << (mag - subBits)) - 1
}

// Histogram is a distribution of observed values, kept in fixed space.
//
// Count, Sum and Peak are exact; quantiles are bucketed. That split is
// deliberate — a report reads better with a true peak in it, and the peak is
// the one order statistic a bucket cannot approximate in the safe direction.
type Histogram struct {
	counts map[int]uint64
	n      uint64
	sum    uint64
	peak   int
}

// Sample records one observation.
func (h *Histogram) Sample(v int) {
	if v < 0 {
		v = 0
	}
	if v > MaxSample {
		v = MaxSample
	}
	if h.counts == nil {
		h.counts = make(map[int]uint64, 4)
	}
	h.counts[bucketOf(v)]++
	h.n++
	h.sum += uint64(v)
	if v > h.peak {
		h.peak = v
	}
}

// Count is how many observations went in.
func (h *Histogram) Count() uint64 { return h.n }

// Peak is the largest observation, exactly.
func (h *Histogram) Peak() int { return h.peak }

// Mean is the arithmetic mean, or zero when nothing has been sampled.
func (h *Histogram) Mean() float64 {
	if h.n == 0 {
		return 0
	}
	return float64(h.sum) / float64(h.n)
}

// Quantile returns the smallest bucket bound at or above the q-th value,
// where q is in (0, 1]. An empty histogram is zero.
//
// It rounds UP to the bucket's upper bound. Everything downstream turns this
// into a reservation, and rounding a reservation down is how an application
// that was fine yesterday starts being killed today.
func (h *Histogram) Quantile(q float64) int {
	if h.n == 0 {
		return 0
	}
	if q <= 0 {
		q = 0
	}
	if q > 1 {
		q = 1
	}
	// The rank is the count-th sample, one-based, so q=1 is the last one.
	rank := uint64(float64(h.n)*q + 0.5)
	if rank == 0 {
		rank = 1
	}
	if rank > h.n {
		rank = h.n
	}
	var seen uint64
	for i := 0; i < numBuckets; i++ {
		seen += h.counts[i]
		if seen >= rank {
			return min(upperBound(i), h.peak)
		}
	}
	return h.peak
}

// Merge folds another histogram into this one. It is how a window over
// several hourly slots is read without keeping a second copy of anything.
func (h *Histogram) Merge(o *Histogram) {
	if o == nil || o.n == 0 {
		return
	}
	if h.counts == nil {
		h.counts = make(map[int]uint64, len(o.counts))
	}
	for b, c := range o.counts {
		h.counts[b] += c
	}
	h.n += o.n
	h.sum += o.sum
	if o.peak > h.peak {
		h.peak = o.peak
	}
}

// wireHistogram is the encoded form. The names are short because this is
// stored in a ConfigMap with a hard 1 MiB ceiling, and buckets are a sparse
// map because a steady application occupies two or three of them.
type wireHistogram struct {
	N    uint64            `json:"n"`
	Sum  uint64            `json:"s"`
	Peak int               `json:"p"`
	B    map[string]uint64 `json:"b,omitempty"`
}

func (h *Histogram) MarshalJSON() ([]byte, error) {
	w := wireHistogram{N: h.n, Sum: h.sum, Peak: h.peak}
	if len(h.counts) > 0 {
		w.B = make(map[string]uint64, len(h.counts))
		for b, c := range h.counts {
			w.B[strconv.Itoa(b)] = c
		}
	}
	return json.Marshal(w)
}

func (h *Histogram) UnmarshalJSON(b []byte) error {
	var w wireHistogram
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	h.n, h.sum, h.peak = w.N, w.Sum, w.Peak
	h.counts = make(map[int]uint64, len(w.B))
	for k, c := range w.B {
		i, err := strconv.Atoi(k)
		if err != nil {
			return fmt.Errorf("usage: histogram bucket %q is not a number", k)
		}
		// A bucket outside the scheme means the document was written by a
		// build using different bounds. Refusing is the only safe answer:
		// silently keeping it would put counts at a value this build reads
		// as something else entirely, and quantiles would be wrong without
		// anything looking wrong.
		if i < 0 || i >= numBuckets {
			return fmt.Errorf("usage: histogram bucket %d is outside this build's scheme (0..%d)", i, numBuckets-1)
		}
		h.counts[i] = c
	}
	return nil
}
