package usage

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// Buckets must be monotonic and cover the range without a gap, because a
// quantile walks them in order and a gap would silently skip observations.
func TestBucketsAreMonotonicAndContiguous(t *testing.T) {
	prev := -1
	for i := 0; i < numBuckets; i++ {
		ub := upperBound(i)
		if ub <= prev {
			t.Fatalf("bucket %d has upper bound %d, not above the previous %d", i, ub, prev)
		}
		for v := prev + 1; v <= ub && v <= prev+64; v++ {
			if got := bucketOf(v); got != i {
				t.Fatalf("value %d lands in bucket %d, but bucket %d claims to hold it", v, got, i)
			}
		}
		prev = ub
	}
	if prev < MaxSample {
		t.Fatalf("the scheme tops out at %d, below MaxSample %d", prev, MaxSample)
	}
}

// The error bound is what makes a quantile usable as a resource request.
func TestBucketErrorStaysUnderSevenPercent(t *testing.T) {
	for v := 1; v <= 1<<20; v += 1 + v/97 {
		ub := upperBound(bucketOf(v))
		if err := float64(ub-v) / float64(v); err > 0.0625+1e-9 {
			t.Fatalf("value %d rounds up to %d, an error of %.4f", v, ub, err)
		}
	}
}

// Small values are exact, which is the whole reason the bottom of the scheme
// is linear: a sidecar at 3 millicores and one at 11 must not share a bucket.
func TestSmallValuesAreExact(t *testing.T) {
	for v := 0; v < exact; v++ {
		if got := upperBound(bucketOf(v)); got != v {
			t.Errorf("value %d is reported as %d, not exactly", v, got)
		}
	}
}

func TestQuantileRoundsUpAndPeakIsExact(t *testing.T) {
	var h Histogram
	for i := 0; i < 99; i++ {
		h.Sample(100)
	}
	h.Sample(4001) // one outlier, deliberately not on a bucket bound

	if h.Count() != 100 {
		t.Fatalf("count is %d, want 100", h.Count())
	}
	if h.Peak() != 4001 {
		t.Errorf("peak is %d, want the exact 4001", h.Peak())
	}
	// Quantiles are bucketed, so the contract is "at or above the true
	// value, by no more than the scheme's error" — never below it.
	for _, q := range []float64{0.5, 0.95} {
		got := h.Quantile(q)
		if got < 100 || float64(got-100)/100 > 0.0625 {
			t.Errorf("q%.2f is %d, want 100 rounded up by at most 6.25%%", q, got)
		}
	}
	// The top quantile rounds up, but never above the peak actually seen —
	// a request derived from it would otherwise reserve for a value nothing
	// ever used.
	if got := h.Quantile(1); got != 4001 {
		t.Errorf("p100 is %d, want the exact peak 4001", got)
	}
	if got := h.Mean(); math.Abs(got-139.01) > 0.01 {
		t.Errorf("mean is %v, want 139.01", got)
	}
}

func TestEmptyHistogramIsAllZeroes(t *testing.T) {
	var h Histogram
	if h.Count() != 0 || h.Peak() != 0 || h.Mean() != 0 || h.Quantile(0.95) != 0 {
		t.Errorf("an empty histogram reported something: %+v", h)
	}
}

func TestSamplesAboveTheMaximumAreClampedNotLost(t *testing.T) {
	var h Histogram
	h.Sample(MaxSample * 4)
	if h.Count() != 1 {
		t.Fatalf("count is %d, want the sample kept", h.Count())
	}
	if h.Peak() != MaxSample {
		t.Errorf("peak is %d, want it clamped to %d", h.Peak(), MaxSample)
	}
}

func TestMergeIsTheSameAsSamplingBothWays(t *testing.T) {
	var a, b, both Histogram
	for i := 1; i <= 50; i++ {
		a.Sample(i)
		both.Sample(i)
	}
	for i := 500; i <= 560; i++ {
		b.Sample(i)
		both.Sample(i)
	}
	a.Merge(&b)
	if a.Count() != both.Count() || a.Peak() != both.Peak() || a.Quantile(0.95) != both.Quantile(0.95) {
		t.Errorf("merged %+v does not match sampled %+v", statOf(&a), statOf(&both))
	}
	a.Merge(nil) // must not panic
}

func TestHistogramSurvivesJSON(t *testing.T) {
	var h Histogram
	for i := 1; i <= 400; i++ {
		h.Sample(i * 7)
	}
	blob, err := json.Marshal(&h)
	if err != nil {
		t.Fatal(err)
	}
	var back Histogram
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if statOf(&back) != statOf(&h) {
		t.Errorf("round trip changed the distribution: %+v became %+v", statOf(&h), statOf(&back))
	}
}

// A bucket index this build does not know means the document was written
// against different bounds. Reading it anyway would put counts at values this
// build interprets as something else, and every quantile would be wrong with
// nothing looking wrong.
func TestAForeignBucketIsRefusedRatherThanReinterpreted(t *testing.T) {
	var h Histogram
	err := json.Unmarshal([]byte(`{"n":1,"s":1,"p":1,"b":{"99999":1}}`), &h)
	if err == nil || !strings.Contains(err.Error(), "outside this build's scheme") {
		t.Fatalf("error is %v, want a refusal naming the scheme", err)
	}
}
