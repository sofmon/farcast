package cli

import (
	"bytes"
	"strings"
	"testing"
)

// The histogram must render legibly and reconcile with the totals, because it
// is the measurement a future padding decision would be made on.
func TestUsageRendersTheSizeDistribution(t *testing.T) {
	r := storageUsageResult{
		Instance: "prod", Bucket: "farcast-prod-0a1b2c3d",
		Objects: 106, StoredBytes: 3 << 20, MonthlyUSD: 0.0001, PricesAsOf: "2026-08",
		Sizes: []usageSizeBand{
			{Label: "<=1K", Objects: 100, Bytes: 50000},
			{Label: "<=64K", Objects: 5, Bytes: 200000},
			{Label: "larger", Objects: 1, Bytes: 2900000},
		},
	}
	var buf bytes.Buffer
	if err := r.Human(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	t.Log("\n" + out)
	for _, want := range []string{"object sizes", "<=1K", "<=64K", "larger", "provider can see"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output is missing %q", want)
		}
	}
	// The largest band must not render a wider bar than the scale allows.
	for _, line := range strings.Split(out, "\n") {
		if strings.Count(line, "#") > 24 {
			t.Errorf("bar overflowed its scale: %q", line)
		}
	}
}

// A bucket with no objects must not render an empty histogram section.
func TestUsageWithoutSizesRendersNoHistogram(t *testing.T) {
	var buf bytes.Buffer
	r := storageUsageResult{Instance: "prod", Bucket: "b", PricesAsOf: "2026-08"}
	if err := r.Human(&buf); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "object sizes") {
		t.Error("an empty bucket rendered a histogram header")
	}
}
