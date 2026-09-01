package kube

import "testing"

// The table is the specification. Every one of these appears in a real
// manifest, and the pairs that differ by a single character are the reason
// this parser exists rather than a strings.TrimSuffix.
func TestParseQuantity(t *testing.T) {
	cases := map[string]float64{
		"0":     0,
		"1":     1,
		"1.5":   1.5,
		"100m":  0.1,
		"250m":  0.25,
		"1000m": 1,
		"2":     2,

		// One character apart, six orders of magnitude apart.
		"100M":  100e6,
		"128Mi": 128 * 1024 * 1024,
		"128M":  128e6,

		"1Ki":   1024,
		"1Gi":   1 << 30,
		"1G":    1e9,
		"1Ti":   1 << 40,
		"512Mi": 512 * 1024 * 1024,

		// Decimal exponent beats exa for 'E', per the Kubernetes grammar.
		"1e3": 1000,
		"1E3": 1000,

		"1n": 1e-9,
		"1u": 1e-6,
		"1k": 1000,
	}
	for in, want := range cases {
		got, err := ParseQuantity(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q = %v, want %v", in, got, want)
		}
	}
}

// An unknown suffix must be an error. Treating it as 1 would turn a typo into
// a plausible number that flows all the way out to an operator as money.
func TestParseQuantityRejectsWhatItDoesNotUnderstand(t *testing.T) {
	for _, in := range []string{
		"", "   ", "abc", "100x", "100mi", "Mi", "1Xi", "--1", "1.2.3",
		"-1", "-100m", "NaN", "Inf",
	} {
		if v, err := ParseQuantity(in); err == nil {
			t.Errorf("%q parsed as %v; expected an error", in, v)
		}
	}
}

func TestParseCPUMilli(t *testing.T) {
	cases := map[string]int{
		"100m": 100, "1": 1000, "250m": 250, "1.5": 1500, "0": 0, "2": 2000,
		// Sub-millicore rounds UP: a workload is never billed for less than
		// it reserves.
		"100u": 1, "1n": 1,
	}
	for in, want := range cases {
		got, err := ParseCPUMilli(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseCPUMilli(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestParseMemMiB(t *testing.T) {
	cases := map[string]int{
		"128Mi": 128, "1Gi": 1024, "512Mi": 512, "0": 0,
		// 128M is 128 million bytes = 122.07 MiB, which rounds up to 123 —
		// NOT the 128 a careless parser would report.
		"128M": 123,
		"1M":   1,
	}
	for in, want := range cases {
		got, err := ParseMemMiB(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseMemMiB(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestParseRejectsImplausiblyLargeQuantities(t *testing.T) {
	if _, err := ParseCPUMilli("1Ei"); err == nil {
		t.Error("an exbibyte of CPU should not parse as a millicore count")
	}
}
