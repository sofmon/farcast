package kube

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Kubernetes writes resource amounts as quantities: a number with an optional
// suffix that is either binary (Ki, Mi, Gi…), decimal SI (n, u, m, k, M, G…),
// or a decimal exponent (e3, E3). "100m" is a tenth of a CPU; "100M" is a
// hundred million. One character apart, six orders of magnitude and a
// completely different bill.
//
// This is the part of a hand-rolled client that has to be right, because a
// misparse does not fail — it produces a plausible number that flows into the
// cost meter and out to an operator as money. Everything here is therefore
// exhaustive about suffixes it does not recognise: an unknown one is an error,
// never a silently-assumed 1.

var binarySuffix = map[string]float64{
	"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30,
	"Ti": 1 << 40, "Pi": 1 << 50, "Ei": 1 << 60,
}

var decimalSuffix = map[byte]float64{
	'n': 1e-9, 'u': 1e-6, 'm': 1e-3,
	'k': 1e3, 'M': 1e6, 'G': 1e9, 'T': 1e12, 'P': 1e15, 'E': 1e18,
}

// ParseQuantity returns a Kubernetes quantity in base units — cores for CPU,
// bytes for memory.
func ParseQuantity(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("kube: empty quantity")
	}

	// Binary suffixes are two characters and are checked first: "Mi" ends in
	// 'i', which is not a decimal suffix, but checking decimal first would
	// leave "M" matched against the wrong half of "Mi".
	if len(s) > 2 {
		if mult, ok := binarySuffix[s[len(s)-2:]]; ok {
			return scale(s[:len(s)-2], mult, s)
		}
	}

	// Plain numbers and decimal-exponent forms ("1", "1.5", "1e3", "1E3")
	// parse whole, which is how the exponent forms get handled at all: "1E3"
	// ends in a digit, so the decimal-suffix branch below never sees it and
	// the two branches cannot actually collide. No valid float literal ends
	// in n, u, m, k, M, G, T, P or E — so this ordering is documentation of
	// intent rather than a tie-break, and a test proving otherwise would be
	// news.
	if v, err := strconv.ParseFloat(s, 64); err == nil {
		return finite(v, s)
	}

	if mult, ok := decimalSuffix[s[len(s)-1]]; ok {
		return scale(s[:len(s)-1], mult, s)
	}
	return 0, fmt.Errorf("kube: unrecognised quantity %q", s)
}

func scale(num string, mult float64, orig string) (float64, error) {
	v, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, fmt.Errorf("kube: unrecognised quantity %q", orig)
	}
	return finite(v*mult, orig)
}

func finite(v float64, orig string) (float64, error) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("kube: quantity %q is not a finite number", orig)
	}
	if v < 0 {
		return 0, fmt.Errorf("kube: quantity %q is negative", orig)
	}
	return v, nil
}

// ParseCPUMilli returns a CPU quantity in millicores, rounded up.
//
// Up, not to nearest: a request rounded down is a workload billed for less
// than it reserves, and the cost pillar's failures should never be in the
// flattering direction.
func ParseCPUMilli(s string) (int, error) {
	cores, err := ParseQuantity(s)
	if err != nil {
		return 0, err
	}
	return ceilInt(cores * 1000)
}

// ParseMemMiB returns a memory quantity in mebibytes, rounded up — for the
// same reason, and because Autopilot's own floors are expressed in MiB.
func ParseMemMiB(s string) (int, error) {
	bytes, err := ParseQuantity(s)
	if err != nil {
		return 0, err
	}
	return ceilInt(bytes / (1 << 20))
}

func ceilInt(v float64) (int, error) {
	c := math.Ceil(v)
	if c > float64(math.MaxInt32) {
		return 0, fmt.Errorf("kube: quantity %v is implausibly large", v)
	}
	return int(c), nil
}
