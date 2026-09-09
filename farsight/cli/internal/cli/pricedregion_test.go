package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sofmon/farcast/technocore/pricing"
)

func TestOnlyTheRateCardsOwnRegionIsSilent(t *testing.T) {
	if pricedElsewhere(pricing.Region) {
		t.Error("the priced region was reported as a mismatch")
	}
	if pricedElsewhere("") {
		t.Error("an unknown region was reported as a mismatch; nothing is known yet")
	}
	if !pricedElsewhere("europe-west1") {
		t.Error("another region was not reported as a mismatch")
	}
}

// The cost pillar is only as good as its rate card, and an operator reading a
// floor of "USD 77.17/mo" has no way to know it is the wrong region's 77.17.
func TestAnotherRegionSaysEveryCostFigureIsModelledElsewhere(t *testing.T) {
	var buf bytes.Buffer
	writeRegionCaveat(&buf, "europe-west1")
	out := buf.String()
	t.Log("\n" + out)
	for _, want := range []string{"europe-west1", pricing.Region, "limit check", "resize", "approximate"} {
		if !strings.Contains(out, want) {
			t.Errorf("the caveat is missing %q", want)
		}
	}

	// And the priced region says nothing at all: a warning that fires always
	// is a warning nobody reads.
	buf.Reset()
	writeRegionCaveat(&buf, pricing.Region)
	if buf.Len() != 0 {
		t.Errorf("the priced region produced a caveat: %q", buf.String())
	}
}

func TestTheOneLineCaveatNamesBothRegions(t *testing.T) {
	got := regionCaveat("asia-east1")
	if !strings.Contains(got, "asia-east1") || !strings.Contains(got, pricing.Region) {
		t.Errorf("caveat is %q, want both regions named", got)
	}
	if regionCaveat(pricing.Region) != "" {
		t.Error("the priced region produced a one-line caveat")
	}
}
