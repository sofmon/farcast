package cli

import (
	"fmt"
	"io"

	"github.com/sofmon/farcast/technocore/pricing"
)

// The cost pillar is only as good as the rate card behind it, and that rate
// card is for ONE region ([ADR 0003]). An instance provisioned anywhere else
// is metered, limited, warned about and — since [ADR 0016] — RESIZED against
// prices that are not its own.
//
// Nothing said so until 2026-09-09. `farcast install` takes any `--region`,
// records it, and every cost figure afterwards is computed from
// [pricing.Region] regardless: the floor check that validates the mandatory
// limit, the ledger, `farcast costs`, and the monthly delta a right-sizing
// decision is justified by. It is a quiet wrongness in the one pillar this
// project calls non-negotiable, and quiet is the part that matters — an
// operator reading "USD 77.17/mo" has no way to know it is the wrong region's
// 77.17.
//
// This warns rather than refuses. Another region can be a perfectly good
// choice — the 5.2 walk reached for one because us-central1 had run out of
// capacity — and blocking it would trade a wrong number for no instance.
//
// [ADR 0003]: ../../../../docs/adr/0003-gke-autopilot.md
// [ADR 0016]: ../../../../docs/adr/0016-adaptive-resources.md

// pricedElsewhere reports whether an instance's region is one the rate card
// does not cover. An empty region is not a mismatch: nothing is known yet.
func pricedElsewhere(region string) bool {
	return region != "" && region != pricing.Region
}

// writeRegionCaveat says that every cost figure for this instance is modelled
// on another region's prices.
func writeRegionCaveat(w io.Writer, region string) {
	if !pricedElsewhere(region) {
		return
	}
	fprintln(w)
	fprintf(w, "This instance is in %s, and FarCast's rate card is %s as of %s.\n",
		region, pricing.Region, pricing.AsOf)
	fprintln(w, "Every cost figure for it — the limit check, the floor, the spend report and")
	fprintln(w, "any resize justified by a saving — is therefore modelled on another region's")
	fprintln(w, "prices. The enforcement is real; the numbers it acts on are approximate.")
}

// regionCaveat is the one-line form, for a result that has no room for four.
func regionCaveat(region string) string {
	if !pricedElsewhere(region) {
		return ""
	}
	return fmt.Sprintf("priced as %s (this instance is in %s)", pricing.Region, region)
}
