package keeper

import (
	"sort"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
)

// The audit ADR 0008 asks for, and the reason the keyholder was given a boot
// label at all.
//
// The reseed budget is a tripwire rather than a barrier: a patient adversary
// stays under it. So the control that actually catches a solicited push is
// reading the ledger — and the question worth asking of it is not "how many
// times did we re-seed" but "how many DISTINCT keyholder processes did we
// re-seed". One reseed per process is a cluster restarting and a keeper doing
// its job. Two into the same process means something asked for key material a
// live process already held, which is what a solicitation looks like from
// outside.
//
// This is detection by audit and it is named as such: it runs when an operator
// runs it, it is not a live alert, and against a cloud that simply reads the
// keyholder's memory it says nothing at all.

// Audit is the reconciliation of one fleet's ledgers.
type Audit struct {
	Instance string
	From     time.Time
	To       time.Time

	Reseeds    int      // successful reseed pushes
	Boots      int      // distinct keyholder processes those pushes landed in
	Refused    int      // pushes the cluster refused
	Devices    []string // devices that appear in the ledgers
	Unlabelled int      // successful reseeds whose target process is unknown

	// Divergent lists the boots that were re-seeded more than once. These are
	// what an operator looks at: a process is sealed once per restart, so a
	// second push into the same one had nothing to restore.
	Divergent []BootCount
}

// BootCount is one keyholder process and how many times it was re-seeded.
type BootCount struct {
	Boot   string
	Count  int
	Device string
	First  time.Time
	Last   time.Time
}

// Clean reports whether the audit found nothing to explain.
func (a Audit) Clean() bool { return len(a.Divergent) == 0 }

// Reconcile folds a fleet's ledger entries into an audit.
//
// Entries from every device are passed together, because budgets add across a
// fleet and a solicitation aimed at one device is invisible in that device's
// own count alone.
func Reconcile(instance string, entries []keyholder.LedgerEntry) Audit {
	a := Audit{Instance: instance}
	byBoot := map[string]*BootCount{}
	devices := map[string]bool{}

	for _, e := range entries {
		if e.Instance != instance {
			continue
		}
		if a.From.IsZero() || e.Time.Before(a.From) {
			a.From = e.Time
		}
		if e.Time.After(a.To) {
			a.To = e.Time
		}
		if e.Device != "" {
			devices[e.Device] = true
		}
		if e.Intent != IntentReseed {
			continue
		}
		if e.Result != "ok" {
			a.Refused++
			continue
		}
		a.Reseeds++
		if e.Boot == "" {
			// An older keeper, or a keyholder that could not mint a label.
			// Counted separately rather than folded in: an unattributable
			// push must not silently improve the ratio the audit turns on.
			a.Unlabelled++
			continue
		}
		bc, ok := byBoot[e.Boot]
		if !ok {
			bc = &BootCount{Boot: e.Boot, Device: e.Device, First: e.Time}
			byBoot[e.Boot] = bc
		}
		bc.Count++
		if e.Time.After(bc.Last) {
			bc.Last = e.Time
		}
		if e.Device != "" && bc.Device != e.Device {
			// More than one device re-seeded this process. That is ordinary in
			// a fleet — two keepers can wake to the same restart — and it is
			// recorded as a fleet rather than attributed to one device.
			bc.Device = "fleet"
		}
	}

	for _, bc := range byBoot {
		if bc.Count > 1 {
			a.Divergent = append(a.Divergent, *bc)
		}
	}
	sort.Slice(a.Divergent, func(i, j int) bool { return a.Divergent[i].Last.After(a.Divergent[j].Last) })

	a.Boots = len(byBoot)
	for d := range devices {
		a.Devices = append(a.Devices, d)
	}
	sort.Strings(a.Devices)
	return a
}
