package keeper

import (
	"crypto/rand"
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

	Reseeds    int      // pushes whose bundle left the device (see Delivered)
	Boots      int      // distinct keyholder processes those pushes landed in
	Refused    int      // pushes refused before the bundle was sent
	Devices    []string // devices that appear in the ledgers
	Unlabelled int      // reseeds whose target process is unknown

	// Unconfirmed counts pushes a device recorded before making and never
	// recorded the outcome of (ResultPending). Each is also counted as a
	// reseed into the process its entry names: the audit cannot rule out that
	// it moved key material, and leaving it out could only hide a second push.
	Unconfirmed int

	// RefusedAfterSend counts pushes refused after their bundle was written
	// to whatever answered (ResultRefusedAfterSend). Each is also counted as
	// a reseed into the process its entry names, for the reason Budget gives:
	// a solicitor that reads the bundle and refuses it would otherwise leave
	// no trace in the audit at all.
	RefusedAfterSend int

	// Divergent lists the boots that were re-seeded more than once. These are
	// what an operator looks at: a process is sealed once per restart, so a
	// second push into the same one had nothing to restore.
	Divergent []BootCount
}

// BootCount is one keyholder process and how many times it was re-seeded.
//
// Unconfirmed and RefusedAfterSend say how many of Count were not plain
// successes, because a divergent process reads differently with them: a
// keeper stopped between recording a push and making it leaves an
// unconfirmed entry for a push that never landed, and the next pass re-seeds
// the same still-sealed process; a push that lost a race to another pusher is
// refused after sending. Neither rules out a solicitation — both are what one
// looks like too — so the row stays, and says which it holds.
type BootCount struct {
	Boot             string
	Count            int
	Unconfirmed      int
	RefusedAfterSend int
	Device           string
	First            time.Time
	Last             time.Time
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
	open := Unsettled(entries)

	for i, e := range entries {
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
		if !Delivered(e, open[i]) {
			if e.Result != ResultPending {
				// A pending entry its outcome settled is read through that
				// outcome; anything else here sent nothing.
				a.Refused++
			}
			continue
		}
		switch e.Result {
		case ResultPending:
			a.Unconfirmed++
		case ResultRefusedAfterSend:
			a.RefusedAfterSend++
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
		switch e.Result {
		case ResultPending:
			bc.Unconfirmed++
		case ResultRefusedAfterSend:
			bc.RefusedAfterSend++
		}
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

// Delivered reports whether a reseed entry stands for a push whose sealed
// bundle left the device: one that succeeded, one refused after sending, or a
// pending entry nothing settled (unsettled, from Unsettled). A settled pending
// entry is read through its outcome, and a plain "refused" sent nothing.
func Delivered(e keyholder.LedgerEntry, unsettled bool) bool {
	switch e.Result {
	case "ok", ResultRefusedAfterSend:
		return true
	case ResultPending:
		return unsettled
	}
	return false
}

// NewPushID is a fresh value for LedgerEntry.Push: random, so that it names
// one push and nothing else — not the device, not the time, not the replica.
func NewPushID() string { return rand.Text() }

// Unsettled returns the index of every pending reseed entry (ResultPending)
// that no later entry settles. An entry settles a pending one when it is a
// reseed outcome carrying the same Push id, from the same device, for the
// same instance and replica, written after it. Pairing by id and not by
// replica is what keeps two keeper processes on one device honest: both can
// announce a push to the same replica before either makes it, and each
// outcome then settles its own announcement and no other. Entries from
// several devices may be interleaved.
//
// A pending entry with no id is never settled — no keeper that writes pending
// entries writes one without — and neither is one whose outcome is lost or
// unreadable: the push it announced may have been made.
func Unsettled(entries []keyholder.LedgerEntry) map[int]bool {
	type push struct {
		instance, device, id string
		ordinal              int
	}
	pending := map[push]int{}
	out := map[int]bool{}
	for i, e := range entries {
		if e.Intent != IntentReseed {
			continue
		}
		if e.Push == "" {
			if e.Result == ResultPending {
				out[i] = true
			}
			continue
		}
		p := push{e.Instance, e.Device, e.Push, e.Ordinal}
		if e.Result == ResultPending {
			if j, ok := pending[p]; ok {
				// The same id announced twice: the first stays open.
				out[j] = true
			}
			pending[p] = i
			continue
		}
		delete(pending, p)
	}
	for _, j := range pending {
		out[j] = true
	}
	return out
}
