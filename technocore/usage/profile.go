package usage

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// SnapshotVersion is the shape of the persisted profile document.
const SnapshotVersion = 1

// DefaultBudget is how many bytes the encoded store may occupy. A ConfigMap
// is capped at 1 MiB by the API server, and this is deliberately half of it:
// the document has to fit with room to spare, because the failure mode of
// discovering otherwise is a write that starts being rejected on a busy
// instance months after it worked in testing.
const DefaultBudget = 512 << 10

// MinSamples is the fewest observations a window needs before anything should
// size a workload from it. At the kernel's thirty-second tick that is an hour
// of a single pod — long enough that a start-up spike is no longer most of
// what was seen.
const MinSamples = 120

// PodUsage is one pod's reading at one moment, alongside what that pod
// reserves. The request travels with the usage because the only question
// worth asking of either is the ratio between them.
type PodUsage struct {
	Pod             string
	CPUMilli        int
	MemMiB          int
	RequestCPUMilli int
	RequestMemMiB   int
}

// Profile is one application's rolling picture, per pod.
type Profile struct {
	CPU *Series `json:"c"`
	Mem *Series `json:"m"`

	// RequestCPUMilli and RequestMemMiB are what one pod of this application
	// currently reserves — the largest across its pods at the last reading,
	// replaced rather than accumulated, so a profile read after a resize
	// describes the reservation now in force.
	RequestCPUMilli int `json:"rc,omitempty"`
	RequestMemMiB   int `json:"rm,omitempty"`

	// Pods is how many were seen at the last reading. It is recorded, and
	// deliberately not folded into the distribution: replica count is a
	// separate question with a separate answer.
	Pods int `json:"n,omitempty"`

	FirstSeen time.Time `json:"f,omitzero"`
	LastSeen  time.Time `json:"l,omitzero"`
}

// Store holds the profiles of every application the kernel has seen.
type Store struct {
	hours    int
	profiles map[string]*Profile
}

// New returns an empty store retaining the given number of hours.
func New(hours int) *Store {
	if hours <= 0 {
		hours = DefaultHours
	}
	return &Store{hours: hours, profiles: map[string]*Profile{}}
}

// Hours is the window currently retained, which a trim may have shortened.
func (s *Store) Hours() int { return s.hours }

// Apps is how many applications are profiled.
func (s *Store) Apps() int { return len(s.profiles) }

// Record takes in one reading for one application: every pod of it, at one
// moment.
//
// Each pod contributes its own sample, so the distribution is across pods and
// time together — which is what makes it describe A pod rather than the sum
// of them.
func (s *Store) Record(at time.Time, app string, pods []PodUsage) {
	if app == "" || len(pods) == 0 {
		return
	}
	if s.profiles == nil {
		s.profiles = map[string]*Profile{}
	}
	p := s.profiles[app]
	if p == nil {
		p = &Profile{CPU: NewSeries(s.hours), Mem: NewSeries(s.hours), FirstSeen: at}
		s.profiles[app] = p
	}
	var reqCPU, reqMem int
	for _, u := range pods {
		p.CPU.Sample(at, u.CPUMilli)
		p.Mem.Sample(at, u.MemMiB)
		reqCPU = max(reqCPU, u.RequestCPUMilli)
		reqMem = max(reqMem, u.RequestMemMiB)
	}
	p.RequestCPUMilli, p.RequestMemMiB = reqCPU, reqMem
	p.Pods = len(pods)
	if at.After(p.LastSeen) {
		p.LastSeen = at
	}
}

// Snapshot is the persisted form of a store.
type Snapshot struct {
	Version  int                 `json:"version"`
	Hours    int                 `json:"hours"`
	Profiles map[string]*Profile `json:"profiles,omitempty"`
}

// Snapshot returns the store's persistable state.
func (s *Store) Snapshot() Snapshot {
	return Snapshot{Version: SnapshotVersion, Hours: s.hours, Profiles: s.profiles}
}

// Restore rebuilds a store from a snapshot.
//
// A snapshot from a different version is refused rather than partially read.
// These are advisory numbers, but numbers something else will turn into a
// resource reservation, and half-understood ones are worse than none.
func Restore(snap Snapshot) (*Store, error) {
	if snap.Version != SnapshotVersion {
		return nil, fmt.Errorf("usage: snapshot version %d, this build reads %d", snap.Version, SnapshotVersion)
	}
	s := New(snap.Hours)
	for app, p := range snap.Profiles {
		if p == nil {
			continue
		}
		if p.CPU == nil {
			p.CPU = NewSeries(s.hours)
		}
		if p.Mem == nil {
			p.Mem = NewSeries(s.hours)
		}
		s.profiles[app] = p
	}
	return s, nil
}

// Forget drops applications last seen before the cutoff. An application that
// has been gone for longer than the window has nothing left in its
// distribution anyway; this is what stops its empty shell accumulating.
func (s *Store) Forget(before time.Time) []string {
	var gone []string
	for app, p := range s.profiles {
		if p.LastSeen.Before(before) {
			gone = append(gone, app)
			delete(s.profiles, app)
		}
	}
	sort.Strings(gone)
	return gone
}

// Trimmed says what fitting the budget cost.
type Trimmed struct {
	// Hours is the window still retained. Below the configured one means
	// every application lost history to the budget.
	Hours int
	// Dropped names applications removed entirely, least recently seen first.
	Dropped []string
	// Bytes is the encoded size after trimming.
	Bytes int
}

// Shortened reports whether the budget cost anything.
func (t Trimmed) Shortened(configured int) bool { return t.Hours < configured || len(t.Dropped) > 0 }

// Trim shrinks the store until its encoded form fits the budget.
//
// Order matters and is [ADR 0014] decision 6: the retained window is
// shortened for everybody first, and only when it is down to a single hour
// does an application get dropped. Degrading uniformly leaves every
// application a usable — if shorter — profile, where dropping first would
// leave some perfect and others invisible.
//
// [ADR 0014]: ../../docs/adr/0014-observed-usage.md
func (s *Store) Trim(budget int) (Trimmed, error) {
	if budget <= 0 {
		budget = DefaultBudget
	}
	out := Trimmed{Hours: s.hours}
	for {
		blob, err := json.Marshal(s.Snapshot())
		if err != nil {
			return out, fmt.Errorf("usage: encode the profiles: %w", err)
		}
		out.Bytes, out.Hours = len(blob), s.hours
		if len(blob) <= budget || len(s.profiles) == 0 {
			return out, nil
		}
		if s.hours > 1 {
			s.hours--
			for _, p := range s.profiles {
				p.CPU.Shrink(s.hours)
				p.Mem.Shrink(s.hours)
			}
			continue
		}
		out.Dropped = append(out.Dropped, s.dropOldest())
	}
}

// dropOldest removes the least recently seen application and names it.
func (s *Store) dropOldest() string {
	var oldest string
	var at time.Time
	for app, p := range s.profiles {
		if oldest == "" || p.LastSeen.Before(at) || (p.LastSeen.Equal(at) && app < oldest) {
			oldest, at = app, p.LastSeen
		}
	}
	delete(s.profiles, oldest)
	return oldest
}

// Stat is one window's shape.
type Stat struct {
	Samples uint64  `json:"samples"`
	Mean    float64 `json:"mean"`
	P50     int     `json:"p50"`
	P95     int     `json:"p95"`
	Peak    int     `json:"peak"`
}

// Thin reports whether there is too little here to size anything from.
func (st Stat) Thin() bool { return st.Samples < MinSamples }

func statOf(h *Histogram) Stat {
	return Stat{Samples: h.Count(), Mean: h.Mean(), P50: h.Quantile(0.50), P95: h.Quantile(0.95), Peak: h.Peak()}
}

// Windows pairs the short and long views of one resource. The comparison
// between them is what "trend" means here: whether the last hour sits above
// the day's distribution, rather than a chart of how it got there.
type Windows struct {
	Hour Stat `json:"hour"`
	Day  Stat `json:"day"`
}

// Summary is one application's profile, resolved to numbers.
type Summary struct {
	App             string    `json:"app"`
	Pods            int       `json:"pods"`
	LastSeen        time.Time `json:"last_seen,omitzero"`
	Hours           int       `json:"hours"`
	RequestCPUMilli int       `json:"request_cpu_milli,omitempty"`
	RequestMemMiB   int       `json:"request_mem_mib,omitempty"`
	CPU             Windows   `json:"cpu"`
	Mem             Windows   `json:"mem"`
}

// CPUHeadroom is what a pod reserves divided by what it used at the day's
// p95. Above one means the reservation is larger than the observation. The
// bool is false when there is no request to compare against, or too little
// observation to compare with — the two cases where a ratio would be a number
// with no meaning.
func (s Summary) CPUHeadroom() (float64, bool) {
	return headroom(s.RequestCPUMilli, s.CPU.Day)
}

// MemHeadroom is the same ratio for memory.
func (s Summary) MemHeadroom() (float64, bool) {
	return headroom(s.RequestMemMiB, s.Mem.Day)
}

func headroom(request int, st Stat) (float64, bool) {
	if request <= 0 || st.Thin() || st.P95 <= 0 {
		return 0, false
	}
	return float64(request) / float64(st.P95), true
}

// Summarize resolves every profile, ordered by application name.
func (s *Store) Summarize(now time.Time) []Summary {
	out := make([]Summary, 0, len(s.profiles))
	for app, p := range s.profiles {
		out = append(out, Summary{
			App:             app,
			Pods:            p.Pods,
			LastSeen:        p.LastSeen,
			Hours:           s.hours,
			RequestCPUMilli: p.RequestCPUMilli,
			RequestMemMiB:   p.RequestMemMiB,
			CPU: Windows{
				Hour: statOf(p.CPU.Window(now, 1)),
				Day:  statOf(p.CPU.Window(now, s.hours)),
			},
			Mem: Windows{
				Hour: statOf(p.Mem.Window(now, 1)),
				Day:  statOf(p.Mem.Window(now, s.hours)),
			},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].App < out[j].App })
	return out
}
