package usage

import "time"

// DefaultHours is how far back a profile remembers. A day covers a full cycle
// of whatever the operator's day looks like, which is the shortest window in
// which "this application is quiet at night" and "this application is quiet"
// are distinguishable.
const DefaultHours = 24

// Series is a rolling window of hourly distributions.
//
// Slots are kept in ascending hour order and only while they are inside the
// window, so the encoded size is fixed by the window rather than by how long
// the instance has been up. An instance running for a year stores exactly
// what one running for a day stores.
type Series struct {
	Hours int    `json:"h"`
	Slots []Slot `json:"s,omitempty"`
}

// Slot is one hour's distribution. Hour is hours since the Unix epoch, which
// is what makes a gap — a restart, a stall — visible as a missing slot rather
// than as an hour of silently attributed samples.
type Slot struct {
	Hour int        `json:"t"`
	Dist *Histogram `json:"d"`
}

// NewSeries returns a series retaining the given number of hours.
func NewSeries(hours int) *Series {
	if hours <= 0 {
		hours = DefaultHours
	}
	return &Series{Hours: hours}
}

func hourOf(t time.Time) int { return int(t.Unix() / 3600) }

// Sample records one observation at a moment.
//
// A sample older than the retained window is dropped rather than folded into
// the oldest slot: the window means something, and a restored profile that
// took in an hour-old reading as though it were current would blur exactly
// the comparison the window exists to support.
func (s *Series) Sample(at time.Time, v int) {
	if s.Hours <= 0 {
		s.Hours = DefaultHours
	}
	h := hourOf(at)
	for i := len(s.Slots) - 1; i >= 0; i-- {
		if s.Slots[i].Hour == h {
			s.Slots[i].Dist.Sample(v)
			return
		}
		if s.Slots[i].Hour < h {
			break
		}
	}
	if n := len(s.Slots); n > 0 && s.Slots[n-1].Hour > h {
		return // out of order and older than the newest slot
	}
	dist := &Histogram{}
	dist.Sample(v)
	s.Slots = append(s.Slots, Slot{Hour: h, Dist: dist})
	s.evict(h)
}

// evict drops slots that have fallen out of the window.
func (s *Series) evict(nowHour int) {
	oldest := nowHour - s.Hours + 1
	keep := 0
	for keep < len(s.Slots) && s.Slots[keep].Hour < oldest {
		keep++
	}
	if keep > 0 {
		s.Slots = append(s.Slots[:0], s.Slots[keep:]...)
	}
}

// Window merges the last n hours, ending with the hour containing now.
//
// The window is aligned to clock hours rather than sliding, so a call one
// minute past the hour with n=1 sees one minute of samples. That is visible
// rather than hidden: the merged histogram carries its own count, and every
// reader of this package reports it.
func (s *Series) Window(now time.Time, n int) *Histogram {
	out := &Histogram{}
	if n <= 0 {
		return out
	}
	nowHour := hourOf(now)
	oldest := nowHour - n + 1
	for i := range s.Slots {
		if s.Slots[i].Hour >= oldest && s.Slots[i].Hour <= nowHour {
			out.Merge(s.Slots[i].Dist)
		}
	}
	return out
}

// Shrink reduces the retained window, dropping the oldest slots to fit. It is
// what makes the byte budget degrade uniformly: everybody loses an hour
// before anybody loses a profile.
func (s *Series) Shrink(hours int) {
	if hours < 1 {
		hours = 1
	}
	if hours >= s.Hours {
		return
	}
	s.Hours = hours
	if n := len(s.Slots); n > 0 {
		// By hour, not by count: slots are absent for hours nothing was
		// sampled, so dropping the first (len-hours) of them would throw away
		// more history than asked for on any instance that has restarted.
		s.evict(s.Slots[n-1].Hour)
	}
}

// Empty reports whether the series holds nothing.
func (s *Series) Empty() bool { return len(s.Slots) == 0 }
