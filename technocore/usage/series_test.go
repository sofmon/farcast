package usage

import (
	"encoding/json"
	"testing"
	"time"
)

func at(hour, minute int) time.Time {
	return time.Date(2026, 9, 9, hour, minute, 0, 0, time.UTC)
}

func TestWindowMergesOnlyTheHoursAskedFor(t *testing.T) {
	s := NewSeries(24)
	for h := 0; h < 6; h++ {
		s.Sample(at(h, 10), 100+h)
		s.Sample(at(h, 40), 100+h)
	}
	now := at(5, 50)

	if got := s.Window(now, 1); got.Count() != 2 || got.Peak() != 105 {
		t.Errorf("the last hour has %d samples peaking at %d, want 2 at 105", got.Count(), got.Peak())
	}
	if got := s.Window(now, 24); got.Count() != 12 || got.Peak() != 105 {
		t.Errorf("the day has %d samples peaking at %d, want 12 at 105", got.Count(), got.Peak())
	}
	if got := s.Window(now, 0); got.Count() != 0 {
		t.Errorf("a zero-hour window returned %d samples", got.Count())
	}
}

// The window is what bounds the stored size. An instance up for a week must
// hold exactly what one up for a day holds.
func TestSlotsFallOutOfTheWindow(t *testing.T) {
	s := NewSeries(3)
	base := at(0, 0)
	for h := 0; h < 100; h++ {
		s.Sample(base.Add(time.Duration(h)*time.Hour), 42)
	}
	if len(s.Slots) != 3 {
		t.Fatalf("kept %d slots, want 3", len(s.Slots))
	}
	if got := s.Window(base.Add(99*time.Hour), 3); got.Count() != 3 {
		t.Errorf("the window holds %d samples, want 3", got.Count())
	}
}

// A gap must stay a gap. Folding a restart's missing hours into the
// neighbouring slots would report a distribution over time nothing observed.
func TestAGapIsAMissingSlotNotASmearedOne(t *testing.T) {
	s := NewSeries(24)
	s.Sample(at(1, 0), 10)
	s.Sample(at(9, 0), 20)
	if len(s.Slots) != 2 {
		t.Fatalf("kept %d slots across an eight-hour gap, want 2", len(s.Slots))
	}
	if got := s.Window(at(9, 30), 4); got.Count() != 1 {
		t.Errorf("a four-hour window over the gap holds %d samples, want just the recent one", got.Count())
	}
}

func TestASampleOlderThanTheNewestSlotIsDroppedNotMisfiled(t *testing.T) {
	s := NewSeries(24)
	s.Sample(at(5, 0), 100)
	s.Sample(at(3, 0), 999) // clock went backwards
	if len(s.Slots) != 1 || s.Slots[0].Dist.Peak() != 100 {
		t.Fatalf("the out-of-order sample landed somewhere: %d slots, peak %d", len(s.Slots), s.Slots[0].Dist.Peak())
	}
	// The same hour as an existing slot is not out of order, and must land.
	s.Sample(at(5, 30), 200)
	if got := s.Slots[0].Dist.Count(); got != 2 {
		t.Errorf("the same-hour sample was dropped: count %d, want 2", got)
	}
}

// Shrinking is by hour, not by slot count: an instance that restarted has
// gaps, and dropping the first N slots would throw away more than asked.
func TestShrinkDropsByHourNotByCount(t *testing.T) {
	s := NewSeries(24)
	s.Sample(at(1, 0), 1)
	s.Sample(at(2, 0), 2)
	s.Sample(at(20, 0), 3)
	s.Sample(at(21, 0), 4)
	s.Shrink(3)
	if s.Hours != 3 {
		t.Fatalf("retained window is %d hours, want 3", s.Hours)
	}
	if len(s.Slots) != 2 {
		t.Fatalf("kept %d slots, want the two inside the last three hours", len(s.Slots))
	}
	if s.Slots[0].Hour != hourOf(at(20, 0)) {
		t.Errorf("kept the wrong slots: first is hour %d", s.Slots[0].Hour)
	}
	s.Shrink(99) // never grows
	if s.Hours != 3 {
		t.Errorf("Shrink widened the window to %d", s.Hours)
	}
}

func TestSeriesSurvivesJSON(t *testing.T) {
	s := NewSeries(6)
	for h := 0; h < 6; h++ {
		s.Sample(at(h, 0), 50*(h+1))
	}
	blob, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back Series
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if back.Hours != 6 || len(back.Slots) != 6 {
		t.Fatalf("round trip gave %d hours and %d slots", back.Hours, len(back.Slots))
	}
	if statOf(back.Window(at(5, 30), 6)) != statOf(s.Window(at(5, 30), 6)) {
		t.Error("round trip changed the window")
	}
}
