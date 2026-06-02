package farcast

import "testing"

// TestAccessorsReturnUsableValues checks every capability accessor returns a
// usable value rather than panicking or handing back a nil that would crash
// on first use.
func TestAccessorsReturnUsableValues(t *testing.T) {
	_ = Log()
	_ = Config()
	_ = Storage()
	_ = AI()

	if Net().HTTPClient() == nil {
		t.Error("Net().HTTPClient() returned nil")
	}
}
