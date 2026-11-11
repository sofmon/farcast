package keyholder

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// LedgerMode is the only mode the ledger may rest under. It sits beside the
// keyring, and it records where key material has been sent.
const LedgerMode = 0o600

// LedgerEntry is one push of key material into a cluster.
//
// It deliberately records WHERE material went and never WHAT went: no key, no
// bundle, no scope material. The value of the record is that it exists on
// hardware the cloud cannot reach or erase, so a fleet's ledgers can later be
// reconciled against what a cluster claims about its own restarts.
type LedgerEntry struct {
	Time       time.Time `json:"time"`
	Instance   string    `json:"instance"`
	Ordinal    int       `json:"ordinal"`
	Intent     string    `json:"intent"`
	Generation uint64    `json:"generation"`
	Phase      string    `json:"phase,omitempty"`
	Result     string    `json:"result"`

	// Device names the keeper that wrote this entry; empty means the operator
	// did, by hand. A fleet's ledgers are reconciled together, so an entry that
	// could not say which device produced it would be unattributable in exactly
	// the audit it exists for.
	Device string `json:"device,omitempty"`

	// Boot is the keyholder process this push landed in. Counting DISTINCT
	// boots against the number of reseeds is the whole of the audit: more
	// reseeds than boots means a process that had not restarted was asked for
	// key material (ADR 0008 finding 1).
	Boot string `json:"boot,omitempty"`

	// Push names one keeper push: the entry written before it (pending) and
	// the one written after it (its outcome) carry the same random value, and
	// only that outcome settles that entry. Pairing by replica instead would
	// let one push's outcome settle another's — two keeper processes on one
	// device, or an entry a torn line made unreadable — and leave the push
	// whose outcome WAS recorded counted as unconfirmed. Empty on every entry
	// a keeper did not write, and on every entry written before it existed.
	// It names nothing outside this ledger, and never leaves the device.
	Push string `json:"push,omitempty"`
}

// AppendLedger adds one entry.
//
// It appends and never rewrites: an operator investigating an unexplained
// unseal needs the history the tooling could otherwise have tidied away. A
// failure to write is returned rather than swallowed — a push that went
// unrecorded is exactly the one that matters later.
//
// An entry returned nil for is readable afterwards. A write that failed
// part-way — a full disk returns the bytes it took with the error, and a
// crash mid-write leaves them too — ends the file in a fragment with no
// newline, and a record appended straight after it would be fused to it and
// dropped by ReadLedger as damaged: a pending entry would then stand on disk
// for a push and be read by nothing. So a file that does not end in a newline
// gets one first, and the fragment stays behind as a line of its own, which
// ReadLedger skips.
func AppendLedger(path string, e LedgerEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("keyholder: preparing the ledger directory: %w", err)
	}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("keyholder: encoding a ledger entry: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, LedgerMode)
	if err != nil {
		return fmt.Errorf("keyholder: opening the ledger: %w", err)
	}
	defer func() { _ = f.Close() }()
	record := append(line, '\n')
	torn, err := endsTorn(f)
	if err != nil {
		return fmt.Errorf("keyholder: reading the ledger's last line: %w", err)
	}
	if torn {
		record = append([]byte{'\n'}, record...)
	}
	if _, err := f.Write(record); err != nil {
		return fmt.Errorf("keyholder: writing the ledger: %w", err)
	}
	return f.Sync()
}

// endsTorn reports whether the ledger's last byte is anything but a newline:
// what a write that failed part-way leaves.
func endsTorn(f *os.File) (bool, error) {
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if info.Size() == 0 {
		return false, nil
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, info.Size()-1); err != nil {
		return false, err
	}
	return last[0] != '\n', nil
}

// ReadLedger returns every entry, oldest first. Phase 5.4's keeper audit is
// its first real reader; 3.2 uses it to show an operator what this machine has
// already done.
func ReadLedger(path string) ([]LedgerEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("keyholder: reading the ledger: %w", err)
	}
	var out []LedgerEntry
	for line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var e LedgerEntry
		if err := json.Unmarshal(line, &e); err != nil {
			// A damaged line is skipped rather than failing the read: a
			// partially written record must not make the rest unreadable.
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func splitLines(data []byte) func(func([]byte) bool) {
	return func(yield func([]byte) bool) {
		start := 0
		for i := range data {
			if data[i] == '\n' {
				if !yield(data[start:i]) {
					return
				}
				start = i + 1
			}
		}
		if start < len(data) {
			yield(data[start:])
		}
	}
}
