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
}

// AppendLedger adds one entry.
//
// It appends and never rewrites: an operator investigating an unexplained
// unseal needs the history the tooling could otherwise have tidied away. A
// failure to write is returned rather than swallowed — a push that went
// unrecorded is exactly the one that matters later.
func AppendLedger(path string, e LedgerEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("keyholder: preparing the ledger directory: %w", err)
	}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("keyholder: encoding a ledger entry: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, LedgerMode)
	if err != nil {
		return fmt.Errorf("keyholder: opening the ledger: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("keyholder: writing the ledger: %w", err)
	}
	return f.Sync()
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
