// Package output renders command results and errors in either human-readable
// or JSON form, keeping formatting concerns out of the commands themselves.
package output

import (
	"encoding/json"
	"fmt"
	"io"
)

// Mode selects how results are rendered.
type Mode int

const (
	ModeHuman Mode = iota
	ModeJSON
)

// ParseMode maps the --output flag value to a Mode.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "", "human":
		return ModeHuman, nil
	case "json":
		return ModeJSON, nil
	default:
		return ModeHuman, fmt.Errorf("invalid output mode %q (want human or json)", s)
	}
}

// Result is a command result that can render itself for humans. JSON output
// uses the value's standard JSON marshaling.
type Result interface {
	Human(w io.Writer) error
}

// Printer renders results to Out and human-mode error messages to Err.
type Printer struct {
	Mode Mode
	Out  io.Writer
	Err  io.Writer
}

// Print writes r in the configured mode.
func (p *Printer) Print(r Result) error {
	if p.Mode == ModeJSON {
		enc := json.NewEncoder(p.Out)
		enc.SetEscapeHTML(false)
		return enc.Encode(r)
	}
	return r.Human(p.Out)
}

// PrintError reports an error. In JSON mode it writes a structured envelope
// to Out (carrying the intended exit code); in human mode it writes a
// "farcast: …" line to Err.
func (p *Printer) PrintError(msg string, code int) {
	if p.Mode == ModeJSON {
		enc := json.NewEncoder(p.Out)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(errorEnvelope{Error: errorBody{Message: msg, Code: code}})
		return
	}
	// Best-effort: a failed write to the user's stderr is not recoverable.
	_, _ = fmt.Fprintf(p.Err, "farcast: %s\n", msg)
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}
