// Package output renders command results and errors in either human-readable
// or JSON form, keeping formatting concerns out of the commands themselves.
package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
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

// KindInternal is the kind of an error nothing classified: the default, and
// never a promise that the failure was FarCast's own fault.
const KindInternal = "internal"

// Kinded is an error that names its own kind, one of the CLI's closed set
// (farsight/cli/README.md, "Error kinds"). The output package does not own
// that set; it only carries whatever the error says.
type Kinded interface {
	error
	ErrorKind() string
}

// KindOf is the kind err carries anywhere in its chain, or KindInternal.
func KindOf(err error) string {
	var k Kinded
	if errors.As(err, &k) {
		if kind := k.ErrorKind(); kind != "" {
			return kind
		}
	}
	return KindInternal
}

// PrintError reports an error. In JSON mode it writes a structured envelope
// to Out (carrying the intended exit code and the error's kind) with the
// message exactly as it is; in human mode it writes a "farcast: …" line to
// Err, through errorText. The kind is additive: a reader that knew only the
// message and the code reads the same two fields it always did.
func (p *Printer) PrintError(err error, code int) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if p.Mode == ModeJSON {
		enc := json.NewEncoder(p.Out)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(errorEnvelope{Error: errorBody{Message: msg, Code: code, Kind: KindOf(err)}})
		return
	}
	// Best-effort: a failed write to the user's stderr is not recoverable.
	_, _ = fmt.Fprintf(p.Err, "farcast: %s\n", errorText(msg))
}

// printableRune is the one rule for which runes of somebody else's text may
// reach an operator's terminal as they are: the ones unicode.IsPrint accepts.
// That refuses every C0 and C1 control — an escape, a carriage return, a
// bell, U+009B — and also the bidi overrides and the other format characters
// (Cf), which are not controls but reorder what is read. Printable and
// errorText both ask it, and the CLI's renderers ask Printable, so there is
// one definition.
func printableRune(r rune) bool { return unicode.IsPrint(r) }

// Printable reports whether s may be shown to an operator as it is: valid
// UTF-8, and every rune of it printable. Invalid UTF-8 is refused on its own
// account: a lone 0x9b is CSI to a terminal reading 8-bit controls, and a
// range over the string would see only U+FFFD, which prints.
func Printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !printableRune(r) {
			return false
		}
	}
	return true
}

// errorText is an error message made safe to print in front of an operator,
// line by line.
//
// An error is not a renderer's field: it is prose this machine wrote, often
// over several lines, that can carry text from outside the machine — a
// keyholder's refusal, a monitor's status line, a keeper's reason. Quoting it
// whole, as a renderer quotes a field, would fold a legitimate multi-line
// error onto one line. So the newlines that separate its lines stay, and so
// do tabs. Every other rune that is not printable prints as its Go escape
// (\x1b, \r, \a, \u202e) in place, and every byte that is not UTF-8 as \xNN:
// the line keeps its words, and loses only the power to act on the terminal.
// Text with nothing to escape comes back unchanged.
func errorText(msg string) string {
	var b strings.Builder
	b.Grow(len(msg))
	for i := 0; i < len(msg); {
		r, size := utf8.DecodeRuneInString(msg[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			q := strconv.QuoteToASCII(msg[i : i+1]) // "\xNN"
			b.WriteString(q[1 : len(q)-1])
		case r == '\n' || r == '\t' || printableRune(r):
			b.WriteString(msg[i : i+size])
		default:
			q := strconv.QuoteRuneToASCII(r) // '\x1b', '\r', '\u202e'
			b.WriteString(q[1 : len(q)-1])
		}
		i += size
	}
	return b.String()
}

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Kind    string `json:"kind"`
}

// ErrorText is errorText for a caller outside this package: an error message
// made safe to print line by line, keeping its newlines and tabs.
func ErrorText(msg string) string { return errorText(msg) }
