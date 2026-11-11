package cli

import (
	"fmt"
	"io"
	"strconv"

	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// fprintf writes formatted text to w, intentionally ignoring the write
// error: a failure writing usage, help, or diagnostics to the user's
// terminal is not recoverable and not worth surfacing.
func fprintf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// fprintln writes a line to w, intentionally ignoring the write error (see
// fprintf).
func fprintln(w io.Writer, args ...any) {
	_, _ = fmt.Fprintln(w, args...)
}

// terminalText is s made safe to put in front of an operator: s itself when
// every rune of it prints, and its Go-quoted form otherwise.
//
// It exists for text somebody else wrote. A manifest comes from a repository
// the operator is deciding whether to trust, and the parser checks only that a
// declaration's reason is not empty — so a reason can carry an escape sequence
// that erases the line above it, a carriage return that overwrites the host it
// sits beside, a newline that forges a declaration of its own, or a bidi
// override that reverses what is read. Every one of those would rewrite the
// review that is the gate. Quoting rather than stripping keeps the evidence:
// the operator sees that the text was strange, and what it was.
//
// What prints is output.Printable's rule: unicode.IsPrint rather than a check
// for ASCII control characters, because the bidi overrides are format
// characters (Cf), not controls; and invalid UTF-8 never prints, because a
// lone 0x9b is CSI to a terminal reading 8-bit controls. The "farcast:
// <error>" line applies the same rule, line by line, so there is one
// definition of what reaches the terminal raw.
func terminalText(s string) string {
	if !output.Printable(s) {
		return strconv.QuoteToGraphic(s)
	}
	return s
}
