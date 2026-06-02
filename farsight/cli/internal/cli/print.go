package cli

import (
	"fmt"
	"io"
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
