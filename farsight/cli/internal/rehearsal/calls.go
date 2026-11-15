package rehearsal

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// calls.log: one line for every request the rehearsal's cluster answers or
// refuses, its token endpoint's included, and for every request a keyholder
// refuses. It is how the walk sees what a read asked for, and that it asked
// for nothing more.

// appendCall adds one line to calls.log: the time, the caller, its
// arguments, and the outcome. A line never holds an environment value, a
// body or a token.
func appendCall(root, who string, args []string, outcome string) {
	line := time.Now().UTC().Format(time.RFC3339) + " " + who
	if len(args) > 0 {
		line += " " + quoteArgs(args)
	}
	line += " | " + strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, outcome) + "\n"
	f, err := os.OpenFile(filepath.Join(root, callsLog), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	_, _ = f.WriteString(line)
	_ = f.Close()
}

// quoteArgs joins arguments with spaces, Go-quoting any that is empty or is
// not plain, so one line stays one line. A path's query is plain: '?' and '&'
// end no line.
func quoteArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a != "" && strings.Trim(a, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-?&") == "" {
			out[i] = a
		} else {
			out[i] = strconv.Quote(a)
		}
	}
	return strings.Join(out, " ")
}
