package cli

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
)

// isTerminal reports whether r is an interactive terminal. It uses only the
// standard library (os.ModeCharDevice), keeping the CLI prompt-library-free.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// prompter reads interactive answers from in and writes prompts to out (which
// is stderr, so stdout carries only command results).
type prompter struct {
	r   *bufio.Reader
	out io.Writer
}

func newPrompter(in io.Reader, out io.Writer) *prompter {
	return &prompter{r: bufio.NewReader(in), out: out}
}

// line asks for a required value.
func (p *prompter) line(label string) (string, error) {
	fprintf(p.out, "%s: ", label)
	return p.read()
}

// lineDefault asks for a value, returning def when the answer is blank.
func (p *prompter) lineDefault(label, def string) (string, error) {
	if def != "" {
		fprintf(p.out, "%s [%s]: ", label, def)
	} else {
		fprintf(p.out, "%s: ", label)
	}
	s, err := p.read()
	if err != nil {
		return "", err
	}
	if s == "" {
		return def, nil
	}
	return s, nil
}

// yesNo asks a yes/no question defaulting to no.
func (p *prompter) yesNo(label string) (bool, error) {
	fprintf(p.out, "%s [y/N]: ", label)
	s, err := p.read()
	if err != nil {
		return false, err
	}
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "y" || s == "yes", nil
}

// positiveFloat asks for a number > 0, repeating until one is given (the
// mandatory cost limit has no default and no "unlimited").
func (p *prompter) positiveFloat(label string) (float64, error) {
	for {
		fprintf(p.out, "%s: ", label)
		s, err := p.read()
		if err != nil {
			return 0, err
		}
		if v, perr := strconv.ParseFloat(strings.TrimSpace(s), 64); perr == nil && v > 0 {
			return v, nil
		}
		fprintln(p.out, "Please enter a positive number.")
	}
}

// read returns the next line with the trailing newline trimmed. A closed input
// with no pending content is an error, so an interactive loop cannot spin.
func (p *prompter) read() (string, error) {
	s, err := p.r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	s = strings.TrimRight(s, "\r\n")
	if errors.Is(err, io.EOF) && s == "" {
		return "", errors.New("input closed")
	}
	return s, nil
}
