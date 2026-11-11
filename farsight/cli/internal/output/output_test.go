package output

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

type sampleResult struct {
	Msg string `json:"msg"`
}

func (r sampleResult) Human(w io.Writer) error {
	_, err := io.WriteString(w, "human: "+r.Msg)
	return err
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": ModeHuman, "human": ModeHuman, "json": ModeJSON} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Errorf("ParseMode(%q) = (%v, %v), want (%v, nil)", in, got, err, want)
		}
	}
	if _, err := ParseMode("xml"); err == nil {
		t.Error("ParseMode(xml) should error")
	}
}

func TestPrinterHuman(t *testing.T) {
	var out, errb bytes.Buffer
	p := &Printer{Mode: ModeHuman, Out: &out, Err: &errb}
	if err := p.Print(sampleResult{Msg: "hi"}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "human: hi" {
		t.Errorf("out = %q", out.String())
	}
}

func TestPrinterJSON(t *testing.T) {
	var out, errb bytes.Buffer
	p := &Printer{Mode: ModeJSON, Out: &out, Err: &errb}
	if err := p.Print(sampleResult{Msg: "hi"}); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(out.String()); got != `{"msg":"hi"}` {
		t.Errorf("out = %q, want {\"msg\":\"hi\"}", got)
	}
}

func TestPrintErrorHuman(t *testing.T) {
	var out, errb bytes.Buffer
	p := &Printer{Mode: ModeHuman, Out: &out, Err: &errb}
	p.PrintError("boom", 1)
	if errb.String() != "farcast: boom\n" {
		t.Errorf("err = %q", errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout should be empty, got %q", out.String())
	}
}

func TestPrintErrorJSON(t *testing.T) {
	var out, errb bytes.Buffer
	p := &Printer{Mode: ModeJSON, Out: &out, Err: &errb}
	p.PrintError("boom", 2)

	var env struct {
		Error struct {
			Message string `json:"message"`
			Code    int    `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if env.Error.Message != "boom" || env.Error.Code != 2 {
		t.Errorf("envelope = %+v", env)
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty, got %q", errb.String())
	}
}

// Printable is the rule every renderer asks: valid UTF-8, and nothing
// unicode.IsPrint refuses — so a bidi override fails it as surely as an
// escape, and a lone byte that is not UTF-8 fails it although a range over the
// string sees only U+FFFD.
func TestPrintable(t *testing.T) {
	for in, want := range map[string]bool{
		"":                                  true,
		"payment processing":                true,
		"paiement à l'étranger — ça marche": true,
		"支払い処理":                             true,
		"\ufffd":                            true,
		"a\x1b[2Kb":                         false,
		"a\rb":                              false,
		"a\nb":                              false,
		"a\tb":                              false,
		"a\x07b":                            false,
		"a\u009bb":                          false,
		"a\x9bb":                            false,
		"a\u202eb":                          false,
		"a\u200fb":                          false,
	} {
		if got := Printable(in); got != want {
			t.Errorf("Printable(%q) = %t, want %t", in, got, want)
		}
	}
}

// hostileError is an error this machine wrote around text that came from
// outside it, over three lines: a keyholder's refusal carrying an OSC 52
// clipboard write ended by BEL, an erase-line, a carriage return, a raw C1
// CSI byte (not UTF-8), U+009B and a bidi override; an indented line quoting a
// monitor that tries to erase the line above; and this machine's own advice.
const hostileError = "keyholder replica 1 refused the keys: x\x1b]52;c;ZXZpbA==\x07\x1b[2K\r\x9b\u009b\u202e\n" +
	"\tthe monitor answered 503 \x1b[1A\x1b[2KService Unavailable\n" +
	"Run 'farcast storage unseal p' again."

// An error printed in human mode can carry a keyholder's refusal or a
// monitor's status line. Line by line, every rune that would act on the
// terminal prints as its escape instead — and nothing else changes: the lines
// stay lines, the tab stays a tab, and the words stay where they were.
func TestPrintErrorHumanEscapesWhatWouldActOnTheTerminal(t *testing.T) {
	var out, errb bytes.Buffer
	p := &Printer{Mode: ModeHuman, Out: &out, Err: &errb}
	p.PrintError(hostileError, 1)
	got := errb.String()
	t.Log("\n" + got)

	if !utf8.ValidString(got) {
		t.Fatalf("bytes that are not UTF-8 reached the terminal:\n%q", got)
	}
	for _, r := range got {
		if r != '\n' && r != '\t' && !unicode.IsPrint(r) {
			t.Fatalf("%U reached the terminal raw:\n%q", r, got)
		}
	}
	if want, n := strings.Count(hostileError, "\n")+1, strings.Count(got, "\n"); n != want || !strings.HasSuffix(got, "\n") {
		t.Fatalf("%d line(s) printed; want %d, each ended — a line was joined or split:\n%q", n, want, got)
	}
	want := "farcast: keyholder replica 1 refused the keys: x\\x1b]52;c;ZXZpbA==\\a\\x1b[2K\\r\\x9b\\u009b\\u202e\n" +
		"\tthe monitor answered 503 \\x1b[1A\\x1b[2KService Unavailable\n" +
		"Run 'farcast storage unseal p' again.\n"
	if got != want {
		t.Errorf("printed\n%q\nwant\n%q", got, want)
	}
	if out.Len() != 0 {
		t.Errorf("stdout should be empty, got %q", out.String())
	}
}

// Text with nothing to escape prints exactly as it was given: a multi-line
// error with an indented line, non-ASCII prose and a U+FFFD that is valid
// UTF-8 is still the error it was.
func TestPrintErrorHumanLeavesPrintableTextAlone(t *testing.T) {
	msg := "instance \"prod\" has no keyring on this machine: open keyring: no such file\n" +
		"\tpaiement à l'étranger — ça marche, 支払い処理, \ufffd\n" +
		"Storage keys live only here."
	var out, errb bytes.Buffer
	(&Printer{Mode: ModeHuman, Out: &out, Err: &errb}).PrintError(msg, 1)
	if want := "farcast: " + msg + "\n"; errb.String() != want {
		t.Errorf("printed %q, want %q", errb.String(), want)
	}
}

// --output json carries an error as it came: the envelope is what encoding/json
// makes of the raw message, byte for byte, and nothing is escaped on the way.
func TestPrintErrorJSONCarriesTheMessageAsItCame(t *testing.T) {
	var out, errb bytes.Buffer
	(&Printer{Mode: ModeJSON, Out: &out, Err: &errb}).PrintError(hostileError, 1)

	var want bytes.Buffer
	enc := json.NewEncoder(&want)
	enc.SetEscapeHTML(false)
	type body struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	}
	if err := enc.Encode(struct {
		Error body `json:"error"`
	}{body{Message: hostileError, Code: 1}}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), want.Bytes()) {
		t.Errorf("JSON envelope\n%s\nwant\n%s", out.Bytes(), want.Bytes())
	}
	var env struct {
		Error body `json:"error"`
	}
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	// encoding/json makes the one byte that is not UTF-8 into U+FFFD, as it
	// always has; everything else is the message as it came.
	if env.Error.Message != strings.ToValidUTF8(hostileError, "\ufffd") {
		t.Errorf("message = %q, want %q", env.Error.Message, hostileError)
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty, got %q", errb.String())
	}
}
