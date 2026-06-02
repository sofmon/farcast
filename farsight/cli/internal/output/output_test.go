package output

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
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
