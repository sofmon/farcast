package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	dskeyholder "github.com/sofmon/farcast/datasphere/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// What a replica says reaches this machine's own words in more places than a
// renderer's fields. Each test below drives one such place with text built to
// act on the terminal and to forge a line of its own, and checks that it
// arrives quoted: a replica's words keep their content and lose their power.

// forgedPinRow is a replica's text that ends by starting a line of its own.
const forgedPinRow = hostileText + "\n  replica 9  enforcing it"

// pinRaiseFails fails every live pin raise with err — an error that is not a
// refusal, so nothing but the site that puts it in a row can quote it.
type pinRaiseFails struct {
	*fakeStateKeyholder
	err error
}

func (p pinRaiseFails) RaisePin(context.Context, int, string, bool) (keyholder.State, error) {
	return keyholder.State{}, p.err
}

// Review finding R3-1 (code). A replica that did not take the pin live is a
// row whose note carries the error, and 'storage key pin' prints the note on
// stdout — rotate and run print it as a warning. The error's text goes in
// quoted.
func TestAPinRaiseNoteQuotesTheReplicasError(t *testing.T) {
	rows := raisePins(context.Background(), pinRaiseFails{&fakeStateKeyholder{phase: "unsealed"}, errors.New(forgedPinRow)}, 2, dskeyholder.Pin{}, false, "prod", nil)
	var b bytes.Buffer
	if err := (keyPinResult{Instance: "prod", Written: true, Replicas: rows}).Human(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "did not take the pin live") {
		t.Fatalf("guard: no replica failed the raise:\n%s", out)
	}
	onlyPrintable(t, "storage key pin", out)
	if strings.Contains(out, "\n  replica 9") {
		t.Errorf("the replica's error forged a row:\n%s", out)
	}
}

// phaseAndStateLie is a fleet whose replica 0 reports a phase built to forge a
// bullet, and whose replica 1 fails its State call with one.
type phaseAndStateLie struct{ *fakeStateKeyholder }

func (p phaseAndStateLie) State(ctx context.Context, i int) (keyholder.State, error) {
	if i == 1 {
		return keyholder.State{}, errors.New(hostileText + "\n  - replica 9 holds every key")
	}
	return p.fakeStateKeyholder.State(ctx, i)
}

// Review finding R3-2 (code). Rekey's gate lists its problems one bullet per
// line, and a dry run prints that list as it is (a real run returns it as its
// error). A replica's phase and its State error go in quoted: the list keeps
// its own lines and gains none.
func TestTheRekeyGateQuotesWhatAReplicaSaid(t *testing.T) {
	dir, env := keyholderInstance(t, true)
	k := scopedKeyring(t, dir, "prod", "demo", "alpha")
	kh := &fakeStateKeyholder{phase: "unsealed"}
	kh.replica(0).phase = hostileText + "\n  - replica 9 holds every key"
	touched := map[string]bool{}
	for _, s := range k.Scopes() {
		touched[s.Name] = true
	}
	gateErr := (&keyRekeyCommand{dryRun: true, newKeyholder: openerFor(phaseAndStateLie{kh})}).gate(context.Background(), env, "prod", k, touched)
	if gateErr == nil {
		t.Fatal("guard: the gate did not refuse")
	}
	var b bytes.Buffer
	if err := (keyRekeyResult{Instance: "prod", DryRun: true, Blocked: gateErr.Error(), Status: "would rekey"}).Human(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"replica 0 is \"x", "replica 1 did not answer (\"x", "\nRun:\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("guard: the refusal lacks %q:\n%s", want, out)
		}
	}
	onlyPrintable(t, "rekey --dry-run", out)
	if strings.Contains(out, "\n  - replica 9") {
		t.Errorf("a replica's words forged a bullet:\n%s", out)
	}
}

// Review finding R3-4 (code). A serving replica can name a scope this keyring
// does not hold, or a key it does not, and the refusal that names them is a
// hand-over's problem and a returned error, which keeps its newlines. Those
// names — the replica's alone — go in quoted.
func TestAReplicaCheckQuotesNamesOnlyTheReplicaSupplied(t *testing.T) {
	dir, _ := keyholderInstance(t, true)
	k := scopedKeyring(t, dir, "prod", "demo", "alpha")
	scope := k.Scopes()[0].Name
	for _, tc := range []struct {
		name string
		keys map[string][]string
	}{
		{"a scope", map[string][]string{forgedPinRow: {"k"}}},
		{"a key", map[string][]string{scope: {k.Scopes()[0].Keyring().KEKs()[0].ID.String(), forgedPinRow}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkReplica("prod", k, 0, keyholder.State{Phase: "unsealed", Keys: tc.keys, Pin: &dskeyholder.PinReport{Status: dskeyholder.PinAbsent}})
			if err == nil {
				t.Fatal("guard: the replica was not refused")
			}
			if !strings.Contains(err.Error(), `"x\x1b]52`) {
				t.Errorf("guard: the replica's name is not in the refusal, quoted: %q", err.Error())
			}
			if strings.ContainsAny(err.Error(), "\n\x1b\r") {
				t.Errorf("the replica's name reached the refusal raw: %q", err.Error())
			}
		})
	}
}

// belowPinForger refuses every push as below the pin, with a reason that
// carries a line of its own.
type belowPinForger struct{ *fakeStateKeyholder }

func (belowPinForger) Unseal(_ context.Context, i int, _ []byte, _ string) (keyholder.State, error) {
	return keyholder.State{}, &keyholder.Refusal{Ordinal: i, Code: dskeyholder.CodeBelowPin,
		Reason: "pin\nfarcast: forged: storage unsealed, 2 of 2 replicas serve generation 9", Status: 409}
}

// Review finding R3-3 (code), end to end. An unseal a replica refuses as
// below the pin returns an error built around the refusal, and the error line
// keeps its newlines: the replica's newline started a "farcast: …" line of its
// own on stderr. The refusal quotes its reason now, so it cannot.
func TestAnUnsealErrorCannotForgeALineFromARefusal(t *testing.T) {
	dir, env := keyholderInstance(t, true)
	scopedKeyring(t, dir, "prod", "demo", "alpha")
	var stdout, stderr bytes.Buffer
	env.Out, env.Err = &stdout, &stderr
	env.Printer = &output.Printer{Mode: output.ModeHuman, Out: &stdout, Err: &stderr}
	err := (&storageUnsealCommand{newKeyholder: openerFor(belowPinForger{&fakeStateKeyholder{phase: "unsealed"}})}).Run(context.Background(), env, []string{"prod"})
	if err == nil {
		t.Fatal("guard: the unseal succeeded")
	}
	env.Printer.PrintError(err.Error(), 1)
	if !strings.Contains(stderr.String(), `pin\nfarcast: forged`) {
		t.Errorf("guard: the refusal is not in the error, quoted:\n%s", stderr.String())
	}
	for _, line := range strings.Split(stderr.String(), "\n") {
		if strings.HasPrefix(line, "farcast: forged") {
			t.Errorf("the replica's refusal forged a line of its own: %q", line)
		}
	}
}
