package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
)

// hostileControls is what each of A28-3's rows hands a value or an error: an
// escape opening an OSC title write, the bell that ends it, and an
// erase-line. It is valid UTF-8 and has no slash, so a directory can be named
// with it too.
const hostileControls = "\x1b]0;pwned\x07\x1b[2K"

// hostilePath is a directory name carrying hostileControls.
const hostilePath = "cfg" + hostileControls

// hostileConfigDir is a config directory whose own path is hostile, so every
// error that names a file in it carries an escape, an OSC and a bell.
func hostileConfigDir(t *testing.T) config.Dir {
	t.Helper()
	root := filepath.Join(t.TempDir(), hostilePath)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return config.Dir(root)
}

// breakRecord leaves an instance's record unreadable and unwritable: a
// directory where metadata.yaml was, so reading or saving it fails with an
// error that names its path.
func breakRecord(t *testing.T, dir config.Dir, name string) {
	t.Helper()
	path := filepath.Join(dir.InstancePath(name), "metadata.yaml")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

// noControlBytes fails t if text carries a byte below 0x20 other than a
// newline or a tab, which an error keeps as the "farcast: <error>" line does.
func noControlBytes(t *testing.T, name, text string) {
	t.Helper()
	for i := 0; i < len(text); i++ {
		if c := text[i]; c < 0x20 && c != '\n' && c != '\t' {
			t.Errorf("%s carries the control byte %#x: %q", name, c, text)
			return
		}
	}
}

// quotedOnTheTerminal fails t if anything that reached the terminal carries a
// byte below 0x20 but a newline or a tab (noControlBytes), or any other rune that acts
// on one (onlyPrintable), or if the line the test drove is not there with
// hostileControls shown escaped rather than dropped.
func quotedOnTheTerminal(t *testing.T, want string, texts map[string]string) {
	t.Helper()
	var all strings.Builder
	for name, text := range texts {
		noControlBytes(t, name, text)
		onlyPrintable(t, name, text)
		all.WriteString(text)
	}
	if !strings.Contains(all.String(), want) || !strings.Contains(all.String(), `\x1b]0;pwned\a\x1b[2K`) {
		t.Errorf("the terminal does not show %q with the hostile text escaped:\n%q", want, texts)
	}
}

// rotationShown is what rotate prints of a hand-over: its keyholder line.
func rotationShown(t *testing.T, res handOverResult) string {
	t.Helper()
	var b bytes.Buffer
	if err := (keyRotateResult{Instance: "p", Keyholder: describeRotation(res, "p")}).Human(&b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// ADR 0023 M2.6d (A28-3). The texts the M2.6c review left printing raw, and
// what a sweep of the same files found beside them, are escaped: an error
// through output.ErrorText, which keeps its lines and escapes the rest in
// place, and a value the record holds through terminalText, which quotes
// it. Either, carrying an escape, an OSC and a bell, reaches neither stdout
// nor stderr with a byte below 0x20 but a newline or a tab, and is shown
// escaped. Printable text is unchanged: a printable error of several lines
// prints its lines as they are (the keyholder opener's row below), and the
// suites that pin each line show the rest.
func TestOlderRawTextsAreQuoted(t *testing.T) {
	refused := errors.New("refused " + hostileControls)

	// The hand-over's Problem and Reason, built from an error this file did
	// not write: run prints them on stderr, and rotate on its keyholder line.
	t.Run("hand-over: the keyholder could not be reached", func(t *testing.T) {
		sees := runWithOpener(t, "p501", func(context.Context, *Env, string) (sealStateClient, func(), error) {
			return nil, nil, refused
		})
		quotedOnTheTerminal(t, "the keyholder could not be reached: ", map[string]string{"stdout": sees.out.String(), "stderr": sees.err.String()})
	})
	// The opener's own error is three printable lines by design
	// (keyholderClientOver): an error keeps its lines, so they print as
	// they are, none folded into one quoted line.
	t.Run("hand-over: the keyholder opener's printable lines", func(t *testing.T) {
		lines := []string{
			`cannot reach "p510" through FatLine: dial tcp: refused`,
			"Storage cannot be unsealed while the tunnel is down, and applications keep receiving ErrStorageSealed until it returns.",
			"Check 'farcast connect p510 --status'.",
		}
		sees := runWithOpener(t, "p510", func(context.Context, *Env, string) (sealStateClient, func(), error) {
			return nil, nil, errors.New(strings.Join(lines, "\n"))
		})
		stderr := sees.err.String()
		want := "the keyholder could not be reached: " + strings.Join(lines, "\n") + ".\n"
		if !strings.Contains(stderr, want) {
			t.Errorf("the opener's three lines do not print as they are; want %q in:\n%s", want, stderr)
		}
	})
	handOver := func(t *testing.T, name string, rotate bool, opts handOverOptions) (handOverResult, *operatorSees) {
		t.Helper()
		dir, meta, env, sees, _ := backdatedInstance(t, name, "alpha")
		base := servingFleet(t, env, meta, dir)
		sees.err.Reset()
		keys := liveKeyring(t, dir, name)
		if rotate {
			k, rots, err := keys.RotateScopeKEKs()
			if err != nil {
				t.Fatal(err)
			}
			opts.rotated = map[string]datasphere.KeyID{}
			for _, r := range rots {
				opts.rotated[r.Scope] = r.Previous
			}
			keys = k
		}
		return handOverKeys(context.Background(), env, meta, openerFor(base), keys, opts), sees
	}
	for _, tc := range []struct {
		name, want string
		rotate     bool
		opts       handOverOptions
	}{
		{"hand-over: before the push", "refused ", false,
			handOverOptions{beforePush: func(sealStateClient) error { return refused }}},
		{"hand-over: before the hold, the key pin", "this keyring is behind the instance's key pin", true,
			handOverOptions{beforeHold: func(datasphere.Keyring) error {
				return fmt.Errorf("%w — %s", &pinBehind{Missing: []string{"00000000000000dd"}}, hostileControls)
			}}},
		{"hand-over: before the hold, the save", "could not record the keys it was about to hand over: ", true,
			handOverOptions{beforeHold: func(datasphere.Keyring) error { return refused }}},
		{"hand-over: before activation, the save", "could not save its keyring with them in use: ", true,
			handOverOptions{beforeActivate: func(sealStateClient) error { return refused }}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, sees := handOver(t, "p502", tc.rotate, tc.opts)
			if res.Problem == "" && res.Reason == "" {
				t.Fatalf("guard: the hand-over says nothing went wrong: %+v", res)
			}
			quotedOnTheTerminal(t, tc.want, map[string]string{
				"Problem": res.Problem, "Reason": res.Reason, "stderr": sees.err.String(), "rotate": rotationShown(t, res)})
		})
	}

	// The hand-over's warnings about this machine's own files: their errors
	// name a path, here a hostile one.
	t.Run("hand-over: the unseal ledger", func(t *testing.T) {
		dir, meta, env, sees := handOverInstanceIn(t, hostileConfigDir(t), "p503")
		keys := scopedKeyring(t, dir, "p503", "demo", "alpha")
		if err := os.MkdirAll(dir.InstanceUnsealLedgerPath("p503"), 0o700); err != nil {
			t.Fatal(err)
		}
		res := handOverKeys(context.Background(), env, meta, openerFor(&fakeStateKeyholder{phase: "unsealed"}), keys, handOverOptions{})
		if !res.Complete() {
			t.Fatalf("guard: the hand-over did not finish: %+v", res)
		}
		quotedOnTheTerminal(t, "warning: the unseal ledger could not be written: ", map[string]string{"stdout": sees.out.String(), "stderr": sees.err.String()})
	})
	t.Run("hand-over: recording the generation", func(t *testing.T) {
		dir, meta, env, sees := handOverInstanceIn(t, hostileConfigDir(t), "p504")
		keys := scopedKeyring(t, dir, "p504", "demo", "alpha")
		breakRecord(t, dir, "p504")
		res := handOverKeys(context.Background(), env, meta, openerFor(&fakeStateKeyholder{phase: "unsealed"}), keys, handOverOptions{})
		if res.RecordErr == nil {
			t.Fatalf("guard: recording the generation did not fail: %+v", res)
		}
		quotedOnTheTerminal(t, "but recording it failed: ", map[string]string{"stdout": sees.out.String(), "stderr": sees.err.String()})
	})

	// run (S-TERM-2): the path of keys.yaml it asks to back up again, which
	// names the config directory; the hand-over's notice when keys.yaml
	// cannot be read again, whose error names it too and is several lines
	// by design; and the keepers it names for re-enrolment, as the record
	// holds them.
	t.Run("run: the keyring's path", func(t *testing.T) {
		dir := hostileConfigDir(t)
		meta := runnableInstance(t, dir, "p511")
		meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 1}
		if err := dir.SaveInstanceMetadata("p511", meta); err != nil {
			t.Fatal(err)
		}
		mintKeyring(t, dir, "p511")
		env, out, errb := testEnvBoth(dir, output.ModeHuman)
		c := runCmd(newFakeRun(twoAppManifest))
		c.newKeyholder = openerFor(&fakeStateKeyholder{phase: "unsealed"})
		if err := c.Run(context.Background(), env, []string{"p511", "github.com/example/my-platform"}); err != nil {
			t.Fatalf("run: %v\n%s", err, errb)
		}
		quotedOnTheTerminal(t, "back it up again: \"", map[string]string{"stdout": out.String(), "stderr": errb.String()})
	})
	t.Run("run: keys.yaml unread at the hand-over", func(t *testing.T) {
		dir := hostileConfigDir(t)
		meta := runnableInstance(t, dir, "p512")
		meta.Keyholder = &config.Keyholder{Deployed: true, Replicas: 1}
		env, out, errb := testEnvBoth(dir, output.ModeHuman)
		c := runCmd(newFakeRun(twoAppManifest))
		if err := c.handScopesToTheKeyholder(context.Background(), env, meta, []string{"api"}, nil, nil); err != nil {
			t.Fatal(err)
		}
		quotedOnTheTerminal(t, "The keyholder does not hold api's scope yet — read the storage keyring for \"p512\": ",
			map[string]string{"stdout": out.String(), "stderr": errb.String()})
		if first := strings.SplitN(datasphere.KeyLossWarning, "\n", 2)[0]; !strings.Contains(errb.String(), "\n"+first) {
			t.Errorf("the keyring's error lost its lines:\n%s", errb.String())
		}
	})
	t.Run("run: the keepers to re-enrol", func(t *testing.T) {
		sees := runWithOpener(t, "p513", openerFor(&fakeStateKeyholder{phase: "unsealed"}), config.Keeper{Device: "desk" + hostileControls})
		quotedOnTheTerminal(t, "\"farcast keeper enroll p513 desk", map[string]string{"stdout": sees.out.String(), "stderr": sees.err.String()})
	})

	// storage deploy: the bucket grant names the record's project and
	// bucket, and the result its image.
	t.Run("storage deploy: the bucket grant's project", func(t *testing.T) {
		var b bytes.Buffer
		writeBucketGrant(&b, "proj"+hostileControls, "bucket-1", "ns", "sa")
		quotedOnTheTerminal(t, "gcloud projects describe \"proj", map[string]string{"stderr": b.String()})
	})
	t.Run("storage deploy: the bucket grant's bucket", func(t *testing.T) {
		var b bytes.Buffer
		writeBucketGrant(&b, "proj-1", "bucket"+hostileControls, "ns", "sa")
		quotedOnTheTerminal(t, "add-iam-policy-binding gs://\"bucket", map[string]string{"stderr": b.String()})
	})
	t.Run("storage deploy: the image", func(t *testing.T) {
		var b bytes.Buffer
		if err := (deployResult{Instance: "p", Image: "img" + hostileControls, Replicas: 2}).Human(&b); err != nil {
			t.Fatal(err)
		}
		quotedOnTheTerminal(t, "  image  \"img", map[string]string{"stdout": b.String()})
	})

	// connect: the reconnect's warning, the warning of a record that could
	// not be saved after the deploy, and the record's values in the result.
	t.Run("connect: the reconnect's warning", func(t *testing.T) {
		r := newConnectRig(t, reconnected)
		r.fp.ensureErr = refused
		stdout, stderr, err := r.run(t, output.ModeHuman, "--yes")
		if err != nil {
			t.Fatalf("a reconnect whose ensure failed: %v", err)
		}
		quotedOnTheTerminal(t, "Warning: ensure the image registry", map[string]string{"stdout": stdout, "stderr": stderr})
	})
	t.Run("connect: recording the deploy", func(t *testing.T) {
		r := newConnectRigIn(t, hostileConfigDir(t))
		r.fc.onApply = func() { breakRecord(t, r.dir, prodName) }
		stdout, stderr, _ := r.run(t, output.ModeHuman, "--yes")
		if len(r.fc.applied) == 0 {
			t.Fatalf("guard: nothing was applied:\n%s", stderr)
		}
		quotedOnTheTerminal(t, "but recording that locally failed: ", map[string]string{"stdout": stdout, "stderr": stderr})
	})
	for _, tc := range []struct {
		field, want string
		edit        func(*connectResult)
	}{
		{"endpoint", "carrier:     public mTLS NLB  \"203.0.113.1:8443", func(r *connectResult) { r.Endpoint += hostileControls }},
		{"registry", "registry:    \"registry-1", func(r *connectResult) { r.Registry += hostileControls }},
		{"image", "image:       \"image-1", func(r *connectResult) { r.Image += hostileControls }},
	} {
		t.Run("connect: the record's "+tc.field, func(t *testing.T) {
			r := connectResult{Name: "p", Connected: true, Endpoint: "203.0.113.1:8443", Registry: "registry-1", Image: "image-1"}
			tc.edit(&r)
			var b bytes.Buffer
			if err := r.Human(&b); err != nil {
				t.Fatal(err)
			}
			quotedOnTheTerminal(t, tc.want, map[string]string{"stdout": b.String()})
		})
	}

	// storage key pin and rotate: a keyholder that could not be reached when
	// the pin was to be handed over live.
	t.Run("storage key pin: the keyholder could not be reached", func(t *testing.T) {
		dir, _, env, sees := handOverInstance(t, "p505")
		scopedKeyring(t, dir, "p505", "demo", "alpha")
		c := &keyPinCommand{assumeYes: true, newKeyholder: func(context.Context, *Env, string) (sealStateClient, func(), error) {
			return nil, nil, refused
		}}
		if err := c.Run(context.Background(), env, []string{"p505"}); err != nil {
			t.Fatalf("key pin: %v", err)
		}
		quotedOnTheTerminal(t, "replicas: not handed to the replicas live (refused ", map[string]string{"stdout": sees.out.String(), "stderr": sees.err.String()})
	})
	t.Run("storage key rotate: the keyholder could not be reached for the pin", func(t *testing.T) {
		dir, meta, env, sees := handOverInstance(t, "p506")
		scopedKeyring(t, dir, "p506", "demo", "alpha")
		base := servingFleet(t, env, meta, dir)
		sees.err.Reset()
		opened := 0
		c := &keyRotateCommand{assumeYes: true, newKeyholder: func(context.Context, *Env, string) (sealStateClient, func(), error) {
			if opened++; opened == 1 {
				return base, func() {}, nil
			}
			return nil, nil, refused
		}}
		var unfinished rotationUnfinished
		if err := c.Run(context.Background(), env, []string{"p506"}); err != nil && !errors.As(err, &unfinished) {
			t.Fatalf("rotate: %v", err)
		}
		quotedOnTheTerminal(t, "not handed to the replicas live (refused ", map[string]string{"stdout": sees.out.String(), "stderr": sees.err.String()})
	})

	// rotate: a record that cannot be read after the keys were minted, and a
	// keyring that cannot be put back after a hand-over that left the new
	// keys unused; each error names a hostile path. And the keepers it names
	// for re-enrolment, as the record holds them.
	t.Run("storage key rotate: the record unread", func(t *testing.T) {
		dir, _, env, sees := handOverInstanceIn(t, hostileConfigDir(t), "p507")
		scopedKeyring(t, dir, "p507", "demo", "alpha")
		breakRecord(t, dir, "p507")
		_ = (&keyRotateCommand{assumeYes: true, newKeyholder: noKeyholder}).Run(context.Background(), env, []string{"p507"})
		quotedOnTheTerminal(t, "the instance's metadata could not be read (", map[string]string{"stdout": sees.out.String(), "stderr": sees.err.String()})
	})
	t.Run("storage key rotate: the keyring not put back", func(t *testing.T) {
		dir, meta, env, sees, _ := backdatedInstanceIn(t, hostileConfigDir(t), "p508", "alpha")
		base := servingFleet(t, env, meta, dir)
		sees.err.Reset()
		path := dir.InstanceKeyringPath("p508")
		fleet := &pushesThen{flakyKeyholder: &flakyKeyholder{fakeStateKeyholder: base, refuseNth: map[int]int{0: 2, 1: 2}}, at: 3, then: func() {
			// Another command writes keys.yaml as the new keys go over, so
			// putting this machine back is refused, naming the file.
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
		}}
		rotateWith(t, env, "p508", fleet)
		quotedOnTheTerminal(t, "This machine's keyring could NOT be put back (", map[string]string{"stdout": sees.out.String(), "stderr": sees.err.String()})
	})
	t.Run("storage key rotate: the keepers to re-enrol", func(t *testing.T) {
		var b bytes.Buffer
		if err := (keyRotateResult{Instance: "p", Active: true, Reenrol: []string{"desk" + hostileControls}}).Human(&b); err != nil {
			t.Fatal(err)
		}
		quotedOnTheTerminal(t, "farcast keeper enroll p desk", map[string]string{"stdout": b.String()})
	})

	// rekey: an object the listing could not name, named as the bucket names
	// it, and a dry run's refusal carrying an opener's error. Both are
	// several lines by design, and keep them.
	t.Run("storage key rekey: an object no key space names", func(t *testing.T) {
		env, out, _, f, _ := rekeyInstance(t)
		var errb bytes.Buffer
		env.Err = &errb
		f.objects["junk"+hostileControls] = datasphere.Object{Data: []byte("not a blob this module wrote")}
		kh := &fakeStateKeyholder{phase: "unsealed"}
		if err := (&keyRekeyCommand{dryRun: true, newKeyholder: openerFor(kh)}).Run(context.Background(), env, []string{"prod"}); err != nil {
			t.Fatalf("a dry run: %v", err)
		}
		quotedOnTheTerminal(t, "Warning: datasphere: recover name of stored object junk", map[string]string{"stdout": out.String(), "stderr": errb.String()})
	})
	t.Run("storage key rekey: why a real run would refuse", func(t *testing.T) {
		env, out, _, _, _ := rekeyInstance(t)
		var errb bytes.Buffer
		env.Err = &errb
		c := &keyRekeyCommand{dryRun: true, newKeyholder: func(context.Context, *Env, string) (sealStateClient, func(), error) {
			return nil, nil, refused
		}}
		if err := c.Run(context.Background(), env, []string{"prod"}); err != nil {
			t.Fatalf("a dry run: %v", err)
		}
		quotedOnTheTerminal(t, "but a real run would refuse: rekey cannot confirm", map[string]string{"stdout": out.String(), "stderr": errb.String()})
	})
}

// pushesThen is a fleet that runs then just before its at-th push, counted
// across every replica from 1.
type pushesThen struct {
	*flakyKeyholder
	n, at int
	then  func()
}

func (p *pushesThen) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	if p.n++; p.n == p.at {
		p.then()
	}
	return p.flakyKeyholder.Unseal(ctx, i, payload, intent)
}
