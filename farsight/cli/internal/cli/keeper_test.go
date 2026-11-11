package cli

// `farcast keeper` — the operator's half (enroll, revoke) and the device's
// half (install), driven end to end over real key material.
//
// Nothing here is stubbed above the crypto: enrolment mints a real leaf from a
// real per-instance CA and seals a real bundle, and install opens it. What the
// assertions are for is the set of properties ADR 0008 says a keeper must have
// — a bundle and no keyring, a leaf and no CA key, a budget, a ledger — because
// each one is a sentence in an ADR until something checks it.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keeper"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/farsight/cli/internal/output"
	"github.com/sofmon/farcast/fatline/identity"
)

const keeperPass = "correct-horse-battery-staple"

// keeperEnv is an instance ready to enrol keepers: connected, with a keyholder
// deployed and a keyring holding the app scope.
func keeperEnv(t *testing.T, mode output.Mode) (*Env, *bytes.Buffer, *bytes.Buffer, config.Dir, string) {
	t.Helper()
	env, out, errb, dir := newInstallEnv(t, mode)
	// newInstallEnv names a directory that does not exist yet; the fixtures
	// below chmod it before they create anything.
	if err := dir.Ensure(); err != nil {
		t.Fatal(err)
	}
	meta := connectedInstance(t, dir, "prod")
	meta.Keyholder = &config.Keyholder{
		Deployed: true, Replicas: 2, Generation: 3,
	}
	if err := dir.SaveInstanceMetadata("prod", meta); err != nil {
		t.Fatal(err)
	}
	keys, err := datasphere.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	scope, err := datasphere.NewAppScope("apps", "web")
	if err != nil {
		t.Fatal(err)
	}
	grown, err := keys.AddScope(scope)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := grown.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.CreateInstanceKeyring("prod", encoded); err != nil {
		t.Fatal(err)
	}
	passFile := filepath.Join(t.TempDir(), "pass")
	if err := os.WriteFile(passFile, []byte(keeperPass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return env, out, errb, dir, passFile
}

func enroll(t *testing.T, env *Env, passFile, device string, extra ...string) string {
	t.Helper()
	packet := filepath.Join(t.TempDir(), device+".packet")
	c := &keeperEnrollCommand{out: packet, passphraseFile: passFile, budget: keeper.DefaultBudget, window: keeper.DefaultWindow}
	_ = extra
	if err := c.Run(context.Background(), env, []string{"prod", device}); err != nil {
		t.Fatalf("keeper enroll %s: %v", device, err)
	}
	return packet
}

func TestKeeperEnrollThenInstall(t *testing.T) {
	env, out, _, dir, passFile := keeperEnv(t, output.ModeHuman)
	packet := enroll(t, env, passFile, "study-desktop")

	if !strings.Contains(out.String(), "study-desktop") {
		t.Errorf("enrolment did not report the device:\n%s", out)
	}
	// One device is not a fleet, and the product stance is two.
	if !strings.Contains(out.String(), "at least two") {
		t.Errorf("enrolling a single keeper did not say two are wanted:\n%s", out)
	}

	info, err := os.Stat(packet)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("packet mode = %v, want 0600", info.Mode().Perm())
	}

	// The fleet is recorded, with the date the credential stops working.
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Keepers) != 1 || meta.Keepers[0].Device != "study-desktop" {
		t.Fatalf("Keepers = %+v, want the enrolled device", meta.Keepers)
	}
	if meta.Keepers[0].Expires.IsZero() {
		t.Error("no expiry was recorded; a leaf that stops working silently is a keeper that stops keeping")
	}

	// Install it on this machine acting as the device.
	out.Reset()
	inst := &keeperInstallCommand{passphraseFile: passFile, acceptRisk: true}
	if err := inst.Run(context.Background(), env, []string{packet}); err != nil {
		t.Fatalf("keeper install: %v", err)
	}
	store, err := keeper.OpenStore(dir.KeeperDir("prod"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	cfg, err := store.Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Device != "study-desktop" || cfg.Instance != "prod" {
		t.Errorf("installed record = %+v", cfg)
	}
	// The bundle carries the generation the instance is ALREADY at. A device
	// that advanced the counter would rewrite what the operator reconciles
	// against.
	if cfg.Generation != 3 {
		t.Errorf("Generation = %d, want the instance's current 3", cfg.Generation)
	}
}

// The properties ADR 0008 states about what a keeper is given.
func TestKeeperPacketCarriesABundleAndNoKeyring(t *testing.T) {
	env, _, _, _, passFile := keeperEnv(t, output.ModeHuman)
	packet := enroll(t, env, passFile, "study-desktop")

	data, err := os.ReadFile(packet)
	if err != nil {
		t.Fatal(err)
	}
	p, err := keeper.Open(data, keeperPass)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// A bundle, and one scope.
	var bundleDoc struct {
		Scopes []struct {
			Name string `yaml:"name"`
		} `yaml:"scopes"`
	}
	if err := yaml.Unmarshal(p.Bundle, &bundleDoc); err != nil {
		t.Fatalf("the packet's bundle did not decode: %v", err)
	}
	if len(bundleDoc.Scopes) != 1 || bundleDoc.Scopes[0].Name != "app-apps-web" {
		t.Errorf("bundle scopes = %+v, want the one application scope the keyring holds", bundleDoc.Scopes)
	}

	// The device's own leaf, named so one device can be revoked alone.
	block, _ := pem.Decode(p.LeafCertPEM)
	if block == nil {
		t.Fatal("the packet carries no parseable leaf")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	want := identity.KeeperURI("prod", "study-desktop")
	found := false
	for _, u := range leaf.URIs {
		if u.String() == want {
			found = true
		}
	}
	if !found {
		t.Errorf("leaf URIs = %v, want %q", leaf.URIs, want)
	}

	// And NOT the CA key. This is what stops a stolen keeper enrolling another
	// keeper, and it is the difference between losing a device and losing the
	// instance.
	raw := string(data)
	mtls, err := env.ConfigDir.LoadInstanceMTLS("prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(mtls.CAKeyPEM) == 0 {
		t.Fatal("the fixture has no CA key, so this assertion would pass vacuously")
	}
	if strings.Contains(raw, string(mtls.CAKeyPEM)) {
		t.Error("the packet contains the instance CA key")
	}
	// Nor the keyring: only the derived bundle travels.
	keyring, err := env.ConfigDir.LoadInstanceKeyring("prod")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, string(keyring)) {
		t.Error("the packet contains the master keyring")
	}
}

func TestKeeperEnrollRefusals(t *testing.T) {
	t.Run("without a CA key this machine cannot enrol", func(t *testing.T) {
		env, _, _, dir, passFile := keeperEnv(t, output.ModeHuman)
		mtls, err := dir.LoadInstanceMTLS("prod")
		if err != nil {
			t.Fatal(err)
		}
		mtls.CAKeyPEM = nil
		if err := dir.SaveInstanceMTLS("prod", mtls); err != nil {
			t.Fatal(err)
		}
		c := &keeperEnrollCommand{out: filepath.Join(t.TempDir(), "p"), passphraseFile: passFile, budget: 8, window: keeper.DefaultWindow}
		err = c.Run(context.Background(), env, []string{"prod", "study-desktop"})
		if err == nil || !strings.Contains(err.Error(), "CA") {
			t.Errorf("err = %v, want a refusal naming the missing CA key", err)
		}
	})

	t.Run("an existing packet is never overwritten", func(t *testing.T) {
		env, _, _, _, passFile := keeperEnv(t, output.ModeHuman)
		path := filepath.Join(t.TempDir(), "taken")
		if err := os.WriteFile(path, []byte("someone else's packet"), 0o600); err != nil {
			t.Fatal(err)
		}
		c := &keeperEnrollCommand{out: path, passphraseFile: passFile, budget: 8, window: keeper.DefaultWindow}
		err := c.Run(context.Background(), env, []string{"prod", "study-desktop"})
		if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
			t.Errorf("err = %v, want a refusal to overwrite", err)
		}
		if got, _ := os.ReadFile(path); string(got) != "someone else's packet" {
			t.Error("the existing file was replaced")
		}
	})

	t.Run("a device name that could not be revoked alone", func(t *testing.T) {
		env, _, _, dir, passFile := keeperEnv(t, output.ModeHuman)
		for _, bad := range []string{"", "Study", "a/b"} {
			out := filepath.Join(t.TempDir(), "p")
			c := &keeperEnrollCommand{out: out, passphraseFile: passFile, budget: 8, window: keeper.DefaultWindow}
			if err := c.Run(context.Background(), env, []string{"prod", bad}); err == nil {
				t.Errorf("enroll accepted the device name %q", bad)
			}
			if _, err := os.Stat(out); err == nil {
				t.Errorf("a refused enrolment for %q still wrote a packet", bad)
			}
		}
		meta, err := dir.LoadInstanceMetadata("prod")
		if err != nil {
			t.Fatal(err)
		}
		if len(meta.Keepers) != 0 {
			t.Errorf("a refused enrolment recorded a keeper: %+v", meta.Keepers)
		}
	})

	// The name is checked on its own terms, before this command needs anything
	// else about the instance to be right.
	//
	// The ordering is what is being asserted: an enrolment that minted a leaf
	// and then discovered the name was unusable would have asked the CA to
	// sign an identity the keyholder refuses by construction. With a bad name
	// AND no CA key, the error must be about the name.
	t.Run("a bad name is refused before the CA key is touched", func(t *testing.T) {
		env, _, _, dir, passFile := keeperEnv(t, output.ModeHuman)
		mtls, err := dir.LoadInstanceMTLS("prod")
		if err != nil {
			t.Fatal(err)
		}
		mtls.CAKeyPEM = nil
		if err := dir.SaveInstanceMTLS("prod", mtls); err != nil {
			t.Fatal(err)
		}
		c := &keeperEnrollCommand{out: filepath.Join(t.TempDir(), "p"), passphraseFile: passFile, budget: 8, window: keeper.DefaultWindow}
		err = c.Run(context.Background(), env, []string{"prod", "Study"})
		if err == nil {
			t.Fatal("enroll accepted an invalid device name")
		}
		if !strings.Contains(err.Error(), "device name") {
			t.Errorf("err = %v, want the device-name refusal rather than a later failure", err)
		}
	})

	t.Run("an instance with no tunnel has nothing for a keeper to dial", func(t *testing.T) {
		env, _, _, dir, passFile := keeperEnv(t, output.ModeHuman)
		meta, err := dir.LoadInstanceMetadata("prod")
		if err != nil {
			t.Fatal(err)
		}
		meta.Carrier = nil
		if err := dir.SaveInstanceMetadata("prod", meta); err != nil {
			t.Fatal(err)
		}
		c := &keeperEnrollCommand{out: filepath.Join(t.TempDir(), "p"), passphraseFile: passFile, budget: 8, window: keeper.DefaultWindow}
		if err := c.Run(context.Background(), env, []string{"prod", "study-desktop"}); err == nil {
			t.Error("enroll produced a packet for an instance with no carrier")
		}
	})
}

// Revocation is narrower than the word suggests, and the command has to say so
// rather than let an operator believe a stolen device is now harmless.
func TestKeeperRevokeSaysWhatItDoesNotDo(t *testing.T) {
	env, out, _, dir, passFile := keeperEnv(t, output.ModeHuman)
	_ = enroll(t, env, passFile, "study-desktop")
	_ = enroll(t, env, passFile, "home-server")
	out.Reset()

	if err := (&keeperRevokeCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod", "study-desktop"}); err != nil {
		t.Fatalf("keeper revoke: %v", err)
	}
	report := out.String()
	// The remedy names commands that exist, in the order they work. This test
	// used to pin "storage rekey prod" — a command that was never registered,
	// so the test enforced the very advice an operator could not follow.
	for _, want := range []string{
		"did not reach the cluster", "does not reach backwards",
		"farcast storage key rotate prod", "farcast storage key rekey prod", "farcast keeper enroll prod",
		"name key cannot rotate",
		// Walk finding 3: the key pin is what retires the device's bundle in
		// the cluster, and only while a replica has loaded it.
		"below-pin", "farcast storage key pin prod", "none loaded",
		"farcast storage state prod",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("the revocation report omits %q:\n%s", want, report)
		}
	}
	// The text it replaced said a revoked device could re-seed with its old
	// keys until its certificate expired, which the pin made untrue.
	usage := (&keeperRevokeCommand{}).Usage()
	for name, text := range map[string]string{"report": report, "usage": usage} {
		flat := strings.Join(strings.Fields(text), " ")
		for _, gone := range []string{"with its old keys", "until its certificate expires, the device can still re-seed", "the generation is no sign"} {
			if strings.Contains(flat, gone) {
				t.Errorf("the revocation %s still says %q:\n%s", name, gone, text)
			}
		}
		for _, want := range []string{"below-pin", "none loaded", "storage key pin", "storage key rotate"} {
			if !strings.Contains(flat, want) {
				t.Errorf("the revocation %s omits %q:\n%s", name, want, text)
			}
		}
	}

	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	var revoked, live int
	for _, k := range meta.Keepers {
		if k.Revoked {
			revoked++
		} else {
			live++
		}
	}
	if revoked != 1 || live != 1 {
		t.Errorf("fleet = %+v, want one revoked and one live", meta.Keepers)
	}
	// The row survives, so old ledger entries stay attributable.
	if len(meta.Keepers) != 2 {
		t.Error("revocation deleted the device's row, which an audit still needs")
	}

	if err := (&keeperRevokeCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod", "study-desktop"}); err == nil {
		t.Error("revoking twice succeeded")
	}
	if err := (&keeperRevokeCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod", "never-enrolled"}); err == nil {
		t.Error("revoking an unknown device succeeded")
	}
}

// Re-enrolment is a deliberate readmission: it replaces the row and clears the
// revocation, because the operator has just issued that device a fresh leaf.
func TestKeeperReEnrolmentReadmitsARevokedDevice(t *testing.T) {
	env, _, _, dir, passFile := keeperEnv(t, output.ModeHuman)
	_ = enroll(t, env, passFile, "study-desktop")
	if err := (&keeperRevokeCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod", "study-desktop"}); err != nil {
		t.Fatal(err)
	}
	_ = enroll(t, env, passFile, "study-desktop")

	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Keepers) != 1 {
		t.Fatalf("Keepers = %+v, want the row replaced rather than duplicated", meta.Keepers)
	}
	if meta.Keepers[0].Revoked {
		t.Error("re-enrolling did not readmit the device")
	}
}

// Budgets add across a fleet while each device refuses only against its own
// (ADR 0008 finding 6), so the machine that enrolled the fleet reads them as a
// total: two devices at 8 and 1 a month admit 9 re-seeds a month, which no
// single device's status shows. A revoked device leaves the total.
func TestKeeperStatusTotalsTheFleetBudget(t *testing.T) {
	env, out, _, _, passFile := keeperEnv(t, output.ModeHuman)
	_ = enroll(t, env, passFile, "study-desktop")
	small := &keeperEnrollCommand{
		out: filepath.Join(t.TempDir(), "laptop.packet"), passphraseFile: passFile,
		budget: 1, window: keeper.DefaultWindow,
	}
	if err := small.Run(context.Background(), env, []string{"prod", "laptop"}); err != nil {
		t.Fatal(err)
	}

	status := func() string {
		t.Helper()
		out.Reset()
		if err := (&keeperStatusCommand{}).Run(context.Background(), env, nil); err != nil {
			t.Fatalf("keeper status: %v", err)
		}
		return out.String()
	}
	got := status()
	for _, want := range []string{
		"study-desktop  until ", "budget 8 per 30 days", "laptop  until ", "budget 1 per 30 days",
		"fleet budget: up to 9 reseeds per 30 days across 2 device(s)",
		"a total of limits, not of use",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("status lacks %q:\n%s", want, got)
		}
	}

	if err := (&keeperRevokeCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod", "laptop"}); err != nil {
		t.Fatal(err)
	}
	got = status()
	if !strings.Contains(got, "fleet budget: up to 8 reseeds per 30 days across 1 device(s)") {
		t.Errorf("a revoked device still counts toward the fleet budget:\n%s", got)
	}
	if strings.Contains(got, "budget 1 per") {
		t.Errorf("a revoked device's row still shows a budget it can no longer use:\n%s", got)
	}
}

// The total is per window — a sum across windows means nothing — and counts
// only keepers that can still push.
func TestFleetBudgetsGroupByWindowAndSkipWhatCannotPush(t *testing.T) {
	now := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	month, week := keeper.DefaultWindow, 7*24*time.Hour
	fleet := map[string][]config.Keeper{
		"prod": {
			{Device: "a", Budget: 8, Window: month, Expires: now.Add(time.Hour)},
			{Device: "b", Budget: 2, Window: month},
			{Device: "c", Budget: 3, Window: week},
			{Device: "revoked", Budget: 50, Window: month, Revoked: true},
			{Device: "expired", Budget: 50, Window: month, Expires: now},
			{Device: "legacy", Budget: 4},
		},
		"lab": {{Device: "z", Budget: 1, Window: month}},
	}
	got := fleetBudgets(fleet, now)
	want := []fleetBudget{
		{Instance: "lab", Window: "30 days", Devices: 1, Reseeds: 1},
		{Instance: "prod", Window: "", Devices: 1, Reseeds: 4},
		{Instance: "prod", Window: "30 days", Devices: 2, Reseeds: 10},
		{Instance: "prod", Window: "7 days", Devices: 1, Reseeds: 3},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fleetBudgets =\n %+v\nwant\n %+v", got, want)
	}

	// A budget with no window cannot be added to anyone's, and the line says
	// what to do about it rather than printing a sum without a period.
	var buf bytes.Buffer
	if err := (keeperStatusResult{Fleet: fleetRows(fleet), FleetBudget: got}).Human(&buf); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"fleet budget: 4 reseed(s) across 1 device(s) enrolled before windows were recorded — re-enrol them to total it",
		"fleet budget: up to 10 reseeds per 30 days across 2 device(s)",
		"fleet budget: up to 3 reseeds per 7 days across 1 device(s)",
	} {
		if !strings.Contains(buf.String(), line) {
			t.Errorf("status lacks %q:\n%s", line, buf.String())
		}
	}
}

func TestKeeperStatusOnAMachineThatKeepsNothing(t *testing.T) {
	env, out, _, _ := newInstallEnv(t, output.ModeHuman)
	if err := (&keeperStatusCommand{}).Run(context.Background(), env, nil); err != nil {
		t.Fatalf("keeper status: %v", err)
	}
	if !strings.Contains(out.String(), "keeps nothing") {
		t.Errorf("status did not say the machine keeps nothing:\n%s", out)
	}
}

// advisedCommand finds every farcast command a piece of output tells the
// operator to run: quoted in prose ('farcast ...'), or on an indented line of
// its own.
var advisedCommand = regexp.MustCompile(`'(farcast [^']+)'|(?m)^\s+(farcast \S[^\n]*)$`)

// resolves reports whether a command line names a real command, walking the
// command tree until the words stop being subcommands.
func resolves(t *testing.T, line string) {
	t.Helper()
	words := strings.Fields(line)
	cmd, ok := defaultRegistry().Lookup(words[1])
	if !ok {
		t.Errorf("%q: there is no command %q", line, words[1])
		return
	}
	for _, w := range words[2:] {
		g, isGroup := cmd.(*group)
		if !isGroup {
			return // an argument, not a subcommand
		}
		if cmd, ok = g.subs.Lookup(w); !ok {
			t.Errorf("%q: %q has no subcommand %q", line, g.name, w)
			return
		}
	}
	if _, stillGroup := cmd.(*group); stillGroup {
		t.Errorf("%q names a command group, not a command", line)
	}
}

// The advice a command prints is only advice if the operator can follow it.
// `keeper revoke` named 'farcast storage rekey' for as long as it existed — a
// command that was never registered, pinned by a test that compared strings.
// So this drives the commands themselves down the paths that print advice,
// collects every command they tell an operator to run, and resolves each one
// against the real command tree. Nothing here is a list somebody has to keep
// in step with the code.
func TestEveryCommandTheCLIAdvisesExists(t *testing.T) {
	var printed strings.Builder

	// revoke's remedy.
	env, out, _, _, passFile := keeperEnv(t, output.ModeHuman)
	_ = enroll(t, env, passFile, "study-desktop")
	if err := (&keeperRevokeCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod", "study-desktop"}); err != nil {
		t.Fatal(err)
	}
	printed.WriteString(out.String())

	// rotate: its next step, a partial rotation, and a keeper to re-enrol.
	dir, meta, env2, sees := handOverInstance(t, "p90")
	scopedKeyring(t, dir, "p90", "demo", "alpha")
	meta.Keepers = []config.Keeper{{Device: "study-desktop"}}
	if err := dir.SaveInstanceMetadata("p90", meta); err != nil {
		t.Fatal(err)
	}
	flaky := &flakyKeyholder{fakeStateKeyholder: &fakeStateKeyholder{phase: "unsealed"}, silent: map[int]bool{1: true}}
	if err := (&keyRotateCommand{assumeYes: true, newKeyholder: openerFor(flaky)}).Run(context.Background(), env2, []string{"p90"}); err != nil {
		printed.WriteString(err.Error()) // a rotation that did not finish fails, and says what finishes it
	}
	printed.WriteString(sees.String())

	// unseal's refusals of a keyring behind the replicas: a scope it lacks,
	// and a key it lacks.
	for _, arrange := range []func(*fakeStateKeyholder){
		func(kh *fakeStateKeyholder) { kh.replica(0).keys["app-elsewhere-other"] = []string{"00000000000000aa"} },
		func(kh *fakeStateKeyholder) {
			kh.replica(0).keys["app-demo-alpha"] = append(kh.replica(0).keys["app-demo-alpha"], "00000000000000bb")
		},
	} {
		dir, meta, env, _ := handOverInstance(t, "p92")
		scopedKeyring(t, dir, "p92", "demo", "alpha")
		kh := servingFleet(t, env, meta, dir)
		arrange(kh)
		if err := (&storageUnsealCommand{newKeyholder: openerFor(kh)}).Run(context.Background(), env, []string{"p92"}); err != nil {
			printed.WriteString(err.Error())
		} else {
			t.Error("guard: unseal from a keyring behind the replicas did not refuse")
		}
	}

	// state, rekey and unseal facing a keyholder older than the CLI.
	{
		env, out, dir, _, _ := rekeyInstance(t)
		meta, _ := dir.LoadInstanceMetadata("prod")
		kh := servingFleet(t, env, meta, dir)
		old := &oldImage{kh}
		if err := (&storageStateCommand{newKeyholder: openerFor(old)}).Run(context.Background(), env, []string{"prod"}); err != nil {
			t.Fatal(err)
		}
		printed.WriteString(out.String())
		if err := (&keyRekeyCommand{assumeYes: true, newKeyholder: openerFor(old)}).Run(context.Background(), env, []string{"prod"}); err != nil {
			printed.WriteString(err.Error())
		}
	}

	// rekey's gate refusal.
	env3, _, _, _, _ := rekeyInstance(t)
	sealed := &fakeStateKeyholder{phase: "restart-sealed"}
	if err := (&keyRekeyCommand{assumeYes: true, newKeyholder: openerFor(sealed)}).Run(context.Background(), env3, []string{"prod"}); err != nil {
		printed.WriteString(err.Error())
	} else {
		t.Error("guard: rekey against a sealed keyholder did not refuse")
	}

	// release naming keepers on other devices, and what to run there.
	{
		env, out, dir, _ := keeperRelease(t)
		if _, err := dir.UpdateInstanceMetadata("prod", func(m *config.InstanceMetadata) error {
			m.Keepers = append(m.Keepers, config.Keeper{Device: "laptop"})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := (&releaseCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod"}); err != nil {
			t.Fatal(err)
		}
		printed.WriteString(out.String())
	}

	// run's partial hand-over and its keeper notice.
	printed.WriteString(runWith(t, "p91",
		&flakyKeyholder{fakeStateKeyholder: &fakeStateKeyholder{phase: "unsealed"}, refuseNth: map[int]int{1: 1}},
		config.Keeper{Device: "study-desktop"}))

	var found []string
	for _, m := range advisedCommand.FindAllStringSubmatch(printed.String(), -1) {
		line := m[1]
		if line == "" {
			line = m[2]
		}
		found = append(found, strings.TrimSpace(line))
		resolves(t, line)
	}
	// A collector that found nothing would pass for the wrong reason.
	for _, want := range []string{"storage key rotate", "storage key rekey", "keeper enroll", "storage unseal", "storage state", "keeper uninstall"} {
		if !slices.ContainsFunc(found, func(c string) bool { return strings.Contains(c, want) }) {
			t.Errorf("no advised command mentions %q; the collector missed it or the advice changed:\n%v", want, found)
		}
	}
}

// installedKeeper enrols and installs a keeper on this machine, and returns
// its store and record.
func installedKeeper(t *testing.T) (*Env, config.Dir, *keeper.Store, keeper.Config) {
	t.Helper()
	env, _, _, dir, passFile := keeperEnv(t, output.ModeHuman)
	packet := enroll(t, env, passFile, "study-desktop")
	if err := (&keeperInstallCommand{passphraseFile: passFile, acceptRisk: true}).Run(context.Background(), env, []string{packet}); err != nil {
		t.Fatalf("keeper install: %v", err)
	}
	store, err := keeper.OpenStore(dir.KeeperDir("prod"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Config()
	if err != nil {
		t.Fatal(err)
	}
	return env, dir, store, cfg
}

func storeBundle(t *testing.T, store *keeper.Store) []byte {
	t.Helper()
	_, _, _, bundle, err := store.Material()
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

// The wiring the mutation suite found untested. Mismatch is right and Decide
// is right; what puts the one into the other is keeperCheck, and dropping that
// argument restored the retired keys silently. Here a keeper enrolled before a
// rotation faces replica 0 restarted — generation zero, nothing to compare —
// and replica 1 serving the rotated keys.
func TestAKeeperEnrolledBeforeARotationDoesNotRestoreTheOldKeys(t *testing.T) {
	env, dir, store, cfg := installedKeeper(t)
	rotated, _, err := liveKeyring(t, dir, "prod").RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	fleet := &fakeStateKeyholder{phase: "restart-sealed"}
	fleet.replica(1).phase, fleet.replica(1).generation, fleet.replica(1).keys = "unsealed", 5, heldKeys(rotated)

	pass, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, storeBundle(t, store))
	if err != nil {
		t.Fatalf("keeperCheckWith: %v", err)
	}
	decisions := pass.Decisions
	if fleet.pushes != 0 {
		t.Fatalf("the keeper pushed %d time(s): it put pre-rotation keys back into a restarted replica", fleet.pushes)
	}
	if decisions[0].Action != keeper.ActionStale || !strings.Contains(decisions[0].Reason, "rotated") {
		t.Errorf("replica 0: %s (%s); want stale, saying the keys were rotated", decisions[0].Action, decisions[0].Reason)
	}
}

// The control: the same restart, with the serving replica holding the keys the
// keeper was enrolled with. It must re-seed — a check that refused every time
// would pass the test above for the wrong reason.
func TestAKeeperWhoseKeysAreCurrentReseedsARestartedReplica(t *testing.T) {
	env, dir, store, cfg := installedKeeper(t)
	fleet := &fakeStateKeyholder{phase: "restart-sealed"}
	fleet.replica(1).phase, fleet.replica(1).generation, fleet.replica(1).keys = "unsealed", 3, heldKeys(liveKeyring(t, dir, "prod"))

	pass, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, storeBundle(t, store))
	if err != nil {
		t.Fatalf("keeperCheckWith: %v", err)
	}
	decisions := pass.Decisions
	if fleet.pushes != 1 || decisions[0].Action != keeper.ActionReseed {
		t.Fatalf("replica 0: %s after %d push(es); want one re-seed", decisions[0].Action, fleet.pushes)
	}
	if !sameKeys(fleet.replica(0).keys, heldKeys(liveKeyring(t, dir, "prod"))) {
		t.Error("the re-seeded replica does not hold the keeper's keys")
	}
}

// heldRotation is a rotation as the fleet first receives it: each new key held,
// the previous one still active.
func heldRotation(t *testing.T, k datasphere.Keyring) (held, active datasphere.Keyring) {
	t.Helper()
	rotated, rotations, err := k.RotateScopeKEKs()
	if err != nil {
		t.Fatal(err)
	}
	previous := map[string]datasphere.KeyID{}
	for _, r := range rotations {
		previous[r.Scope] = r.Previous
	}
	if held, err = rotated.WithScopeActive(previous); err != nil {
		t.Fatal(err)
	}
	return held, rotated
}

// Closure item 16. While a rotation is half-way — the new key held by a
// serving replica, not yet used — that replica's ACTIVE key is still one the
// old bundle carries. Comparing only that, a keeper enrolled before the
// rotation re-seeded a restarted replica without the new key, which the
// serving one was about to start writing under.
func TestAKeeperDoesNotReseedWhileAServingReplicaHoldsAKeyItLacks(t *testing.T) {
	env, dir, store, cfg := installedKeeper(t)
	held, _ := heldRotation(t, liveKeyring(t, dir, "prod"))
	fleet := &fakeStateKeyholder{phase: "restart-sealed"}
	fleet.replica(1).phase, fleet.replica(1).generation, fleet.replica(1).keys = "unsealed", 5, heldKeys(held)

	pass, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, storeBundle(t, store))
	if err != nil {
		t.Fatalf("keeperCheckWith: %v", err)
	}
	decisions := pass.Decisions
	if fleet.pushes != 0 || decisions[0].Action != keeper.ActionStale {
		t.Fatalf("replica 0: %s (%s) after %d push(es); want stale and no push", decisions[0].Action, decisions[0].Reason, fleet.pushes)
	}
}

// Finding C. A keeper enrolled AFTER a rotation that has not reached every
// replica writes under a key a serving replica lacks. It used to re-seed,
// because it carries that replica's key too.
func TestAKeeperAheadOfAServingReplicaDoesNotReseed(t *testing.T) {
	env, dir, store, cfg := installedKeeper(t)
	_, rotated := heldRotation(t, liveKeyring(t, dir, "prod"))
	ahead := storeBundleOf(t, cfg, rotated)
	fleet := &fakeStateKeyholder{phase: "restart-sealed"}
	fleet.replica(1).phase, fleet.replica(1).generation, fleet.replica(1).keys = "unsealed", 1, heldKeys(liveKeyring(t, dir, "prod"))

	pass, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, ahead)
	if err != nil {
		t.Fatalf("keeperCheckWith: %v", err)
	}
	decisions := pass.Decisions
	if fleet.pushes != 0 || decisions[0].Action != keeper.ActionStale || !strings.Contains(decisions[0].Reason, "farcast storage unseal") {
		t.Fatalf("replica 0: %s (%s) after %d push(es); want stale, naming the unseal that finishes the hand-over", decisions[0].Action, decisions[0].Reason, fleet.pushes)
	}
}

// storeBundleOf is the bundle a keeper enrolled from this keyring would hold.
func storeBundleOf(t *testing.T, cfg keeper.Config, k datasphere.Keyring) []byte {
	t.Helper()
	b, err := datasphere.NewBundle(cfg.Instance, cfg.Generation, k.Scopes())
	if err != nil {
		t.Fatal(err)
	}
	data, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// N18. A replica unsealed between the keeper's read and its push refuses the
// re-seed as already serving. Nothing went wrong and nothing is left to do —
// so it must not be reported as a failure, and the ledger must not record a
// re-seed that never happened.
func TestAReseedRefusedAsAlreadyServingIsNotAFailure(t *testing.T) {
	env, dir, store, cfg := installedKeeper(t)
	fleet := &unsealedMidCheck{fakeStateKeyholder: &fakeStateKeyholder{phase: "restart-sealed"}}
	fleet.replica(1).phase, fleet.replica(1).generation, fleet.replica(1).keys = "unsealed", 1, heldKeys(liveKeyring(t, dir, "prod"))

	pass, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, storeBundle(t, store))
	if err != nil {
		t.Fatalf("keeperCheckWith: %v", err)
	}
	decisions := pass.Decisions
	if decisions[0].Action != keeper.ActionNone {
		t.Errorf("replica 0: %s (%s); want none — another pusher reached it first", decisions[0].Action, decisions[0].Reason)
	}
	entries, err := keyholder.ReadLedger(store.LedgerPath())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Ordinal == 0 && e.Result == "ok" {
			t.Errorf("the ledger records a re-seed that did not happen: %+v", e)
		}
	}
}

// unsealedMidCheck is a replica unsealed by someone else between a keeper's
// read and its push.
type unsealedMidCheck struct{ *fakeStateKeyholder }

func (u *unsealedMidCheck) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	u.replica(i).phase = "unsealed"
	return u.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
}

// Review 4, finding 0. A replica whose answer was lost is unknown, not
// sealed: read as sealed, a serving replica holding rotated keys was no
// reference at all, and a keeper enrolled before the rotation re-seeded the
// old keys beside it.
func TestAKeeperDoesNotReseedBesideAReplicaThatDidNotAnswer(t *testing.T) {
	env, dir, store, cfg := installedKeeper(t)
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	fleet := servingFleet(t, env, meta, dir)
	mustRotate(t, env, "prod", fleet)
	fleet.replica(0).phase, fleet.replica(0).keys, fleet.replica(0).generation = "restart-sealed", nil, 0
	// Without a key pin — the pin would refuse this bundle first, which
	// TestAKeeperRefusesWhatThePinRefusesWithNothingServing covers.
	unpin(t, dir, "prod", fleet)
	pushes := fleet.pushes

	silent := &flakyKeyholder{fakeStateKeyholder: fleet, silent: map[int]bool{1: true}}
	pass, err := keeperCheckWith(context.Background(), env, store, cfg, silent, storeBundle(t, store))
	if err != nil {
		t.Fatalf("keeperCheckWith: %v", err)
	}
	decisions := pass.Decisions
	if fleet.pushes != pushes || decisions[0].Action != keeper.ActionUnchecked {
		t.Fatalf("replica 0: %s (%s) after %d push(es); want unchecked and no push", decisions[0].Action, decisions[0].Reason, fleet.pushes-pushes)
	}
	noSplit(t, fleet)
}

// The case the key pin exists for. Every replica restarted after a rotation,
// so none serves to compare with — before the pin, a keeper enrolled before
// the rotation re-seeded the old keys into both. The pin each replica loaded
// at start is the reference, and the keeper reads it from the sealed replicas.
func TestAKeeperRefusesWhatThePinRefusesWithNothingServing(t *testing.T) {
	env, dir, store, cfg := installedKeeper(t)
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	fleet := servingFleet(t, env, meta, dir)
	mustRotate(t, env, "prod", fleet)
	if fleet.replica(0).pin == nil {
		t.Fatal("guard: the rotation did not hand the replicas the pin")
	}
	for i := range 2 {
		fleet.replica(i).phase, fleet.replica(i).keys, fleet.replica(i).generation = "restart-sealed", nil, 0
	}
	pushes := fleet.pushes

	pass, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, storeBundle(t, store))
	if err != nil {
		t.Fatalf("keeperCheckWith: %v", err)
	}
	decisions := pass.Decisions
	for _, d := range decisions {
		if d.Action != keeper.ActionStale || !strings.Contains(d.Reason, "key pin") {
			t.Errorf("replica %d: %s (%s); want stale, naming the pin", d.Ordinal, d.Action, d.Reason)
		}
	}
	if fleet.pushes != pushes {
		t.Errorf("%d push(es) of a pre-rotation bundle into a fleet with nothing serving", fleet.pushes-pushes)
	}

	// And a modified keeper that skips its own check is refused by the
	// keyholder: the fake fleet enforces the pin as the vault does.
	if _, err := fleet.Unseal(context.Background(), 0, storeBundle(t, store), keeper.IntentReseed); !keyholder.BelowPin(err) {
		t.Errorf("a pre-rotation bundle pushed regardless = %v; want below-pin", err)
	}
	if fleet.replica(0).phase != "restart-sealed" {
		t.Error("a bundle below the pin unsealed the replica")
	}
}

// A keeper checks its own leaf before dialling: a leaf that does not bind the
// bundle beside it is refused by every keyholder, every pass.
func TestAKeeperChecksItsLeafBindsItsBundle(t *testing.T) {
	m, err := identity.Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte("version: 1\n")
	bound, _, err := identity.IssueKeeperClient(m.CACertPEM, m.CAKeyPEM, "prod", "laptop", bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := leafBindsBundle(bound, bundle); err != nil {
		t.Errorf("a leaf bound to its bundle: %v", err)
	}
	if err := leafBindsBundle(bound, []byte("version: 1\nother: true\n")); err == nil {
		t.Error("a leaf bound to another bundle passed")
	}
	// The operator's leaf binds nothing, like a keeper's from before binding.
	if err := leafBindsBundle(m.ClientCertPEM, bundle); err == nil || !strings.Contains(err.Error(), "re-enrol") {
		t.Errorf("an unbound leaf = %v; want a refusal naming re-enrolment", err)
	}

	// What keeperCheck runs before dialling. Each refusal is a person's to
	// act on, every pass alike, so it exits 3 — never 4, which a timer
	// retries forever.
	now := time.Now()
	if err := keeperLeafUsable(bound, bundle, now); err != nil {
		t.Errorf("a current leaf bound to its bundle: %v", err)
	}
	if err := keeperLeafUsable(m.ClientCertPEM, bundle, now); exitCodeOf(err) != exitCannotKeep {
		t.Errorf("an unbound leaf = %v (exit %d); want exit %d", err, exitCodeOf(err), exitCannotKeep)
	}
	// An expired leaf fails at the TLS handshake, which reads exactly like a
	// tunnel that did not answer; checked here, it says what it is.
	later := leafExpiry(bound).Add(time.Hour)
	err = keeperLeafUsable(bound, bundle, later)
	if exitCodeOf(err) != exitCannotKeep || err == nil || !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), "re-enrol") {
		t.Errorf("an expired leaf = %v (exit %d); want exit %d, saying it expired and to re-enrol", err, exitCodeOf(err), exitCannotKeep)
	}
}

// keeperCheck itself runs the leaf check before it dials, and a tunnel that
// does not answer is a retry, not a fault on this device.
func TestKeeperCheckClassesWhatStopsItBeforeThePass(t *testing.T) {
	env, dir, store, cfg := installedKeeper(t)

	// A cancelled context: the dial fails without reaching for any network.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := keeperCheck(ctx, env, store, cfg)
	if exitCodeOf(err) != exitIncomplete || !strings.Contains(err.Error(), "cannot reach") {
		t.Errorf("an undialable tunnel = %v (exit %d); want exit %d", err, exitCodeOf(err), exitIncomplete)
	}

	// A leaf that binds no bundle, put where the device keeps its own.
	m, err := identity.Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir.KeeperDir("prod"), "leaf.crt"), m.ClientCertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = keeperCheck(context.Background(), env, store, cfg)
	if exitCodeOf(err) != exitCannotKeep || !strings.Contains(err.Error(), "does not bind") {
		t.Errorf("an unbound leaf = %v (exit %d); want exit %d before any dial", err, exitCodeOf(err), exitCannotKeep)
	}
}

// Walk finding 4. With every replica sealed behind a pin that refuses this
// device's bundle, the pin's verdict is printed once for the pass, and each
// replica's line points to it rather than repeating — or naming — another
// replica.
func TestAKeeperReportsTheFleetPinVerdictOnce(t *testing.T) {
	env, dir, store, cfg := installedKeeper(t)
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	fleet := servingFleet(t, env, meta, dir)
	mustRotate(t, env, "prod", fleet)
	for i := range 2 {
		fleet.replica(i).phase, fleet.replica(i).keys, fleet.replica(i).generation = "restart-sealed", nil, 0
	}
	var errb bytes.Buffer
	env.Err = &errb

	pass, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, storeBundle(t, store))
	if err != nil {
		t.Fatal(err)
	}
	report := errb.String()
	if n := strings.Count(report, "key pin refuses"); n != 1 {
		t.Errorf("the pin's verdict is printed %d times; want once:\n%s", n, report)
	}
	lines := strings.Split(report, "\n")
	if !slices.ContainsFunc(lines, func(l string) bool {
		return strings.HasPrefix(l, "this device: stale-bundle") && strings.Contains(l, "key pin refuses")
	}) {
		t.Errorf("no 'this device: stale-bundle' line carries the pin's verdict:\n%s", report)
	}
	for i := range 2 {
		prefix := fmt.Sprintf("replica %d: stale-bundle", i)
		if !strings.Contains(report, prefix) {
			t.Errorf("the report omits %q:\n%s", prefix, report)
		}
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "replica 1:") && strings.Contains(l, "replica 0") {
			t.Errorf("replica 1's line names replica 0: %q", l)
		}
	}
	if code := exitCodeOf(keeperPassError("prod", pass)); code != exitCannotKeep {
		t.Errorf("the pass exits %d; want %d", code, exitCannotKeep)
	}
}

// Walk finding 4, the early warning. A keeper enrolled before a rotation
// learns it is stale at the rotation — with every replica still serving —
// rather than at the next restart, which is the outage it exists for.
func TestAStaleKeeperSaysSoWithNothingSealed(t *testing.T) {
	env, dir, store, cfg := installedKeeper(t)
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	fleet := servingFleet(t, env, meta, dir)
	mustRotate(t, env, "prod", fleet)
	pushes := fleet.pushes
	var errb bytes.Buffer
	env.Err = &errb

	pass, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, storeBundle(t, store))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range pass.Decisions {
		if d.Action != keeper.ActionNone {
			t.Fatalf("guard: replica %d is %s; every replica should be serving", d.Ordinal, d.Action)
		}
	}
	if fleet.pushes != pushes {
		t.Errorf("%d push(es) into a serving fleet", fleet.pushes-pushes)
	}
	if got := keeper.PassOutcome(pass.Decisions, pass.Fleet); got != keeper.OutcomeCannotKeep {
		t.Errorf("PassOutcome = %d; want cannot-keep: the fleet has moved past this bundle", got)
	}
	if !strings.Contains(errb.String(), "this device: stale-bundle") {
		t.Errorf("the pass did not say this device is stale:\n%s", errb.String())
	}
	if code := exitCodeOf(keeperPassError("prod", pass)); code != exitCannotKeep {
		t.Errorf("--once exits %d; want %d", code, exitCannotKeep)
	}
}

// --once is for a timer, and a timer reads the exit status: kept (0), a
// person must act (3), the next pass retries (4).
func TestKeeperRunOnceExitsByOutcome(t *testing.T) {
	env, _, _, _ := installedKeeper(t)
	env.Err = &bytes.Buffer{}
	pass := func(as ...keeper.Action) keeperPassResult {
		p := keeperPassResult{}
		for i, a := range as {
			p.Decisions = append(p.Decisions, keeper.Decision{Ordinal: i, Action: a, Reason: string(a)})
		}
		return p
	}
	for _, tc := range []struct {
		name   string
		result keeperPassResult
		err    error
		want   int
	}{
		{"kept", pass(keeper.ActionNone, keeper.ActionReseed), nil, 0},
		{"held by the operator", pass(keeper.ActionHold, keeper.ActionNone), nil, 0},
		{"stale", pass(keeper.ActionStale, keeper.ActionNone), nil, exitCannotKeep},
		{"stale with every replica serving", keeperPassResult{Decisions: pass(keeper.ActionNone, keeper.ActionNone).Decisions, Fleet: keeper.Fleet{Mismatch: "moved"}}, nil, exitCannotKeep},
		{"pin unreadable", pass(keeper.ActionPinUnreadable, keeper.ActionNone), nil, exitCannotKeep},
		{"budget spent", pass(keeper.ActionBudget, keeper.ActionNone), nil, exitCannotKeep},
		{"unreachable", pass(keeper.ActionNone, keeper.ActionUnknown), nil, exitIncomplete},
		{"unchecked", pass(keeper.ActionUnchecked, keeper.ActionUnknown), nil, exitIncomplete},
		{"a tunnel that did not answer", keeperPassResult{}, &exitCodeError{code: exitIncomplete, err: errors.New("cannot reach")}, exitIncomplete},
		{"a fault on this device", keeperPassResult{}, errors.New("ledger unreadable"), 1},
	} {
		c := &keeperRunCommand{once: true, check: func(context.Context, *Env, *keeper.Store, keeper.Config) (keeperPassResult, error) {
			return tc.result, tc.err
		}}
		err := c.Run(context.Background(), env, []string{"prod"})
		if got := exitCodeOf(err); got != tc.want {
			t.Errorf("%s: exit %d (%v); want %d", tc.name, got, err, tc.want)
		}
	}
}

// Without --once a keeper never exits on what a pass found: it reports and
// checks again. One that exited on a refusal or a dead tunnel would be absent
// for the restart it exists for.
func TestKeeperRunKeepsRunningPastARefusal(t *testing.T) {
	env, _, _, _ := installedKeeper(t)
	env.Err = &bytes.Buffer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	c := &keeperRunCommand{interval: time.Nanosecond, check: func(context.Context, *Env, *keeper.Store, keeper.Config) (keeperPassResult, error) {
		calls++
		switch calls {
		case 1:
			return keeperPassResult{Decisions: []keeper.Decision{{Action: keeper.ActionStale}}}, nil
		case 2:
			return keeperPassResult{}, &exitCodeError{code: exitCannotKeep, err: errors.New("leaf expired")}
		default:
			cancel()
			return keeperPassResult{Decisions: []keeper.Decision{{Action: keeper.ActionUnknown}}}, nil
		}
	}}
	if err := c.Run(ctx, env, []string{"prod"}); err != nil {
		t.Errorf("the loop returned %v after %d pass(es); it must keep running", err, calls)
	}
	if calls < 3 {
		t.Errorf("the loop ran %d pass(es); want at least 3", calls)
	}
}

// ledgerBreaksOnPush is a fleet whose every push that lands, lands after this
// device's ledger stopped taking writes — a directory where the file was,
// which is what a read-only remount or a full disk looks like to AppendLedger
// while the pending entry written just before the push, and ReadLedger
// earlier in the pass, still worked. refuse answers one replica's push with
// an error of its own instead, and leaves the ledger as it was.
type ledgerBreaksOnPush struct {
	*fakeStateKeyholder
	ledger string
	refuse map[int]error
}

func (b *ledgerBreaksOnPush) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	if err := b.refuse[i]; err != nil {
		return keyholder.State{}, err
	}
	_ = os.Remove(b.ledger)
	_ = os.MkdirAll(b.ledger, 0o700)
	return b.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
}

// onceOver is `keeper run --once` with its pass run against kh instead of a
// tunnel: Run's own handling of what the pass returns is what is under test.
func onceOver(t *testing.T, env *Env, store *keeper.Store, kh sealStateClient) error {
	t.Helper()
	bundle := storeBundle(t, store)
	c := &keeperRunCommand{once: true, check: func(ctx context.Context, env *Env, store *keeper.Store, cfg keeper.Config) (keeperPassResult, error) {
		return keeperCheckWith(ctx, env, store, cfg, kh, bundle)
	}}
	return c.Run(context.Background(), env, []string{"prod"})
}

// Review finding C-ledger-exit0. A re-seed the ledger did not record was a
// WARNING and exit 0 ("kept"): a keeper on a timer reported success on every
// pass while the ledger — which the next pass reads the budget from, and an
// audit reads — stopped counting. It is a fault on this device, exit 1, and
// the replica's re-seed is still reported. (Since review finding RV2-1 the
// push is recorded as pending before it is made, so what is lost here is its
// outcome; the pending entry still counts.)
func TestAnUnrecordedReseedIsAFaultOnThisDevice(t *testing.T) {
	env, dir, store, _ := installedKeeper(t)
	var errb bytes.Buffer
	env.Err = &errb
	fleet := &fakeStateKeyholder{phase: "restart-sealed"}
	fleet.replica(1).phase, fleet.replica(1).generation, fleet.replica(1).keys = "unsealed", 3, heldKeys(liveKeyring(t, dir, "prod"))

	err := onceOver(t, env, store, &ledgerBreaksOnPush{fakeStateKeyholder: fleet, ledger: store.LedgerPath()})
	if !strings.Contains(errb.String(), "WARNING: the outcome of a reseed was not recorded in the ledger") {
		t.Fatalf("guard: the ledger write did not fail:\n%s", errb.String())
	}
	if code := exitCodeOf(err); code != 1 {
		t.Errorf("--once after an unrecorded re-seed exits %d (%v); want 1, a fault on this device", code, err)
	}
	if err == nil || !strings.Contains(err.Error(), "not recorded in this device's ledger") {
		t.Errorf("the error = %v; want it to say the re-seed was not recorded", err)
	}
	if fleet.pushes != 1 || fleet.replica(0).phase != "unsealed" {
		t.Errorf("replica 0 is %s after %d push(es); the push itself should have landed", fleet.replica(0).phase, fleet.pushes)
	}
	if !strings.Contains(errb.String(), "replica 0: re-seeded prod") {
		t.Errorf("the re-seed the ledger missed is not reported:\n%s", errb.String())
	}
}

// The precedence. A pass that hit a ledger fault and ALSO found a replica a
// person must see to (3), or one to retry (4), exits 1: the fault is on this
// device and outranks both. Every replica is still reported, and the error
// keeps what else the pass found, since it is the line a timer's log keeps.
// Replica 0's push is the one refused, so that its outcome is recorded and
// the ledger breaks only under replica 1's push, which lands.
func TestALedgerFaultOutranksWhatElseThePassFound(t *testing.T) {
	for _, tc := range []struct {
		name    string
		refusal error
		line    string // replica 0's report
		found   string // what the error keeps of the pass
	}{
		{"cannot keep", &keyholder.Refusal{Ordinal: 0, Code: "pin-unreadable", Reason: "pin-unreadable", Status: 409},
			"replica 0: pin-unreadable", "cannot keep"},
		{"incomplete", errors.New("tunnel dropped"), "replica 0: unreachable", "did not finish"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _, store, _ := installedKeeper(t)
			var errb bytes.Buffer
			env.Err = &errb
			fleet := &fakeStateKeyholder{phase: "restart-sealed"}
			kh := &ledgerBreaksOnPush{fakeStateKeyholder: fleet, ledger: store.LedgerPath(), refuse: map[int]error{0: tc.refusal}}

			err := onceOver(t, env, store, kh)
			if code := exitCodeOf(err); code != 1 {
				t.Errorf("exit %d (%v); want 1 — a ledger fault outranks %s", code, err, tc.name)
			}
			if err == nil || !strings.Contains(err.Error(), "not recorded in this device's ledger") || !strings.Contains(err.Error(), tc.found) {
				t.Errorf("the error = %v; want the ledger fault, and that the pass also found %q", err, tc.found)
			}
			for _, want := range []string{tc.line, "replica 1: re-seeded prod"} {
				if !strings.Contains(errb.String(), want) {
					t.Errorf("stderr omits %q; every replica is still reported:\n%s", want, errb.String())
				}
			}
		})
	}
}

// Without --once a ledger fault is reported and the keeper carries on: it
// never exits on what a pass found, and a fault is no exception.
func TestKeeperRunKeepsRunningPastALedgerFault(t *testing.T) {
	env, dir, store, _ := installedKeeper(t)
	var errb bytes.Buffer
	env.Err = &errb
	fleet := &fakeStateKeyholder{phase: "restart-sealed"}
	fleet.replica(1).phase, fleet.replica(1).generation, fleet.replica(1).keys = "unsealed", 3, heldKeys(liveKeyring(t, dir, "prod"))
	kh := &ledgerBreaksOnPush{fakeStateKeyholder: fleet, ledger: store.LedgerPath()}
	bundle := storeBundle(t, store)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	c := &keeperRunCommand{interval: time.Nanosecond, check: func(ctx context.Context, env *Env, store *keeper.Store, cfg keeper.Config) (keeperPassResult, error) {
		calls++
		if calls > 1 {
			cancel()
			return keeperPassResult{}, nil
		}
		return keeperCheckWith(ctx, env, store, cfg, kh, bundle)
	}}
	if err := c.Run(ctx, env, []string{"prod"}); err != nil {
		t.Errorf("the loop returned %v; it must keep running", err)
	}
	if calls < 2 {
		t.Errorf("the loop ran %d pass(es); want it to check again after the fault", calls)
	}
	if !strings.Contains(errb.String(), "check failed: the outcome of a re-seed was not recorded in this device's ledger") {
		t.Errorf("the loop did not report the ledger fault:\n%s", errb.String())
	}
}

// Review finding RV2-1. A ledger that reads but does not write — mode 0400
// after a restore, a read-only remount — once let every pass push and record
// nothing, and since each pass reads the budget back from the ledger, a fleet
// the cluster restarted before every pass was re-seeded without limit (24
// pushes in 12 passes against a budget of 8). A push is now recorded before it
// is made, and is not made when that fails: no pass pushes anything, and
// every pass is a fault on this device.
func TestAReadOnlyLedgerStopsEveryPush(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through mode 0400")
	}
	env, _, store, cfg := installedKeeper(t)
	var errb bytes.Buffer
	env.Err = &errb
	path := store.LedgerPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.WriteFile(path, nil, keyholder.LedgerMode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, keyholder.LedgerMode) })
	fleet := &fakeStateKeyholder{phase: "restart-sealed"}
	bundle := storeBundle(t, store)

	for pass := range cfg.Budget + 4 {
		// The cluster restarts both replicas before every pass.
		for i := range 2 {
			fleet.replica(i).phase, fleet.replica(i).generation, fleet.replica(i).keys = "restart-sealed", 0, nil
		}
		p, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, bundle)
		if code := exitCodeOf(err); code != 1 || !strings.Contains(err.Error(), "so none was") {
			t.Fatalf("pass %d: exit %d (%v); want 1, the ledger fault that stopped the push", pass, code, err)
		}
		for _, d := range p.Decisions {
			if d.Action != keeper.ActionLedgerUnwritable {
				t.Errorf("pass %d, replica %d: %s (%s); want %s", pass, d.Ordinal, d.Action, d.Reason, keeper.ActionLedgerUnwritable)
			}
		}
	}
	if fleet.pushes != 0 {
		t.Errorf("%d re-seed(s) pushed through a ledger that records none (budget %d per %s)", fleet.pushes, cfg.Budget, cfg.Window)
	}
	for _, want := range []string{"replica 0: ledger-unwritable", "replica 1: ledger-unwritable"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr omits %q:\n%s", want, errb.String())
		}
	}
	if code := exitCodeOf(onceOver(t, env, store, fleet)); code != 1 {
		t.Errorf("--once over a read-only ledger exits %d; want 1, a fault on this device", code)
	}
}

// ledgerReadOnlyOnPush makes this device's ledger read-only under every push:
// the pending entry written just before it is on disk, and the outcome cannot
// follow — which is also what a disk the pending entry filled looks like.
type ledgerReadOnlyOnPush struct {
	*fakeStateKeyholder
	ledger string
}

func (b *ledgerReadOnlyOnPush) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	_ = os.Chmod(b.ledger, 0o400)
	return b.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
}

// RV2-1, the other half: a push whose outcome the ledger lost still spends
// the budget. Its pending entry stands for it, as a success, so a fleet the
// cluster restarts before every pass is re-seeded exactly budget times and
// then refused — and the audit reads every one of them as unconfirmed.
func TestALostOutcomeStillSpendsTheBudget(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through mode 0400")
	}
	env, _, store, cfg := installedKeeper(t)
	var errb bytes.Buffer
	env.Err = &errb
	path := store.LedgerPath()
	t.Cleanup(func() { _ = os.Chmod(path, keyholder.LedgerMode) })
	fleet := &fakeStateKeyholder{phase: "restart-sealed"}
	kh := &ledgerReadOnlyOnPush{fakeStateKeyholder: fleet, ledger: path}
	bundle := storeBundle(t, store)

	for range cfg.Budget + 4 {
		// Writable again by the next pass, as a disk is once space frees.
		_ = os.Chmod(path, keyholder.LedgerMode)
		for i := range 2 {
			fleet.replica(i).phase, fleet.replica(i).generation, fleet.replica(i).keys = "restart-sealed", 0, nil
		}
		_, _ = keeperCheckWith(context.Background(), env, store, cfg, kh, bundle)
	}
	if fleet.pushes != cfg.Budget {
		t.Errorf("%d re-seed(s) pushed against a budget of %d: the pushes whose outcome was lost were not counted", fleet.pushes, cfg.Budget)
	}
	if !strings.Contains(errb.String(), string(keeper.ActionBudget)) {
		t.Errorf("the budget never refused:\n%s", errb.String())
	}
	entries, err := keyholder.ReadLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if b := keeper.Budget(entries, cfg.Budget, cfg.Window, time.Now().UTC()); b.Used != cfg.Budget || b.Allowed {
		t.Errorf("the ledger's budget reads %s; want all %d spent", b, cfg.Budget)
	}
	if a := keeper.Reconcile(cfg.Instance, entries); a.Unconfirmed != cfg.Budget || a.Reseeds != cfg.Budget {
		t.Errorf("audit: %d unconfirmed, %d reseeds; want %d of each", a.Unconfirmed, a.Reseeds, cfg.Budget)
	}
}

// pushReadsLedger records the newest ledger entry at the moment of each push.
type pushReadsLedger struct {
	*fakeStateKeyholder
	ledger string
	newest []keyholder.LedgerEntry
}

func (p *pushReadsLedger) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	entries, err := keyholder.ReadLedger(p.ledger)
	if err == nil && len(entries) > 0 {
		p.newest = append(p.newest, entries[len(entries)-1])
	} else {
		p.newest = append(p.newest, keyholder.LedgerEntry{})
	}
	return p.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
}

// The order is the guarantee: when a push is made, the entry that records it
// is already on this device's disk — naming the replica, the device and the
// process — and the outcome written after it settles it, so a pass whose
// writes all landed reads exactly as it did before pending entries existed.
func TestAPushIsRecordedBeforeItIsMade(t *testing.T) {
	env, _, store, cfg := installedKeeper(t)
	fleet := &fakeStateKeyholder{phase: "restart-sealed"}
	kh := &pushReadsLedger{fakeStateKeyholder: fleet, ledger: store.LedgerPath()}
	if _, err := keeperCheckWith(context.Background(), env, store, cfg, kh, storeBundle(t, store)); err != nil {
		t.Fatal(err)
	}
	if len(kh.newest) != 2 {
		t.Fatalf("%d push(es); want both replicas re-seeded", len(kh.newest))
	}
	for i, e := range kh.newest {
		if e.Result != keeper.ResultPending || e.Ordinal != i || e.Intent != keeper.IntentReseed || e.Device != cfg.Device || e.Boot != "b0" {
			t.Errorf("at replica %d's push the ledger's newest entry is %+v; want its pending entry", i, e)
		}
	}
	entries, err := keyholder.ReadLedger(store.LedgerPath())
	if err != nil {
		t.Fatal(err)
	}
	if open := keeper.Unsettled(entries); len(open) != 0 {
		t.Errorf("unsettled entries %v after a pass whose writes landed:\n%+v", open, entries)
	}
	a := keeper.Reconcile(cfg.Instance, entries)
	if a.Reseeds != 2 || a.Refused != 0 || a.Unconfirmed != 0 {
		t.Errorf("audit: %d reseeds, %d refused, %d unconfirmed; want 2, 0, 0", a.Reseeds, a.Refused, a.Unconfirmed)
	}
	if b := keeper.Budget(entries, cfg.Budget, cfg.Window, time.Now().UTC()); b.Used != 2 {
		t.Errorf("budget used %d; want 2 — a settled pending entry is not a second push", b.Used)
	}
}

// keeper status names the pushes whose outcome its ledger lost.
func TestKeeperStatusNamesUnconfirmedPushes(t *testing.T) {
	env, out, _, dir, passFile := keeperEnv(t, output.ModeHuman)
	packet := enroll(t, env, passFile, "study-desktop")
	if err := (&keeperInstallCommand{passphraseFile: passFile, acceptRisk: true}).Run(context.Background(), env, []string{packet}); err != nil {
		t.Fatalf("keeper install: %v", err)
	}
	store, err := keeper.OpenStore(dir.KeeperDir("prod"))
	if err != nil {
		t.Fatal(err)
	}
	if err := keyholder.AppendLedger(store.LedgerPath(), keyholder.LedgerEntry{
		Time: time.Now().UTC(), Instance: "prod", Intent: keeper.IntentReseed, Device: "study-desktop",
		Boot: "abcd1234", Result: keeper.ResultPending,
	}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := (&keeperStatusCommand{}).Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("keeper status: %v", err)
	}
	for _, want := range []string{"reseeds     1 into 1 distinct keyholder process", "unconfirmed 1 push(es)", "budget      1 of 8 used"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status omits %q:\n%s", want, out.String())
		}
	}
}

// A push refused because the replica cannot read its pin names the repair,
// not a re-enrolment that would be refused the same way.
func TestAKeeperRefusedOnAnUnreadablePinNamesTheRepair(t *testing.T) {
	env, dir, store, cfg := installedKeeper(t)
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	fleet := servingFleet(t, env, meta, dir)
	for i := range 2 {
		fleet.replica(i).phase, fleet.replica(i).keys, fleet.replica(i).generation = "restart-sealed", nil, 0
	}
	unreadable := &refusesWith{fakeStateKeyholder: fleet, code: "pin-unreadable"}
	pass, err := keeperCheckWith(context.Background(), env, store, cfg, unreadable, storeBundle(t, store))
	if err != nil {
		t.Fatal(err)
	}
	decisions := pass.Decisions
	for _, d := range decisions {
		if d.Action != keeper.ActionPinUnreadable || !strings.Contains(d.Reason, "storage key pin") || strings.Contains(d.Reason, "re-enrol") {
			t.Errorf("replica %d: %s (%s); want pin-unreadable, naming 'storage key pin' and not re-enrolment", d.Ordinal, d.Action, d.Reason)
		}
	}
	if code := exitCodeOf(keeperPassError("prod", pass)); code != exitCannotKeep {
		t.Errorf("a pass refused on an unreadable pin exits %d; want %d — a person must repair it", code, exitCannotKeep)
	}
}

// refusesWith answers every push with one keyholder code.
type refusesWith struct {
	*fakeStateKeyholder
	code string
}

func (r *refusesWith) Unseal(_ context.Context, i int, _ []byte, _ string) (keyholder.State, error) {
	return keyholder.State{}, &keyholder.Refusal{Ordinal: i, Code: r.code, Reason: r.code, Status: 409}
}

// openPacket reads a written packet back with the test passphrase.
func openPacket(t *testing.T, path string) *keeper.Packet {
	t.Helper()
	sealed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := keeper.Open(sealed, keeperPass)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Enrolment records the token of the leaf it put in the packet. It is the only
// moment this machine holds that leaf, and the only way the operator can later
// say which device a tunnel stream in Shrike's picture was.
func TestEnrolRecordsTheLeafToken(t *testing.T) {
	env, _, _, dir, passFile := keeperEnv(t, output.ModeHuman)
	p := openPacket(t, enroll(t, env, passFile, "laptop"))
	want, err := identity.LeafTokenPEM(p.LeafCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Keepers) != 1 || !slices.Equal(meta.Keepers[0].LeafTokens, []string{want}) {
		t.Errorf("Keepers = %+v, want the packet's leaf token %s recorded", meta.Keepers, want)
	}
	// The token names the device's leaf, not the operator's.
	opLeaf, err := dir.LoadOperatorLeaf("prod")
	if err != nil {
		t.Fatal(err)
	}
	if op, _ := identity.LeafTokenPEM(opLeaf); op == want {
		t.Error("the keeper was recorded under the operator's token")
	}
}

// Re-enrolling a device keeps the tokens of its earlier leaves: each stays
// valid in the cluster until its own NotAfter, and a stream one of them opens
// must still be named as this device's. A revocation keeps them too.
func TestReEnrolmentKeepsEarlierLeafTokens(t *testing.T) {
	env, _, _, dir, passFile := keeperEnv(t, output.ModeHuman)
	first := openPacket(t, enroll(t, env, passFile, "laptop"))
	second := openPacket(t, enroll(t, env, passFile, "laptop"))
	t1, _ := identity.LeafTokenPEM(first.LeafCertPEM)
	t2, _ := identity.LeafTokenPEM(second.LeafCertPEM)
	if err := (&keeperRevokeCommand{assumeYes: true}).Run(context.Background(), env, []string{"prod", "laptop"}); err != nil {
		t.Fatal(err)
	}
	meta, err := dir.LoadInstanceMetadata("prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(meta.Keepers) != 1 || !slices.Equal(meta.Keepers[0].LeafTokens, []string{t1, t2}) {
		t.Errorf("Keepers = %+v, want tokens [%s %s], oldest first", meta.Keepers, t1, t2)
	}
}

// Enroll and install speak of the budget the way status does — in days, with a
// count that agrees — while JSON keeps the flag's own duration syntax, which a
// script can parse back. The 2026-11-10 walk printed "8 reseeds per 720h0m0s".
func TestEnrollAndInstallSpeakInDays(t *testing.T) {
	env, out, _, _, passFile := keeperEnv(t, output.ModeHuman)
	packet := filepath.Join(t.TempDir(), "one.packet")
	c := &keeperEnrollCommand{out: packet, passphraseFile: passFile, budget: 1, window: keeper.DefaultWindow}
	if err := c.Run(context.Background(), env, []string{"prod", "one"}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	inst := &keeperInstallCommand{passphraseFile: passFile, acceptRisk: true}
	if err := inst.Run(context.Background(), env, []string{packet}); err != nil {
		t.Fatalf("install: %v", err)
	}
	got := out.String()
	if n := strings.Count(got, "budget      1 reseed per 30 days\n"); n != 2 {
		t.Errorf("want the budget in days, singular, from enroll and install; found it %d time(s):\n%s", n, got)
	}
	if strings.Contains(got, "720h") {
		t.Errorf("a person was shown the window as a Go duration:\n%s", got)
	}

	jenv, jout, _, _, jpass := keeperEnv(t, output.ModeJSON)
	jc := &keeperEnrollCommand{out: filepath.Join(t.TempDir(), "j.packet"), passphraseFile: jpass, budget: 8, window: keeper.DefaultWindow}
	if err := jc.Run(context.Background(), jenv, []string{"prod", "j"}); err != nil {
		t.Fatalf("enroll (json): %v", err)
	}
	if !strings.Contains(jout.String(), `"window":"720h0m0s"`) && !strings.Contains(jout.String(), `"window": "720h0m0s"`) {
		t.Errorf("JSON window changed; it is a contract:\n%s", jout)
	}
}

// The packet is not keys.yaml: losing it loses nothing, and the hazard is the
// opposite one — whoever holds it with the passphrase holds the device. The
// walk's build told the operator the packet's loss was permanent data loss.
func TestEnrollWarnsOfDisclosureNotLoss(t *testing.T) {
	env, _, errb, _, passFile := keeperEnv(t, output.ModeHuman)
	enroll(t, env, passFile, "study-desktop")
	got := errb.String()
	if strings.Contains(got, datasphere.KeyLossWarning) {
		t.Errorf("enroll calls the packet a keyring:\n%s", got)
	}
	for _, want := range []string{
		"Losing the packet loses nothing",
		"can read what is stored under the keys it carries",
		"'farcast keeper revoke' alone stops neither",
		"'farcast storage key rotate prod', then 'farcast storage key rekey prod'",
		"nothing undoes what was read before",
		`holds keeper "study-desktop"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("enroll's warning omits %q:\n%s", want, got)
		}
	}
	// The remedy it names is the one revoke prints, in the same order.
	remedy := revokeRemedy("prod")
	if !strings.Contains(got, "'"+remedy[0]+"'") || !strings.Contains(got, "'"+remedy[1]+"'") {
		t.Errorf("enroll's remedy is not revoke's %v:\n%s", remedy[:2], got)
	}
}

// Counts agree with their nouns in status, and a backup reason recorded before
// it lost its "keeper: " prefix still reads as a reason.
func TestKeeperStatusCountsAgreeAndNotesReadAsReasons(t *testing.T) {
	var b bytes.Buffer
	r := keeperStatusResult{
		Keeping: []keeperStatusEntry{{
			Instance: "prod", Device: "one", Generation: 3, Reseeds: 1, Boots: 1,
			BudgetUsed: 1, BudgetLimit: 1, BackupNote: "keeper: this platform has no backup pipeline",
		}},
		Fleet:       []fleetRow{{Instance: "prod", Device: "one", Budget: 1, Window: "30 days"}},
		FleetBudget: []fleetBudget{{Instance: "prod", Window: "30 days", Devices: 1, Reseeds: 1}},
	}
	if err := r.Human(&b); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	for _, want := range []string{
		"reseeds     1 into 1 distinct keyholder process\n",
		"fleet budget: up to 1 reseed per 30 days across 1 device(s)",
		"NOT verifiably excluded — this platform has no backup pipeline\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("status omits %q:\n%s", want, got)
		}
	}

	b.Reset()
	inst := keeperInstallResult{Instance: "prod", Device: "one", Budget: 2, Window: "720h0m0s", window: keeper.DefaultWindow,
		BackupNote: "keeper: this platform has no backup pipeline"}
	if err := inst.Human(&b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"budget      2 reseeds per 30 days\n", "NOT verifiably excluded — this platform has no backup pipeline\n"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("install omits %q:\n%s", want, b.String())
		}
	}
}

// distinctBoots gives each replica a boot label of its own, as a real fleet
// does; gen moves on when the test restarts a replica.
type distinctBoots struct {
	*fakeStateKeyholder
	gen int
}

func (d *distinctBoots) label(i int) string { return fmt.Sprintf("boot-%d-%d", i, d.gen) }

func (d *distinctBoots) State(ctx context.Context, i int) (keyholder.State, error) {
	st, err := d.fakeStateKeyholder.State(ctx, i)
	st.Boot = d.label(i)
	return st, err
}

func (d *distinctBoots) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	st, err := d.fakeStateKeyholder.Unseal(ctx, i, payload, intent)
	if err == nil {
		st.Boot = d.label(i)
	}
	return st, err
}

// overlappingPass runs a whole second pass (another keeper process on this
// device) while the first is between its pending entry for replica 0 and
// that push.
type overlappingPass struct {
	*distinctBoots
	other func()
	ran   bool
}

func (o *overlappingPass) Unseal(ctx context.Context, i int, payload []byte, intent string) (keyholder.State, error) {
	if !o.ran && i == 0 {
		o.ran = true
		o.other()
	}
	return o.distinctBoots.Unseal(ctx, i, payload, intent)
}

// Review finding V3-1. Two keeper processes on one device that overlap — a
// timer's --once and a manual one — each announce a push to the same replica
// before either makes it. Paired by replica, B's outcome settled A's
// announcement, A's outcome settled nothing, and B's announcement stood open:
// the audit read an unconfirmed second push into the process B's push landed
// in. Each push names itself now, and every announcement is settled by its
// own outcome. (keeperCheckWith is called directly, past the pass lock that
// keeps two passes on one device from overlapping at all: this is what the
// ledger says if they do, as on a platform with no lock.)
func TestOverlappingPassesEachSettleTheirOwnPush(t *testing.T) {
	env, _, store, cfg := installedKeeper(t)
	env.Err = &bytes.Buffer{}
	fleet := &distinctBoots{fakeStateKeyholder: &fakeStateKeyholder{phase: "restart-sealed"}}
	bundle := storeBundle(t, store)
	a := &overlappingPass{distinctBoots: fleet}
	a.other = func() {
		if _, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, bundle); err != nil {
			t.Errorf("pass B: %v", err)
		}
	}
	if _, err := keeperCheckWith(context.Background(), env, store, cfg, a, bundle); err != nil {
		t.Fatalf("pass A: %v", err)
	}
	entries, err := keyholder.ReadLedger(store.LedgerPath())
	if err != nil {
		t.Fatal(err)
	}
	if len(fleet.sent) != 2 || len(entries) != 8 {
		t.Fatalf("guard: %d bundles accepted, %d ledger lines; want 2 and 8 (four pushes, two lines each)", len(fleet.sent), len(entries))
	}
	if entries[0].Result != keeper.ResultPending || entries[1].Result != keeper.ResultPending {
		t.Fatalf("guard: the passes did not interleave:\n%+v", entries)
	}
	if open := keeper.Unsettled(entries); len(open) != 0 {
		t.Errorf("announcements left open although every outcome was recorded: %v\n%+v", open, entries)
	}
	if audit := keeper.Reconcile(cfg.Instance, entries); audit.Unconfirmed != 0 {
		t.Errorf("audit: %d unconfirmed; every push's outcome is in the ledger", audit.Unconfirmed)
	}
}

// Review finding V3-1, the lock. One device makes one pass at a time: a
// second keeper process that finds a pass running makes no call, writes no
// line, and exits 4 for the next pass to retry — it does not wait, and it
// does not push into a replica the running pass is already re-seeding.
func TestASecondPassOnThisDeviceStandsAside(t *testing.T) {
	env, _, store, _ := installedKeeper(t)
	env.Err = &bytes.Buffer{}
	fleet := &fakeStateKeyholder{phase: "restart-sealed"}
	release, err := store.LockPass()
	if err != nil {
		t.Fatal(err)
	}
	err = onceOver(t, env, store, fleet)
	if code := exitCodeOf(err); code != exitIncomplete || !errors.Is(err, keeper.ErrPassRunning) {
		t.Errorf("--once while another pass runs: exit %d (%v); want %d, another pass running", code, err, exitIncomplete)
	}
	if fleet.pushes != 0 {
		t.Errorf("%d push(es) made beside a running pass", fleet.pushes)
	}
	if entries, _ := keyholder.ReadLedger(store.LedgerPath()); len(entries) != 0 {
		t.Errorf("the pass that stood aside wrote %d ledger line(s)", len(entries))
	}
	release()
	if err := onceOver(t, env, store, fleet); err != nil || fleet.pushes != 2 {
		t.Errorf("once the other pass ended: %v after %d push(es); want both replicas re-seeded", err, fleet.pushes)
	}
}

// Review finding V3-1, the killed keeper. A keeper stopped between its
// pending entry and the push leaves an announcement nothing settles, and the
// next pass re-seeds the same still-sealed process: the audit reads that
// process as re-seeded twice. That cannot be told from a solicitation, so the
// row stays — and says that one of its two pushes is unconfirmed, and what
// that can mean.
func TestAKilledKeeperReadsAsUnconfirmedOnItsRow(t *testing.T) {
	env, out, _, dir, passFile := keeperEnv(t, output.ModeHuman)
	packet := enroll(t, env, passFile, "study-desktop")
	if err := (&keeperInstallCommand{passphraseFile: passFile, acceptRisk: true}).Run(context.Background(), env, []string{packet}); err != nil {
		t.Fatalf("keeper install: %v", err)
	}
	store, err := keeper.OpenStore(dir.KeeperDir("prod"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := store.Config()
	if err != nil {
		t.Fatal(err)
	}
	env.Err = &bytes.Buffer{}
	fleet := &distinctBoots{fakeStateKeyholder: &fakeStateKeyholder{phase: "restart-sealed"}}
	if err := keyholder.AppendLedger(store.LedgerPath(), keyholder.LedgerEntry{
		Time: time.Now().UTC().Add(-time.Minute), Instance: cfg.Instance, Ordinal: 0, Intent: keeper.IntentReseed,
		Generation: cfg.Generation, Device: cfg.Device, Boot: fleet.label(0), Result: keeper.ResultPending, Push: keeper.NewPushID(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, storeBundle(t, store)); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := (&keeperStatusCommand{}).Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("keeper status: %v", err)
	}
	for _, want := range []string{
		"process boot-0-0 re-seeded 2 times", ": 1 unconfirmed",
		"An unconfirmed push may never have landed",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status omits %q:\n%s", want, out.String())
		}
	}
}

// Review finding V3-4. The rest of a pass budgets from the pending entry of a
// push whose outcome the ledger lost, as the next pass will: with one slot
// left, replica 0 takes it and replica 1 is refused by the budget — not
// tried, and found unwritable.
func TestALostOutcomeSpendsTheLastSlotWithinThePass(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes through mode 0400")
	}
	env, _, store, cfg := installedKeeper(t)
	env.Err = &bytes.Buffer{}
	path := store.LedgerPath()
	now := time.Now().UTC()
	for i := range cfg.Budget - 1 {
		push := keeper.NewPushID()
		for _, r := range []string{keeper.ResultPending, "ok"} {
			if err := keyholder.AppendLedger(path, keyholder.LedgerEntry{Time: now.Add(-time.Duration(i+1) * time.Hour), Instance: cfg.Instance,
				Ordinal: i % 2, Intent: keeper.IntentReseed, Generation: cfg.Generation, Device: cfg.Device,
				Boot: fmt.Sprintf("old-%d", i), Result: r, Push: push}); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Cleanup(func() { _ = os.Chmod(path, keyholder.LedgerMode) })
	fleet := &fakeStateKeyholder{phase: "restart-sealed"}
	pass, _ := keeperCheckWith(context.Background(), env, store, cfg, &ledgerReadOnlyOnPush{fakeStateKeyholder: fleet, ledger: path}, storeBundle(t, store))
	if fleet.pushes != 1 {
		t.Errorf("%d push(es) with one budget slot left; want 1", fleet.pushes)
	}
	if len(pass.Decisions) != 2 || pass.Decisions[1].Action != keeper.ActionBudget {
		t.Errorf("decisions %+v; want replica 1 refused by the budget", pass.Decisions)
	}
}

// solicitor is ADR 0008 finding 1's: it presents the keyholder's server leaf
// (it rests in a Secret), says every replica restarted, takes the sealed
// bundle — the challenge was its own, so it can open it — and answers with
// a refusal, or fails before anything is sent when sentNothing is set.
type solicitor struct {
	sentNothing bool
	received    int
}

func (s *solicitor) State(_ context.Context, i int) (keyholder.State, error) {
	return keyholder.State{Phase: "restart-sealed", Boot: fmt.Sprintf("same-%d", i)}, nil
}

func (s *solicitor) Unseal(_ context.Context, i int, _ []byte, _ string) (keyholder.State, error) {
	if s.sentNothing {
		return keyholder.State{}, &keyholder.NothingSentError{Err: errors.New("reaching replica: the tunnel is down")}
	}
	s.received++
	return keyholder.State{}, &keyholder.Refusal{Ordinal: i, Code: "already-serving", Reason: "serving (already-serving)", Status: 409}
}

// Review finding V3-3. A refusal that arrives after the bundle was sent moved
// key material as far as this device can tell, and is counted: a solicitor
// that answers every push with "already serving" once let 48 bundles leave in
// 24 passes against a budget of 8, with the budget at 0 and the audit clean.
// Now the budget trips at its limit, and the audit names every one. A push
// that sent nothing — a tunnel that is down — still spends nothing.
func TestARefusalAfterSendingSpendsTheBudget(t *testing.T) {
	t.Run("refused after sending", func(t *testing.T) {
		env, _, store, cfg := installedKeeper(t)
		env.Err = &bytes.Buffer{}
		s := &solicitor{}
		bundle := storeBundle(t, store)
		var last keeperPassResult
		for range cfg.Budget * 3 {
			pass, err := keeperCheckWith(context.Background(), env, store, cfg, s, bundle)
			if err != nil {
				t.Fatal(err)
			}
			last = pass
		}
		if s.received != cfg.Budget {
			t.Errorf("%d bundles delivered to a solicitor that refused each one; want the budget, %d", s.received, cfg.Budget)
		}
		for _, d := range last.Decisions {
			if d.Action != keeper.ActionBudget {
				t.Errorf("replica %d: %s; want the budget's refusal", d.Ordinal, d.Action)
			}
		}
		entries, err := keyholder.ReadLedger(store.LedgerPath())
		if err != nil {
			t.Fatal(err)
		}
		a := keeper.Reconcile(cfg.Instance, entries)
		if a.Reseeds != cfg.Budget || a.RefusedAfterSend != cfg.Budget || a.Refused != 0 || a.Clean() {
			t.Errorf("audit: %d reseeds, %d refused after sending, %d refused, clean=%v; want %d, %d, 0 and not clean",
				a.Reseeds, a.RefusedAfterSend, a.Refused, a.Clean(), cfg.Budget, cfg.Budget)
		}
	})
	t.Run("nothing sent", func(t *testing.T) {
		env, _, store, cfg := installedKeeper(t)
		env.Err = &bytes.Buffer{}
		s := &solicitor{sentNothing: true}
		bundle := storeBundle(t, store)
		for range cfg.Budget + 2 {
			if _, err := keeperCheckWith(context.Background(), env, store, cfg, s, bundle); err != nil {
				t.Fatal(err)
			}
		}
		entries, err := keyholder.ReadLedger(store.LedgerPath())
		if err != nil {
			t.Fatal(err)
		}
		if b := keeper.Budget(entries, cfg.Budget, cfg.Window, time.Now().UTC()); b.Used != 0 {
			t.Errorf("budget %s after pushes that sent nothing; want none used", b)
		}
		for _, e := range entries {
			if e.Result != keeper.ResultPending && e.Result != "refused" {
				t.Errorf("a push that sent nothing was recorded as %q", e.Result)
			}
		}
	})
}

// Review finding R3-3, the keeper's half. --once returns its pass's reason as
// an error, and an error keeps its newlines: a replica's words in a reason —
// a State error, a push error — are quoted, so they cannot start a line that
// reads as this machine's.
func TestAKeeperPassErrorQuotesAReplicasWords(t *testing.T) {
	const forged = "x\nfarcast: forged: storage unsealed\x1b[2K"
	for _, tc := range []struct {
		name string
		kh   sealStateClient
	}{
		{"a State error", &stateFails{err: errors.New(forged)}},
		{"a push error", &pushFails{fakeStateKeyholder: &fakeStateKeyholder{phase: "restart-sealed"}, err: errors.New(forged)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _, store, _ := installedKeeper(t)
			env.Err = &bytes.Buffer{}
			err := onceOver(t, env, store, tc.kh)
			if err == nil {
				t.Fatal("guard: the pass found nothing wrong")
			}
			if strings.ContainsAny(err.Error(), "\n\x1b") || !strings.Contains(err.Error(), `x\nfarcast: forged`) {
				t.Errorf("--once's error = %q; want the replica's words in it, quoted onto one line", err.Error())
			}
		})
	}
}

// stateFails is a fleet whose every State call fails with err.
type stateFails struct{ err error }

func (s *stateFails) State(context.Context, int) (keyholder.State, error) {
	return keyholder.State{}, s.err
}

func (s *stateFails) Unseal(context.Context, int, []byte, string) (keyholder.State, error) {
	return keyholder.State{}, s.err
}

// pushFails is a fleet whose every push fails with err, after sending.
type pushFails struct {
	*fakeStateKeyholder
	err error
}

func (p *pushFails) Unseal(context.Context, int, []byte, string) (keyholder.State, error) {
	return keyholder.State{}, p.err
}

// Review finding R3-3, keeperPassError itself: each reason it puts in --once's
// error — the incomplete replica's, the cannot-keep replica's, the fleet's
// verdict — can carry a replica's words, and goes in quoted.
func TestKeeperPassErrorQuotesEachReason(t *testing.T) {
	const forged = "x\nfarcast: forged: storage unsealed\x1b[2K"
	for _, tc := range []struct {
		name string
		pass keeperPassResult
	}{
		{"incomplete", keeperPassResult{Decisions: []keeper.Decision{{Ordinal: 0, Action: keeper.ActionUnknown, Reason: forged}}}},
		{"cannot keep", keeperPassResult{Decisions: []keeper.Decision{{Ordinal: 0, Action: keeper.ActionStale, Reason: forged}}}},
		{"the fleet's verdict", keeperPassResult{Fleet: keeper.Fleet{Mismatch: forged}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := keeperPassError("prod", tc.pass)
			if err == nil {
				t.Fatal("guard: the pass kept the instance")
			}
			if strings.ContainsAny(err.Error(), "\n\x1b") || !strings.Contains(err.Error(), `x\nfarcast: forged`) {
				t.Errorf("error = %q; want the reason in it, quoted onto one line", err.Error())
			}
		})
	}
}

// keeper status reads a refusal after sending as a push: counted, named on
// its own line, and noted on the row of a process it re-seeded twice. A boot
// label is the keyholder's word, read back through the tunnel, and goes
// through terminalText like the rest.
func TestKeeperStatusNamesRefusalsAfterSending(t *testing.T) {
	env, out, _, dir, passFile := keeperEnv(t, output.ModeHuman)
	packet := enroll(t, env, passFile, "study-desktop")
	if err := (&keeperInstallCommand{passphraseFile: passFile, acceptRisk: true}).Run(context.Background(), env, []string{packet}); err != nil {
		t.Fatalf("keeper install: %v", err)
	}
	store, err := keeper.OpenStore(dir.KeeperDir("prod"))
	if err != nil {
		t.Fatal(err)
	}
	const boot = "\x1b]52;c;" // eight bytes: all of it survives shortBoot
	now := time.Now().UTC()
	for i, result := range []string{"ok", keeper.ResultRefusedAfterSend} {
		if err := keyholder.AppendLedger(store.LedgerPath(), keyholder.LedgerEntry{
			Time: now.Add(time.Duration(i) * time.Minute), Instance: "prod", Intent: keeper.IntentReseed, Device: "study-desktop",
			Boot: boot, Result: result, Push: keeper.NewPushID(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	out.Reset()
	if err := (&keeperStatusCommand{}).Run(context.Background(), env, []string{"prod"}); err != nil {
		t.Fatalf("keeper status: %v", err)
	}
	for _, want := range []string{
		"reseeds     2 into 1 distinct keyholder process", "after send  1 push(es) refused after the bundle was sent",
		"re-seeded 2 times", ": 1 refused after the bundle was sent", "may have lost a race to another pusher",
		"budget      2 of 8 used",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status omits %q:\n%s", want, out.String())
		}
	}
	onlyPrintable(t, "keeper status", out.String())
}
