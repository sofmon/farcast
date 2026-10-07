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
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

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
		"name key cannot rotate", "can still re-seed",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("the revocation report omits %q:\n%s", want, report)
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
	for _, want := range []string{"storage key rotate", "storage key rekey", "keeper enroll", "storage unseal", "storage state"} {
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

	decisions, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, storeBundle(t, store))
	if err != nil {
		t.Fatalf("keeperCheckWith: %v", err)
	}
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

	decisions, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, storeBundle(t, store))
	if err != nil {
		t.Fatalf("keeperCheckWith: %v", err)
	}
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

	decisions, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, storeBundle(t, store))
	if err != nil {
		t.Fatalf("keeperCheckWith: %v", err)
	}
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

	decisions, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, ahead)
	if err != nil {
		t.Fatalf("keeperCheckWith: %v", err)
	}
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

	decisions, err := keeperCheckWith(context.Background(), env, store, cfg, fleet, storeBundle(t, store))
	if err != nil {
		t.Fatalf("keeperCheckWith: %v", err)
	}
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
	pushes := fleet.pushes

	silent := &flakyKeyholder{fakeStateKeyholder: fleet, silent: map[int]bool{1: true}}
	decisions, err := keeperCheckWith(context.Background(), env, store, cfg, silent, storeBundle(t, store))
	if err != nil {
		t.Fatalf("keeperCheckWith: %v", err)
	}
	if fleet.pushes != pushes || decisions[0].Action != keeper.ActionUnchecked {
		t.Fatalf("replica 0: %s (%s) after %d push(es); want unchecked and no push", decisions[0].Action, decisions[0].Reason, fleet.pushes-pushes)
	}
	noSplit(t, fleet)
}
