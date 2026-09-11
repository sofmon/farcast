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
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/config"
	"github.com/sofmon/farcast/farsight/cli/internal/keeper"
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
	for _, want := range []string{"did not reach the cluster", "storage rekey prod", "does not reach backwards"} {
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
