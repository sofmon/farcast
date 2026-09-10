package keeper

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
)

const pass = "correct-horse-battery-staple"

func samplePacket() *Packet {
	return &Packet{
		Version: 1, Instance: "prod", Device: "study-desktop",
		Carrier: "203.0.113.9:8443", ServerName: "prod.fatline.farcast",
		CACertPEM:   []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"),
		LeafCertPEM: []byte("-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----"),
		LeafKeyPEM:  []byte("-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----"),
		Bundle:      []byte("version: 1\ninstance: prod\n"),
		Generation:  3, Budget: DefaultBudget, Window: DefaultWindow,
		IssuedAt: time.Now().UTC().Truncate(time.Second),
	}
}

func TestPacketRoundTrip(t *testing.T) {
	want := samplePacket()
	sealed, err := Seal(want, pass)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// The armored file must not contain the material it carries.
	for _, secret := range [][]byte{want.LeafKeyPEM, want.Bundle} {
		if strings.Contains(string(sealed), string(secret)) {
			t.Error("the sealed packet contains its own key material")
		}
	}
	got, err := Open(sealed, pass)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Instance != want.Instance || got.Device != want.Device ||
		got.Generation != want.Generation || got.Budget != want.Budget || got.Window != want.Window {
		t.Errorf("round trip = %+v, want the packet back", got)
	}
	if string(got.Bundle) != string(want.Bundle) || string(got.LeafKeyPEM) != string(want.LeafKeyPEM) {
		t.Error("the material did not survive the round trip")
	}

	if _, err := Open(sealed, "a-different-passphrase"); err == nil {
		t.Error("Open accepted a wrong passphrase")
	}
}

func TestPacketValidation(t *testing.T) {
	for name, mangle := range map[string]func(*Packet){
		"no instance":   func(p *Packet) { p.Instance = "" },
		"no device":     func(p *Packet) { p.Device = "" },
		"no carrier":    func(p *Packet) { p.Carrier = "" },
		"no server":     func(p *Packet) { p.ServerName = "" },
		"no CA":         func(p *Packet) { p.CACertPEM = nil },
		"no leaf":       func(p *Packet) { p.LeafCertPEM = nil },
		"no key":        func(p *Packet) { p.LeafKeyPEM = nil },
		"no bundle":     func(p *Packet) { p.Bundle = nil },
		"no budget":     func(p *Packet) { p.Budget = 0 },
		"no window":     func(p *Packet) { p.Window = 0 },
		"wrong version": func(p *Packet) { p.Version = 99 },
	} {
		t.Run(name, func(t *testing.T) {
			p := samplePacket()
			mangle(p)
			if err := p.Validate(); err == nil {
				t.Errorf("Validate accepted a packet with %s", name)
			}
			if _, err := Seal(p, pass); err == nil {
				t.Errorf("Seal accepted a packet with %s", name)
			}
		})
	}
}

// An unbounded keeper is a solicitation endpoint with no tripwire, so a packet
// carrying no budget is refused rather than defaulted.
func TestPacketWithoutABudgetIsRefusedRatherThanDefaulted(t *testing.T) {
	p := samplePacket()
	p.Budget = 0
	err := p.Validate()
	if err == nil {
		t.Fatal("a budgetless packet validated")
	}
	if !strings.Contains(err.Error(), "tripwire") {
		t.Errorf("the refusal does not say why a budget is required: %v", err)
	}
}

func TestValidateDevice(t *testing.T) {
	for _, ok := range []string{"a", "study-desktop", "home-server-2"} {
		if err := ValidateDevice(ok); err != nil {
			t.Errorf("ValidateDevice(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "Study", "2desktop", "study_desktop", "study-", "a/b", strings.Repeat("x", MaxDeviceLen+1)} {
		if err := ValidateDevice(bad); err == nil {
			t.Errorf("ValidateDevice(%q) = nil, want a refusal", bad)
		}
	}
}

func TestInstallWritesRestrictedMaterial(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prod")
	store, err := Install(dir, samplePacket(), true)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != dirMode {
		t.Errorf("directory mode = %v, want %v", info.Mode().Perm(), os.FileMode(dirMode))
	}
	for _, f := range []string{caFile, leafFile, leafKey, bundleFile, configFile} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if fi.Mode().Perm() != fileMode {
			t.Errorf("%s mode = %v, want %v", f, fi.Mode().Perm(), os.FileMode(fileMode))
		}
	}
	cfg, err := store.Config()
	if err != nil {
		t.Fatalf("Config: %v", err)
	}
	if cfg.Instance != "prod" || cfg.Device != "study-desktop" || cfg.Generation != 3 {
		t.Errorf("record = %+v, want the packet's own values", cfg)
	}
	// The record says what the platform actually managed, not what was hoped.
	if runtime.GOOS == "darwin" && !cfg.BackupExcluded {
		t.Errorf("macOS install did not record a backup exclusion: %s", cfg.BackupNote)
	}
	if runtime.GOOS != "darwin" && cfg.BackupExcluded {
		t.Error("a platform with no verifiable exclusion recorded one anyway")
	}

	// The keeper record itself must hold no key material: an operator reading
	// it should never have a bundle on screen.
	raw, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "instance: prod") {
		t.Errorf("the keeper record does not name its instance:\n%s", raw)
	}
	for _, secret := range []string{"PRIVATE KEY", "BEGIN CERTIFICATE"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the keeper record contains %q; an operator reading it should never have material on screen", secret)
		}
	}
}

// A synced folder uploads the bundle continuously. That refusal is not
// overridable, which is the one place this package refuses to take an
// operator's word for it.
func TestInstallRefusesASyncedPathEvenWithForce(t *testing.T) {
	base := t.TempDir()
	for _, root := range []string{"Dropbox", "Library/Mobile Documents", "OneDrive"} {
		dir := filepath.Join(base, root, "farcast", "prod")
		_, err := Install(dir, samplePacket(), true)
		if err == nil {
			t.Fatalf("Install accepted a path under %q even with force", root)
		}
		if !strings.Contains(err.Error(), root) {
			t.Errorf("the refusal does not name the sync root: %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(dir, bundleFile)); statErr == nil {
			t.Error("a refused install left a bundle behind")
		}
	}
}

func TestRemoveKeepsTheLedger(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prod")
	store, err := Install(dir, samplePacket(), true)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := keyholder.AppendLedger(store.LedgerPath(), keyholder.LedgerEntry{
		Time: time.Now().UTC(), Instance: "prod", Intent: IntentReseed, Result: "ok", Boot: "abcd",
	}); err != nil {
		t.Fatalf("AppendLedger: %v", err)
	}
	if err := store.Remove(); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	for _, f := range []string{bundleFile, leafKey, configFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Errorf("%s survived Remove", f)
		}
	}
	// The ledger is what an audit reads afterwards. A device that erased its
	// own history on the way out would remove exactly the evidence.
	entries, err := keyholder.ReadLedger(store.LedgerPath())
	if err != nil || len(entries) != 1 {
		t.Errorf("the ledger did not survive Remove: %d entries, %v", len(entries), err)
	}
}

// A platform that cannot guarantee the exclusion cannot be a keeper — unless
// the operator says otherwise, and then the record says they did.
//
// On macOS the real exclusion always succeeds, so the refusal path is reached
// through the seam. Without this the rule would be untested on the one platform
// this is developed against.
func TestInstallRefusesWithoutAVerifiableBackupExclusion(t *testing.T) {
	original := excludeFromBackup
	excludeFromBackup = func(string) error { return errors.New("no exclusion here") }
	defer func() { excludeFromBackup = original }()

	dir := filepath.Join(t.TempDir(), "prod")
	_, err := Install(dir, samplePacket(), false)
	if err == nil {
		t.Fatal("Install proceeded without a verifiable backup exclusion")
	}
	for _, want := range []string{"no exclusion here", "cannot be a keeper", "--accept-backup-risk"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal omits %q: %v", want, err)
		}
	}
	if _, statErr := os.Stat(filepath.Join(dir, bundleFile)); statErr == nil {
		t.Error("a refused install left a bundle on disk")
	}

	// Forced, it proceeds — and writes down that it could not verify, so an
	// operator reading the record later sees what the device actually managed.
	store, err := Install(dir, samplePacket(), true)
	if err != nil {
		t.Fatalf("forced Install: %v", err)
	}
	cfg, err := store.Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BackupExcluded {
		t.Error("a forced install recorded an exclusion it did not get")
	}
	if !strings.Contains(cfg.BackupNote, "no exclusion here") {
		t.Errorf("BackupNote = %q, want the reason it failed", cfg.BackupNote)
	}
}

// Re-enrolment writes over material that is already there, and os.WriteFile
// honours its mode only when it CREATES a file.
//
// Every keeper is re-enrolled at least every 90 days when its leaf expires, so
// this is the ordinary path rather than an edge case — and a bundle that came
// back from it world-readable would be a permission regression nobody watched
// happen.
func TestReinstallTightensExistingModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prod")
	if _, err := Install(dir, samplePacket(), true); err != nil {
		t.Fatalf("Install: %v", err)
	}
	for _, f := range []string{caFile, leafFile, leafKey, bundleFile, configFile} {
		if err := os.Chmod(filepath.Join(dir, f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Install(dir, samplePacket(), true); err != nil {
		t.Fatalf("re-install: %v", err)
	}
	for _, f := range []string{caFile, leafFile, leafKey, bundleFile, configFile} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != fileMode {
			t.Errorf("%s came back from re-enrolment at %v, want %v", f, fi.Mode().Perm(), os.FileMode(fileMode))
		}
	}
}
