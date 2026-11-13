package keeper

import (
	"bytes"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/datasphere"
	"github.com/sofmon/farcast/farsight/cli/internal/keyholder"
	"github.com/sofmon/farcast/fatline/identity"
)

const pass = "correct-horse-battery-staple"

// samplePacket is a packet whose fields are complete and whose certificates
// are placeholders: enough for Validate, Seal and Open, which read no
// certificate. Install verifies the certificate, so its tests use enrolled.
func samplePacket() *Packet {
	return &Packet{
		Version: packetVersion, Instance: "prod", Device: "study-desktop",
		Carrier: "203.0.113.9:8443", ServerName: "prod.fatline.farcast",
		CACertPEM:   []byte("-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----"),
		LeafCertPEM: []byte("-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----"),
		Bundle:      []byte("version: 1\ninstance: prod\n"),
		Generation:  3, Budget: DefaultBudget, Window: DefaultWindow,
		IssuedAt: time.Now().UTC().Truncate(time.Second),
	}
}

// mintCA is an instance's identity: its CA, as the operator's machine holds it.
func mintCA(t *testing.T) *identity.Material {
	t.Helper()
	m, err := identity.Mint("prod")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// request makes this device a request in dir, as 'keeper request' does.
func request(t *testing.T, dir string) GeneratedRequest {
	t.Helper()
	_, gen, err := NewRequest(dir, "prod", true, false, time.Now())
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return gen
}

// packetFor is the packet the operator's machine returns for a request: a
// certificate for the request's key, issued by m's CA, and no key.
func packetFor(t *testing.T, m *identity.Material, requestDER []byte) *Packet {
	t.Helper()
	p := samplePacket()
	cert, err := identity.IssueKeeperClient(m.CACertPEM, m.CAKeyPEM, "prod", p.Device, p.Bundle, requestDER)
	if err != nil {
		t.Fatalf("IssueKeeperClient: %v", err)
	}
	p.CACertPEM, p.LeafCertPEM = m.CACertPEM, cert
	return p
}

// enrolled is a request made in dir and the packet issued for it.
func enrolled(t *testing.T, dir string) (*identity.Material, GeneratedRequest, *Packet) {
	t.Helper()
	m := mintCA(t)
	gen := request(t, dir)
	return m, gen, packetFor(t, m, gen.RequestDER)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func absent(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, f := range names {
		if _, err := os.Stat(filepath.Join(dir, f)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists (%v); want it absent", f, err)
		}
	}
}

func TestPacketRoundTrip(t *testing.T) {
	want := samplePacket()
	sealed, err := Seal(want, pass)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// The armored file must not contain the material it carries.
	if strings.Contains(string(sealed), string(want.Bundle)) {
		t.Error("the sealed packet contains its own key material")
	}
	got, err := Open(sealed, pass)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Instance != want.Instance || got.Device != want.Device ||
		got.Generation != want.Generation || got.Budget != want.Budget || got.Window != want.Window {
		t.Errorf("round trip = %+v, want the packet back", got)
	}
	if string(got.Bundle) != string(want.Bundle) || string(got.LeafCertPEM) != string(want.LeafCertPEM) {
		t.Error("the material did not survive the round trip")
	}

	if _, err := Open(sealed, "a-different-passphrase"); err == nil {
		t.Error("Open accepted a wrong passphrase")
	}
}

// B-T4. A real version 2 packet, sealed and opened, holds a certificate and a
// bundle and no private key — in the armored bytes, in what they decrypt to,
// and in what Open returns.
func TestPacketRoundTripCarriesNoKey(t *testing.T) {
	_, gen, p := enrolled(t, filepath.Join(t.TempDir(), "prod"))
	sealed, err := Seal(p, pass)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	plaintext, err := datasphere.Unarmor(datasphere.ArmorKeeperPacket, sealed, pass)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"the armored packet": sealed, "its plaintext": plaintext} {
		if bytes.Contains(b, []byte("PRIVATE KEY")) || bytes.Contains(b, []byte("leaf_key_pem")) {
			t.Errorf("%s holds a private key", name)
		}
		if bytes.Contains(b, gen.KeyPEM) {
			t.Errorf("%s holds the device's key", name)
		}
	}
	if !bytes.Contains(plaintext, []byte("version: 2")) {
		t.Errorf("the packet is not version 2")
	}
	got, err := Open(sealed, pass)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(got.LeafKeyPEM) != 0 {
		t.Error("the opened packet carries a key")
	}
	if !bytes.Equal(got.LeafCertPEM, p.LeafCertPEM) {
		t.Error("the certificate did not survive the round trip")
	}
}

// B-T3.
func TestPacketValidation(t *testing.T) {
	for name, mangle := range map[string]func(*Packet){
		"no instance":    func(p *Packet) { p.Instance = "" },
		"no device":      func(p *Packet) { p.Device = "" },
		"no carrier":     func(p *Packet) { p.Carrier = "" },
		"no server":      func(p *Packet) { p.ServerName = "" },
		"no CA":          func(p *Packet) { p.CACertPEM = nil },
		"no leaf cert":   func(p *Packet) { p.LeafCertPEM = nil },
		"a key present":  func(p *Packet) { p.LeafKeyPEM = []byte("-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----") },
		"no bundle":      func(p *Packet) { p.Bundle = nil },
		"no budget":      func(p *Packet) { p.Budget = 0 },
		"no window":      func(p *Packet) { p.Window = 0 },
		"wrong version":  func(p *Packet) { p.Version = 99 },
		"version 1":      func(p *Packet) { p.Version = 1 },
		"instance ../x":  func(p *Packet) { p.Instance = "../x" },
		"instance a/b":   func(p *Packet) { p.Instance = "a/b" },
		"instance Prod":  func(p *Packet) { p.Instance = "Prod" },
		"instance -x":    func(p *Packet) { p.Instance = "-x" },
		"instance x-":    func(p *Packet) { p.Instance = "x-" },
		"instance 33":    func(p *Packet) { p.Instance = strings.Repeat("x", 33) },
		"instance space": func(p *Packet) { p.Instance = "pr od" },
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
	if err := samplePacket().Validate(); err != nil {
		t.Fatalf("the sample packet: %v", err)
	}
	// The longest name install accepts is still a packet's.
	p := samplePacket()
	p.Instance = strings.Repeat("x", MaxInstanceLen)
	if err := p.Validate(); err != nil {
		t.Errorf("a %d-byte instance: %v", MaxInstanceLen, err)
	}

	// The two ADR 0020 refusals say what they are and what to do instead.
	p = samplePacket()
	p.LeafKeyPEM = []byte("-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----")
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "ADR 0020") || !strings.Contains(err.Error(), "private key") {
		t.Errorf("a key present = %v; want a refusal naming ADR 0020", err)
	}
	p = samplePacket()
	p.Version = 1
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "ADR 0020") || !strings.Contains(err.Error(), "keeper request") {
		t.Errorf("a version 1 packet = %v; want a refusal naming ADR 0020 and 'keeper request'", err)
	}
	// Open refuses the same: a sealed version 1 packet carrying a key does
	// not reach Install.
	v1 := samplePacket()
	v1.Version, v1.LeafKeyPEM = 1, []byte("-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----")
	plain, err := yaml.Marshal(v1)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := datasphere.Armor(datasphere.ArmorKeeperPacket, plain, pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(sealed, pass); err == nil || !strings.Contains(err.Error(), "version 1") {
		t.Errorf("Open of a version 1 packet = %v; want it refused", err)
	}
}

// A packet refused on opening has its decoded key and bundle zeroed before the
// refusal returns: the packets refused for carrying a private key are exactly
// the ones whose key would otherwise sit uncleared in the heap.
func TestARefusedPacketIsZeroedBeforeItIsRefused(t *testing.T) {
	key := []byte("-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----")
	v1 := samplePacket()
	v1.Version, v1.LeafKeyPEM = 1, key
	v2 := samplePacket()
	v2.LeafKeyPEM = key
	plain := func(p *Packet) string {
		b, err := yaml.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// A field that will not decode after the key and the bundle have: the
	// decoder fills what came before it, and stops.
	undecodable := strings.Replace(plain(v2), "budget: 8", "budget: [x]", 1)
	if undecodable == plain(v2) {
		t.Fatal("the fixture did not break the packet")
	}
	for name, text := range map[string]string{
		"a version 1 packet":            plain(v1),
		"a version 2 packet with a key": plain(v2),
		"a packet that does not decode": undecodable,
	} {
		var p Packet
		if err := decodePacket([]byte(text), &p); err == nil {
			t.Errorf("%s: decoded and validated", name)
			continue
		}
		if p.LeafKeyPEM != nil || p.Bundle != nil {
			t.Errorf("%s: refused with its key (%d bytes) or bundle (%d bytes) still in the packet", name, len(p.LeafKeyPEM), len(p.Bundle))
		}
	}
	// And a packet that opens keeps what it carries.
	var p Packet
	if err := decodePacket([]byte(plain(samplePacket())), &p); err != nil || len(p.Bundle) == 0 {
		t.Errorf("the sample packet: %v, bundle %d bytes", err, len(p.Bundle))
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

func TestValidateInstance(t *testing.T) {
	for _, ok := range []string{"a", "prod", "a-1", strings.Repeat("x", MaxInstanceLen)} {
		if err := ValidateInstance(ok); err != nil {
			t.Errorf("ValidateInstance(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "Prod", "1a", "a-", "a_b", "../x", "a/b", ".", strings.Repeat("x", MaxInstanceLen+1)} {
		err := ValidateInstance(bad)
		if err == nil {
			t.Errorf("ValidateInstance(%q) = nil, want a refusal", bad)
			continue
		}
		// The name may be hostile (a packet's), so the refusal never repeats it.
		if bad != "" && strings.Contains(err.Error(), bad) {
			t.Errorf("ValidateInstance(%q) repeats the name: %v", bad, err)
		}
	}
}

func TestInstallWritesRestrictedMaterial(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prod")
	_, _, p := enrolled(t, dir)
	store, err := Install(dir, p, true)
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
	raw := readFile(t, filepath.Join(dir, configFile))
	if !strings.Contains(string(raw), "instance: prod") {
		t.Errorf("the keeper record does not name its instance:\n%s", raw)
	}
	for _, secret := range []string{"PRIVATE KEY", "BEGIN CERTIFICATE"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the keeper record contains %q; an operator reading it should never have material on screen", secret)
		}
	}
}

// B-T5. Install writes the certificate and the bundle beside the key the
// device made, and moves that key into place: it is the same bytes, never a
// copy, and the request is gone.
func TestInstallWritesOnlyTheCertificateAndBundle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prod")
	_, gen, p := enrolled(t, dir)
	pendingKey := readFile(t, filepath.Join(dir, requestKeyFile))
	if !bytes.Equal(pendingKey, gen.KeyPEM) {
		t.Fatal("request.key does not hold the generated key")
	}
	store, err := Install(dir, p, true)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got := readFile(t, filepath.Join(dir, leafKey)); !bytes.Equal(got, pendingKey) {
		t.Error("leaf.key is not the key the request was made for")
	}
	absent(t, dir, requestKeyFile, requestRecordFile)
	if got := readFile(t, filepath.Join(dir, leafFile)); !bytes.Equal(got, p.LeafCertPEM) {
		t.Error("leaf.crt is not the packet's certificate")
	}
	if got := readFile(t, filepath.Join(dir, bundleFile)); !bytes.Equal(got, p.Bundle) {
		t.Error("bundle.yaml is not the packet's bundle")
	}
	cfg, err := store.Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KeySHA256 != gen.KeySHA256 || cfg.KeyStore != KeyStoreFile || cfg.Version != recordVersion {
		t.Errorf("record key = %q %q (version %d); want %q %q (version %d)", cfg.KeySHA256, cfg.KeyStore, cfg.Version, gen.KeySHA256, KeyStoreFile, recordVersion)
	}
	raw := readFile(t, filepath.Join(dir, configFile))
	for _, want := range []string{"key_sha256: " + gen.KeySHA256, "key_store: file"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("keeper.yaml lacks %q:\n%s", want, raw)
		}
	}
	for _, f := range []string{caFile, leafFile, leafKey, bundleFile, configFile} {
		if fi, err := os.Stat(filepath.Join(dir, f)); err != nil || fi.Mode().Perm() != fileMode {
			t.Errorf("%s: %v, %v; want mode %v", f, fi, err, os.FileMode(fileMode))
		}
	}
	// What the daemon reads is a pair.
	_, cert, key, _, err := store.Material()
	if err != nil {
		t.Fatal(err)
	}
	if fp, _ := identity.CertKeyFingerprint(cert); fp != gen.KeySHA256 || !bytes.Equal(key, pendingKey) {
		t.Error("the installed certificate and key are not the request's")
	}
}

// B-T6. A certificate for a key this device does not hold is a security
// event, and nothing on the device changes.
func TestInstallRefusesACertificateForAnotherKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prod")
	m := mintCA(t)
	mine := request(t, dir)
	beforeKey := readFile(t, filepath.Join(dir, requestKeyFile))
	beforeRecord := readFile(t, filepath.Join(dir, requestRecordFile))

	// Somebody else's key, certified under this device's name.
	theirs, err := GenerateRequest()
	if err != nil {
		t.Fatal(err)
	}
	p := packetFor(t, m, theirs.RequestDER)
	_, err = Install(dir, p, true)
	var fk *ForeignKeyError
	if !errors.As(err, &fk) {
		t.Fatalf("Install = %v; want a *ForeignKeyError", err)
	}
	if fk.CertKey != theirs.KeySHA256 || fk.Pending != mine.KeySHA256 || fk.Installed != "" {
		t.Errorf("ForeignKeyError = %+v", fk)
	}
	msg := err.Error()
	for _, want := range []string{
		"security event", identity.FormatFingerprint(theirs.KeySHA256), identity.FormatFingerprint(mine.KeySHA256),
		"'farcast keeper revoke prod study-desktop'", "'farcast storage key rotate prod'", "'farcast storage key rekey prod'",
		"Nothing was installed", "'farcast keeper request prod'",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal lacks %q:\n%s", want, msg)
		}
	}
	absent(t, dir, leafFile, bundleFile, configFile, caFile, leafKey)
	if !bytes.Equal(readFile(t, filepath.Join(dir, requestKeyFile)), beforeKey) ||
		!bytes.Equal(readFile(t, filepath.Join(dir, requestRecordFile)), beforeRecord) {
		t.Error("the refused install touched the pending request")
	}

	// A device that made no request at all: refused, and nothing created.
	empty := filepath.Join(t.TempDir(), "prod")
	_, err = Install(empty, p, true)
	if !errors.As(err, &fk) || fk.Pending != "" || fk.Installed != "" || !strings.Contains(err.Error(), "(its key for prod: none)") {
		t.Errorf("Install with no key here = %v; want a *ForeignKeyError naming none", err)
	}
	if _, err := os.Stat(empty); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused install created %s (%v)", empty, err)
	}
}

// B-T7. Install checks the certificate is a client leaf of the packet's CA,
// at the later of now and its NotBefore: a device clock that lags the
// operator's does not block an install, and an expired leaf does.
func TestInstallRefusesACertificateFromAnotherCA(t *testing.T) {
	t.Run("another CA than the packet's", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "prod")
		m, gen, _ := enrolled(t, dir)
		other := mintCA(t)
		p := packetFor(t, other, gen.RequestDER)
		p.CACertPEM = m.CACertPEM
		_, err := Install(dir, p, true)
		if err == nil || !strings.Contains(err.Error(), "does not chain to its CA") {
			t.Errorf("Install = %v; want a chain refusal", err)
		}
		absent(t, dir, leafFile, bundleFile, configFile, leafKey)
	})

	dir := filepath.Join(t.TempDir(), "prod")
	gen := request(t, dir)
	ca := newTestCA(t)
	for _, c := range []struct {
		name      string
		eku       []x509.ExtKeyUsage
		notBefore time.Time
		notAfter  time.Time
		installs  bool
	}{
		{"a server leaf", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Now().Add(-time.Minute), time.Now().Add(time.Hour), false},
		{"an expired leaf", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, time.Now().Add(-2 * time.Hour), time.Now().Add(-time.Hour), false},
		{"a leaf from the device's future", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, time.Now().Add(time.Hour), time.Now().Add(48 * time.Hour), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := samplePacket()
			p.CACertPEM, p.LeafCertPEM = ca.certPEM, ca.issue(t, gen.RequestDER, c.eku, c.notBefore, c.notAfter)
			_, err := Install(dir, p, true)
			if c.installs {
				if err != nil {
					t.Errorf("Install = %v; want it installed", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "does not chain") {
				t.Errorf("Install = %v; want a chain refusal", err)
			}
			absent(t, dir, leafFile, configFile)
		})
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

// Wiping deletes the two files that could open anything — the bundle and the
// leaf key — and keeps the ledger an audit reads afterwards, and the record
// 'keeper status' needs to read it. The old Remove deleted the record too,
// which made the kept ledger unreadable.
func TestWipeKeepsTheLedgerAndTheRecord(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prod")
	_, _, p := enrolled(t, dir)
	store, err := Install(dir, p, true)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := keyholder.AppendLedger(store.LedgerPath(), keyholder.LedgerEntry{
		Time: time.Now().UTC(), Instance: "prod", Intent: IntentReseed, Result: "ok", Boot: "abcd",
	}); err != nil {
		t.Fatalf("AppendLedger: %v", err)
	}
	first := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	if err := store.Wipe("instance released", first); err != nil {
		t.Fatalf("Wipe: %v", err)
	}
	absent(t, dir, bundleFile, leafKey)
	for _, f := range []string{configFile, caFile, leafFile} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s did not survive Wipe: %v", f, err)
		}
	}
	entries, err := keyholder.ReadLedger(store.LedgerPath())
	if err != nil || len(entries) != 1 {
		t.Errorf("the ledger did not survive Wipe: %d entries, %v", len(entries), err)
	}
	cfg, err := store.Config()
	if err != nil || !cfg.WipedAt.Equal(first) || cfg.WipedReason != "instance released" {
		t.Errorf("the record does not say it was wiped: %+v, %v", cfg, err)
	}
	if _, _, _, _, err := store.Material(); !errors.Is(err, ErrWiped) {
		t.Errorf("Material after Wipe = %v; want ErrWiped", err)
	}
	// Idempotent, and the first date and reason stand.
	if err := store.Wipe("again", first.Add(time.Hour)); err != nil {
		t.Fatalf("second Wipe: %v", err)
	}
	if cfg, _ := store.Config(); !cfg.WipedAt.Equal(first) || cfg.WipedReason != "instance released" {
		t.Errorf("a second Wipe rewrote the first: %+v", cfg)
	}
}

// B-T8. A renewal request pending beside an installed key is a key too, and a
// wipe takes it with the rest.
func TestWipeRemovesThePendingRequestToo(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prod")
	_, _, p := enrolled(t, dir)
	store, err := Install(dir, p, true)
	if err != nil {
		t.Fatal(err)
	}
	request(t, dir) // a renewal
	if err := store.Wipe("uninstalled", time.Now()); err != nil {
		t.Fatal(err)
	}
	absent(t, dir, leafKey, bundleFile, requestKeyFile, requestRecordFile)
	if r, err := PendingRequest(dir); r != nil || err != nil {
		t.Errorf("PendingRequest after Wipe = %+v, %v", r, err)
	}
}

// B-T8. Re-installing the packet for the key already installed rewrites what
// it wrote and nothing else: a crash part way is mended by running it again.
func TestReinstallOfTheSamePacketIsIdempotent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prod")
	_, gen, p := enrolled(t, dir)
	if _, err := Install(dir, p, true); err != nil {
		t.Fatal(err)
	}
	key := readFile(t, filepath.Join(dir, leafKey))
	store, err := Install(dir, p, true)
	if err != nil {
		t.Fatalf("re-install: %v", err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(dir, leafKey)), key) {
		t.Error("a re-install changed the key")
	}
	cfg, err := store.Config()
	if err != nil || cfg.KeySHA256 != gen.KeySHA256 || cfg.KeyStore != KeyStoreFile {
		t.Errorf("record after re-install = %+v, %v", cfg, err)
	}
	absent(t, dir, requestKeyFile, requestRecordFile)

	// An install that stopped after moving the key leaves the request's
	// record behind; running it again finishes the job.
	if err := os.WriteFile(filepath.Join(dir, requestRecordFile), []byte("version: 1\ninstance: prod\nkey_sha256: "+gen.KeySHA256+"\nkey_store: file\n"), fileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(dir, p, true); err != nil {
		t.Fatal(err)
	}
	absent(t, dir, requestRecordFile)
}

// B-T8. Review finding R1-5: with K1 installed and a renewal request for K2
// pending, re-installing K1's packet leaves the request byte for byte, and
// K2's packet then installs.
func TestReinstallLeavesAPendingRenewalAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prod")
	m, _, p1 := enrolled(t, dir)
	if _, err := Install(dir, p1, true); err != nil {
		t.Fatal(err)
	}
	k2 := request(t, dir)
	key2 := readFile(t, filepath.Join(dir, requestKeyFile))
	rec2 := readFile(t, filepath.Join(dir, requestRecordFile))
	if _, err := Install(dir, p1, true); err != nil {
		t.Fatalf("re-installing K1's packet: %v", err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(dir, requestKeyFile)), key2) ||
		!bytes.Equal(readFile(t, filepath.Join(dir, requestRecordFile)), rec2) {
		t.Fatal("re-installing the installed key's packet touched the pending renewal")
	}
	store, err := Install(dir, packetFor(t, m, k2.RequestDER), true)
	if err != nil {
		t.Fatalf("installing K2's packet: %v", err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(dir, leafKey)), key2) {
		t.Error("leaf.key is not K2 after its packet installed")
	}
	if cfg, err := store.Config(); err != nil || cfg.KeySHA256 != k2.KeySHA256 {
		t.Errorf("record after K2 = %+v, %v", cfg, err)
	}
	absent(t, dir, requestKeyFile, requestRecordFile)
	// And K1's packet is now another key's.
	var fk *ForeignKeyError
	if _, err := Install(dir, p1, true); !errors.As(err, &fk) {
		t.Errorf("K1's packet after K2 installed = %v; want a *ForeignKeyError", err)
	}
}

// Enrolling again over a wiped directory makes it a keeper again — from a new
// request, since the wipe took the key.
func TestReinstallClearsAWipe(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prod")
	m, _, p := enrolled(t, dir)
	store, err := Install(dir, p, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Wipe("uninstalled", time.Now()); err != nil {
		t.Fatal(err)
	}
	// The old packet's key went with the wipe.
	var fk *ForeignKeyError
	if _, err := Install(dir, p, true); !errors.As(err, &fk) {
		t.Fatalf("the wiped key's packet = %v; want a *ForeignKeyError", err)
	}
	gen := request(t, dir)
	if store, err = Install(dir, packetFor(t, m, gen.RequestDER), true); err != nil {
		t.Fatalf("reinstall: %v", err)
	}
	if _, _, _, _, err := store.Material(); err != nil {
		t.Errorf("a reinstalled keeper's material = %v", err)
	}
}

// A platform that cannot guarantee the exclusion cannot be a keeper — unless
// the operator says otherwise, and then the record says they did.
//
// On macOS the real exclusion always succeeds, so the refusal path is reached
// through the seam. Without this the rule would be untested on the one platform
// this is developed against.
func TestInstallRefusesWithoutAVerifiableBackupExclusion(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prod")
	_, _, p := enrolled(t, dir)

	original := excludeFromBackup
	excludeFromBackup = func(string) error { return errors.New("no exclusion here") }
	defer func() { excludeFromBackup = original }()

	_, err := Install(dir, p, false)
	if err == nil {
		t.Fatal("Install proceeded without a verifiable backup exclusion")
	}
	for _, want := range []string{"no exclusion here", "cannot be a keeper", "--accept-backup-risk"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal omits %q: %v", want, err)
		}
	}
	// The refusal names its package once, in front; the reason underneath
	// carries no prefix of its own, so the record below reads as a reason.
	if !strings.HasPrefix(err.Error(), "keeper: no exclusion here\n") {
		t.Errorf("the refusal does not open with the prefixed reason: %q", err)
	}
	absent(t, dir, bundleFile, leafKey, configFile)

	// Forced, it proceeds — and writes down that it could not verify, so an
	// operator reading the record later sees what the device actually managed.
	store, err := Install(dir, p, true)
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
	if cfg.BackupNote != "no exclusion here" {
		t.Errorf("BackupNote = %q, want exactly the reason it failed", cfg.BackupNote)
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
	_, _, p := enrolled(t, dir)
	if _, err := Install(dir, p, true); err != nil {
		t.Fatalf("Install: %v", err)
	}
	for _, f := range []string{caFile, leafFile, leafKey, bundleFile, configFile} {
		if err := os.Chmod(filepath.Join(dir, f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Install(dir, p, true); err != nil {
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

// A directory holding only a request says so when a keeper is looked for.
func TestOpenStoreNamesAPendingRequest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "prod")
	if _, err := OpenStore(dir); err == nil || strings.Contains(err.Error(), "pending") {
		t.Errorf("OpenStore of nothing = %v", err)
	}
	request(t, dir)
	_, err := OpenStore(dir)
	if err == nil || !strings.Contains(err.Error(), "is pending here") || !strings.Contains(err.Error(), "install the packet it returns") {
		t.Errorf("OpenStore beside a pending request = %v; want it named", err)
	}
	if err := DiscardRequest(dir); err != nil {
		t.Fatal(err)
	}
	absent(t, dir, requestKeyFile, requestRecordFile)
	if err := DiscardRequest(dir); err != nil {
		t.Errorf("a second DiscardRequest: %v", err)
	}
}
