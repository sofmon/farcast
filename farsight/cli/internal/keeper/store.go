package keeper

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/sofmon/farcast/fatline/identity"
)

// File names inside a keeper's directory. The material files are separate from
// the record so that a human reading the record never has key material on
// screen, and so the two can carry different modes.
const (
	configFile = "keeper.yaml"
	caFile     = "ca.crt"
	leafFile   = "leaf.crt"
	leafKey    = "leaf.key"
	bundleFile = "bundle.yaml"
	ledgerFile = "ledger.jsonl"
	// passLockFile is held, by flock, for the length of one pass. It holds
	// nothing.
	passLockFile = "pass.lock"

	// dirMode and fileMode are the only modes anything here rests under.
	dirMode  = 0o700
	fileMode = 0o600
)

// Config is a keeper's record of what it is enrolled for. It holds no key
// material: everything here is a name, an address or a number.
type Config struct {
	Version     int           `yaml:"version"`
	Instance    string        `yaml:"instance"`
	Device      string        `yaml:"device"`
	Carrier     string        `yaml:"carrier"`
	ServerName  string        `yaml:"server_name"`
	Generation  uint64        `yaml:"generation"`
	Budget      int           `yaml:"budget"`
	Window      time.Duration `yaml:"window"`
	InstalledAt time.Time     `yaml:"installed_at"`

	// BackupExcluded records whether this build could exclude the directory
	// from the platform's backup pipeline, and is written from what the check
	// actually returned rather than from what was intended.
	BackupExcluded bool   `yaml:"backup_excluded"`
	BackupNote     string `yaml:"backup_note,omitempty"`

	// KeySHA256 is the fingerprint (identity.KeyFingerprint) of the key this
	// device made and its certificate certifies, and KeyStore where that key
	// was born (KeyStoreFile). Empty on a record from before ADR 0020.
	KeySHA256 string `yaml:"key_sha256,omitempty"`
	KeyStore  string `yaml:"key_store,omitempty"`

	// WipedAt is when this device's key material was wiped, and WipedReason
	// why. The record and the ledger stay: the ledger is the evidence an
	// audit reads, and 'keeper status' needs the record to read it.
	WipedAt     time.Time `yaml:"wiped_at,omitzero"`
	WipedReason string    `yaml:"wiped_reason,omitempty"`
}

// ErrPassRunning is another keeper process on this device mid-pass.
var ErrPassRunning = errors.New("another keeper pass on this device is running")

// ErrWiped is a keeper whose material was wiped: it holds a record and a
// ledger, and nothing it could push.
var ErrWiped = errors.New("keeper: this device's material was wiped")

// Store is one enrolled keeper's on-device state.
type Store struct{ dir string }

// Dir returns the directory this store lives in.
func (s *Store) Dir() string { return s.dir }

// LedgerPath is where this keeper records what it has pushed.
func (s *Store) LedgerPath() string { return filepath.Join(s.dir, ledgerFile) }

// Install writes a packet's certificate and bundle into dir, beside the key
// this device made for it, ready for the daemon.
//
// The packet carries no key (ADR 0020 decision 3): the device made its own
// with 'keeper request', and the certificate must certify that key, pending or
// already installed. A certificate for any other key is a security event — the
// request was replaced on its way to the operator, or the packet is another
// device's — and Install refuses it with a *ForeignKeyError, having written,
// created and removed nothing.
//
// The material comes to rest UNARMORED, and that is the honest consequence of
// what a keeper is for: a device that re-seeds at 03:00 without waking anyone
// cannot be holding a passphrase behind a human. What protects it is the
// platform — 0600 under a 0700 directory, excluded from the backup pipeline —
// and the tiering that put only a derived bundle here in the first place.
//
// Install refuses rather than proceeding when the platform cannot make the
// backup guarantee, because ADR 0008 says a platform that cannot guarantee the
// exclusion cannot be a keeper. `force` records the operator overriding that,
// which is theirs to do and is written into the record either way.
//
// Re-installing the packet for the key already installed is idempotent, so a
// crash part way is mended by running it again, and it never touches a
// request pending beside that key: a renewal's packet must still install.
func Install(dir string, p *Packet, force bool) (*Store, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if err := refuseSyncedPath(dir); err != nil {
		// Not overridable. A synced directory is a live upload of the bundle
		// to somebody's cloud, which is the exact outcome this whole design
		// exists to prevent — and unlike a backup pipeline it is continuous.
		return nil, err
	}
	if err := verifyLeaf(p, time.Now()); err != nil {
		return nil, err
	}
	certKey, err := identity.CertKeyFingerprint(p.LeafCertPEM)
	if err != nil {
		return nil, fmt.Errorf("keeper: the packet's certificate: %w", err)
	}

	// What this device holds for the instance: a pending request's key, when
	// the record beside it names this instance, and an installed one.
	var pendingKey string
	pending, err := PendingRequest(dir)
	if err != nil {
		return nil, err
	}
	if pending != nil && pending.Instance == p.Instance {
		if pendingKey, err = heldKeyFingerprint(dir, requestKeyFile); err != nil {
			return nil, err
		}
	}
	installedKey, err := heldKeyFingerprint(dir, leafKey)
	if err != nil {
		return nil, err
	}
	matchedPending := pendingKey != "" && pendingKey == certKey
	matchedInstalled := !matchedPending && installedKey != "" && installedKey == certKey
	if !matchedPending && !matchedInstalled {
		return nil, &ForeignKeyError{
			Instance: p.Instance, Device: p.Device,
			CertKey: certKey, Pending: pendingKey, Installed: installedKey,
		}
	}

	excluded, note, err := Prepare(dir, force)
	if err != nil {
		return nil, err
	}
	for _, f := range []struct {
		name string
		data []byte
	}{
		{caFile, p.CACertPEM},
		{leafFile, p.LeafCertPEM},
		{bundleFile, p.Bundle},
	} {
		if err := writeSecret(filepath.Join(dir, f.name), f.data); err != nil {
			return nil, err
		}
	}

	keyStore := KeyStoreFile
	if matchedPending {
		if pending.KeyStore != "" {
			keyStore = pending.KeyStore
		}
		// The key moves; it is never copied. A rename within the directory
		// is atomic, so a crash leaves it under one name or the other, and
		// running install again finds it either way.
		if err := os.Rename(filepath.Join(dir, requestKeyFile), filepath.Join(dir, leafKey)); err != nil {
			return nil, fmt.Errorf("keeper: moving the request's key into place: %w", err)
		}
	} else {
		switch {
		case pending != nil && pending.KeySHA256 == certKey && pending.KeyStore != "":
			keyStore = pending.KeyStore
		default:
			if prev, perr := (&Store{dir: dir}).Config(); perr == nil && prev.KeyStore != "" {
				keyStore = prev.KeyStore
			}
		}
	}
	// A rename keeps the request key's mode and a re-install rewrites nothing
	// of the key, so its mode is set here either way: os.WriteFile honours a
	// mode only when it creates a file, and a key that came back from a
	// re-enrolment world-readable is a regression nobody watched happen.
	if err := os.Chmod(filepath.Join(dir, leafKey), fileMode); err != nil {
		return nil, fmt.Errorf("keeper: securing %s: %w", leafKey, err)
	}

	cfg := Config{
		Version: recordVersion, Instance: p.Instance, Device: p.Device,
		Carrier: p.Carrier, ServerName: p.ServerName, Generation: p.Generation,
		Budget: p.Budget, Window: p.Window, InstalledAt: time.Now().UTC(),
		BackupExcluded: excluded, BackupNote: note,
		KeySHA256: certKey, KeyStore: keyStore,
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("keeper: encode the keeper record: %w", err)
	}
	if err := writeSecret(filepath.Join(dir, configFile), out); err != nil {
		return nil, err
	}

	switch {
	case matchedPending:
		if err := os.Remove(filepath.Join(dir, requestRecordFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("keeper: removing the request record: %w", err)
		}
	case pending != nil && pending.KeySHA256 == certKey && pendingKey == "":
		// The record of the request this key came from, left by an install
		// that stopped after moving the key: its key is the installed one, so
		// nothing is pending. A record naming any other key is a renewal and
		// stays.
		if err := os.Remove(filepath.Join(dir, requestRecordFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("keeper: removing the request record: %w", err)
		}
	}
	return &Store{dir: dir}, nil
}

// verifyLeaf checks the packet's certificate chains to the packet's CA as a
// client leaf. It proves the CA's signature and the EKU without depending on
// this device's clock agreeing with the operator's: a leaf starts a minute
// before it was issued, and a board with no real-time clock can lag until it
// syncs, so the check runs at the later of now and the leaf's NotBefore. An
// expired leaf is still refused.
func verifyLeaf(p *Packet, now time.Time) error {
	block, _ := pem.Decode(p.LeafCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("keeper: the packet's certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("keeper: the packet's certificate does not parse")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(p.CACertPEM) {
		return errors.New("keeper: the packet's CA certificate does not parse")
	}
	at := now
	if leaf.NotBefore.After(at) {
		at = leaf.NotBefore
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: at,
	}); err != nil {
		return fmt.Errorf("keeper: the packet's certificate does not chain to its CA: %w", err)
	}
	return nil
}

// OpenStore loads an installed keeper.
func OpenStore(dir string) (*Store, error) {
	s := &Store{dir: dir}
	if _, err := os.Stat(filepath.Join(dir, configFile)); err != nil {
		if os.IsNotExist(err) {
			if r, rerr := PendingRequest(dir); rerr == nil && r != nil {
				return nil, fmt.Errorf("keeper: nothing is enrolled at %s; a request made %s is pending here: "+
					"carry it to the operator's machine and install the packet it returns",
					dir, r.CreatedAt.UTC().Format("2006-01-02"))
			}
			return nil, fmt.Errorf("keeper: nothing is enrolled at %s", dir)
		}
		return nil, err
	}
	return s, nil
}

// Config reads the keeper's record.
func (s *Store) Config() (Config, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, configFile))
	if err != nil {
		return Config{}, fmt.Errorf("keeper: reading the keeper record: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("keeper: the keeper record did not decode: %w", err)
	}
	return cfg, nil
}

// Material returns the key and identity material this keeper holds.
//
// The caller is expected to clear what it is handed. Nothing here is cached in
// the Store: a daemon that kept the bundle resident between wake-ups would hold
// key material in memory for the entire uptime of the device, to save a read of
// a local file once a month.
func (s *Store) Material() (caCertPEM, leafCertPEM, leafKeyPEM, bundle []byte, err error) {
	if cfg, cerr := s.Config(); cerr == nil && !cfg.WipedAt.IsZero() {
		return nil, nil, nil, nil, fmt.Errorf("%w on %s (%s)", ErrWiped, cfg.WipedAt.Format("2006-01-02"), cfg.WipedReason)
	}
	read := func(name string) []byte {
		if err != nil {
			return nil
		}
		var data []byte
		data, err = os.ReadFile(filepath.Join(s.dir, name))
		if err != nil {
			err = fmt.Errorf("keeper: reading %s: %w", name, err)
		}
		return data
	}
	caCertPEM = read(caFile)
	leafCertPEM = read(leafFile)
	leafKeyPEM = read(leafKey)
	bundle = read(bundleFile)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return caCertPEM, leafCertPEM, leafKeyPEM, bundle, nil
}

// CACert is the instance CA this keeper was enrolled under. It is public, and
// it is what proves a keeper directory belongs to a given instance — names
// are local labels, and another machine's instance may share one.
func (s *Store) CACert() ([]byte, error) {
	return os.ReadFile(filepath.Join(s.dir, caFile))
}

// Wipe deletes the files on this device that could open anything: the
// bundle and the leaf's private key — and a pending request's key and record,
// which would otherwise outlive the keeper they were made to renew.
//
// The ledger is deliberately KEPT, and so is the record 'keeper status' needs
// to read it (ADR 0008: a device that erased its own history on the way out
// would remove exactly the evidence an audit needs afterwards). The
// certificates stay too: they are public, and the leaf names the identity
// every ledger entry was made under. The record is marked first, so a crash
// part way leaves a keeper that refuses to run rather than one that has lost
// its explanation. Idempotent: the first reason and date stand.
func (s *Store) Wipe(reason string, at time.Time) error {
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	if cfg.WipedAt.IsZero() {
		cfg.WipedAt, cfg.WipedReason = at.UTC(), reason
		out, err := yaml.Marshal(cfg)
		if err != nil {
			return fmt.Errorf("keeper: encode the keeper record: %w", err)
		}
		if err := writeSecret(filepath.Join(s.dir, configFile), out); err != nil {
			return err
		}
	}
	for _, f := range []string{leafKey, bundleFile, requestKeyFile, requestRecordFile} {
		if err := os.Remove(filepath.Join(s.dir, f)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("keeper: removing %s: %w", f, err)
		}
	}
	return nil
}

// excludeFromBackup is ExcludeFromBackup behind a seam.
//
// The refusal it drives — a platform that cannot guarantee the exclusion
// cannot be a keeper — is one of the load-bearing rules here, and on the
// platform this is developed against the real function always succeeds. A
// guard whose failure path nothing can reach is a guard nobody has checked.
var excludeFromBackup = ExcludeFromBackup

// writeSecret writes material at 0600, replacing whatever was there.
func writeSecret(path string, data []byte) error {
	if err := os.WriteFile(path, data, fileMode); err != nil {
		return fmt.Errorf("keeper: writing %s: %w", filepath.Base(path), err)
	}
	// WriteFile honours the mode only when it CREATES the file; an existing
	// one keeps whatever mode it had, which on a re-enrolment could be
	// anything.
	if err := os.Chmod(path, fileMode); err != nil {
		return fmt.Errorf("keeper: securing %s: %w", filepath.Base(path), err)
	}
	return nil
}

// syncedRoots are directory names that mean "this path is continuously
// uploaded somewhere".
//
// The list is not exhaustive and cannot be — it is a guard against the
// plausible mistake of installing a keeper into a synced folder, not a
// detector of every sync agent. What makes it worth having anyway is that the
// failure it catches is silent and total: a bundle in a synced directory is
// already in somebody's cloud by the time anyone looks.
var syncedRoots = []string{
	"Library/Mobile Documents", // iCloud Drive
	"iCloud Drive",
	"Dropbox",
	"Google Drive",
	"GoogleDrive",
	"OneDrive",
	"Nextcloud",
	"ownCloud",
	"Sync.com",
	"pCloud Drive",
	"Box Sync",
	"Creative Cloud Files",
	"Mega",
	"Yandex.Disk",
	"Seafile",
	"Syncthing",
}

// refuseSyncedPath rejects a directory that sits under a known sync root.
func refuseSyncedPath(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("keeper: resolving %s: %w", dir, err)
	}
	slashed := filepath.ToSlash(abs)
	for _, root := range syncedRoots {
		needle := "/" + filepath.ToSlash(root)
		if strings.Contains(slashed, needle+"/") || strings.HasSuffix(slashed, needle) {
			return fmt.Errorf(
				"keeper: refusing to install into %s, which is inside %q — a synced folder uploads this "+
					"device's bundle and key continuously, to the kind of cloud this design exists to keep it off",
				abs, root)
		}
	}
	return nil
}
