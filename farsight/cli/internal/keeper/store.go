package keeper

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
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
}

// Store is one enrolled keeper's on-device state.
type Store struct{ dir string }

// Dir returns the directory this store lives in.
func (s *Store) Dir() string { return s.dir }

// LedgerPath is where this keeper records what it has pushed.
func (s *Store) LedgerPath() string { return filepath.Join(s.dir, ledgerFile) }

// Install writes a packet's material into dir, ready for the daemon.
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
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("keeper: preparing %s: %w", dir, err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return nil, fmt.Errorf("keeper: securing %s: %w", dir, err)
	}

	excluded, note := true, ""
	if err := excludeFromBackup(dir); err != nil {
		excluded, note = false, err.Error()
		if !force {
			return nil, fmt.Errorf(
				"%w\n\nThe bundle, this device's private key and the ledger would rest somewhere the platform "+
					"may copy off the device. ADR 0008 says a platform that cannot guarantee the exclusion cannot "+
					"be a keeper.\n\nIf you have arranged the exclusion yourself, re-run with --accept-backup-risk "+
					"and the record will say that you did.", err)
		}
	}

	for _, f := range []struct {
		name string
		data []byte
	}{
		{caFile, p.CACertPEM},
		{leafFile, p.LeafCertPEM},
		{leafKey, p.LeafKeyPEM},
		{bundleFile, p.Bundle},
	} {
		if err := writeSecret(filepath.Join(dir, f.name), f.data); err != nil {
			return nil, err
		}
	}

	cfg := Config{
		Version: packetVersion, Instance: p.Instance, Device: p.Device,
		Carrier: p.Carrier, ServerName: p.ServerName, Generation: p.Generation,
		Budget: p.Budget, Window: p.Window, InstalledAt: time.Now().UTC(),
		BackupExcluded: excluded, BackupNote: note,
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("keeper: encode the keeper record: %w", err)
	}
	if err := writeSecret(filepath.Join(dir, configFile), out); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// OpenStore loads an installed keeper.
func OpenStore(dir string) (*Store, error) {
	s := &Store{dir: dir}
	if _, err := os.Stat(filepath.Join(dir, configFile)); err != nil {
		if os.IsNotExist(err) {
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

// Remove deletes this keeper's material from the device.
//
// The ledger is deliberately KEPT: it is the record of what this device did
// with key material, and a device that erased its own history on the way out
// would remove exactly the evidence an audit needs afterwards.
func (s *Store) Remove() error {
	for _, f := range []string{caFile, leafFile, leafKey, bundleFile, configFile} {
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
					"device's bundle continuously, to the kind of cloud this design exists to keep it off",
				abs, root)
		}
	}
	return nil
}
