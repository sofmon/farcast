package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/goccy/go-yaml"
)

const (
	instancesSubdir = "instances"
	metadataFile    = "metadata.yaml"
	credentialsFile = "credentials.yaml"
	kubeconfigFile  = "kubeconfig.yaml"
	fatlineSubdir   = "fatline"
	// datasphereSubdir holds the instance's storage keyring. It sits beside
	// the FatLine material because the two are the instance's crown jewels and
	// the operator's backup gesture — copy the instance directory offline —
	// has to cover both in one motion.
	datasphereSubdir = "datasphere"
	keyringFile      = "keys.yaml"
)

// Data-plane mTLS material file names (under <instance>/fatline/). The CA
// private key (ca.key) is the crown jewel: it stays here and is never shipped
// to the cluster.
const (
	caCertFile     = "ca.crt"
	caKeyFile      = "ca.key"
	clientCertFile = "client.crt"
	clientKeyFile  = "client.key"
	serverCertFile = "server.crt"
	serverKeyFile  = "server.key"
)

// Instance lifecycle states recorded in metadata.yaml.
const (
	InstanceProvisioning = "provisioning"
	InstanceRunning      = "running"
	InstanceUnreachable  = "unreachable"
	InstanceDeleting     = "deleting"
	InstanceError        = "error"
)

// CostLimit is the mandatory spend ceiling captured at install. For phase 1.3
// it is a monthly USD amount; enforcement is TechnoCore's job (4.1).
type CostLimit struct {
	Amount   float64 `yaml:"amount"`
	Currency string  `yaml:"currency"`
	Period   string  `yaml:"period"`
}

// Carrier records how the operator's tunnel reaches FatLine's data plane,
// bound by `farcast connect` (2.3, ADR 0005). Type is e.g. "nlb".
type Carrier struct {
	Type       string `yaml:"type"`
	Endpoint   string `yaml:"endpoint"`    // host:port the tunnel client dials
	ServerName string `yaml:"server_name"` // pinned TLS server identity (SAN)
}

// Registry records the instance-owned container image registry (ADR 0007) and
// what was last deployed out of it. The instance owning its registry is what
// keeps a third party out of the runtime path: every image the cluster runs was
// built on the operator's machine, from Git, and pushed here.
//
// Nothing secret lives in this record — the push credential is minted in-process
// per command and never stored (that is the whole point of ADR 0007 decision 5).
// Prefix is what every image reference is derived from; Puller is kept so the
// grant that lets the cluster pull is auditable from local state alone, without
// opening a cloud console.
type Registry struct {
	Prefix     string `yaml:"prefix,omitempty"`     // image-path prefix, e.g. us-central1-docker.pkg.dev/proj/farcast-prod
	Repository string `yaml:"repository,omitempty"` // the cloud repository's own name, e.g. farcast-prod
	Location   string `yaml:"location,omitempty"`   // region the repository lives in
	Puller     string `yaml:"puller,omitempty"`     // principal granted pull access on it

	// FatLineDigest is the digest-pinned reference (host/repo@sha256:…) the
	// cluster was last told to run. Deploys pin digests rather than tags, so
	// this records exactly what is running — a tag could be rewritten under it.
	FatLineDigest string `yaml:"fatline_digest,omitempty"`
}

// Storage records the instance's DataSphere bucket (phase 3.3).
//
// It is a pointer so metadata written before instances had storage still
// loads; such an instance converges the next time a storage command runs,
// which mints a name, records it here, and only then creates the bucket.
//
// Bucket carries 32 bits of randomness that exist NOWHERE else once minted,
// and the name is deliberately not derivable from the instance name — its
// instance segment may have been truncated to fit the cloud's length cap. That
// is why this record is written BEFORE the call that creates the bucket: a
// record with no bucket behind it is converged by the next ensure, while a
// bucket with no record is billable storage nobody is watching, under a name
// nobody can reconstruct.
//
// Nothing secret lives here. The keyring is a separate 0600 file in the
// instance directory, and it is the file whose loss is the permanent loss of
// everything the bucket holds.
type Storage struct {
	Bucket   string `yaml:"bucket"`
	Location string `yaml:"location,omitempty"`

	// Provider is the STORAGE provider ("gcs"), a different registry from
	// InstanceMetadata.Provider, the compute provider ("gke"). It is recorded
	// rather than re-derived so a later change to the compute-to-storage
	// default table cannot silently repoint an existing instance at a
	// different cloud's storage.
	Provider string `yaml:"provider,omitempty"`

	// RecordedAt is when the name was minted and written — before any create
	// call. CreatedAt is when the bucket was first confirmed to exist.
	//
	// The two differ exactly in the window the ordering exists to survive, and
	// the distinction is load-bearing beyond bookkeeping: while CreatedAt is
	// empty the recorded name is only an intent, so a name conflict may safely
	// be resolved by minting another. Once CreatedAt is set the name has held
	// real data, and minting past a conflict would abandon it.
	RecordedAt time.Time `yaml:"recorded_at,omitempty"`
	CreatedAt  time.Time `yaml:"created_at,omitempty"`
}

// InstanceMetadata is the non-secret record for an installed instance.
type InstanceMetadata struct {
	Name      string    `yaml:"name"`
	Provider  string    `yaml:"provider"`
	Project   string    `yaml:"project,omitempty"`
	Region    string    `yaml:"region"`
	Cluster   string    `yaml:"cluster"`
	Endpoint  string    `yaml:"endpoint,omitempty"`
	Status    string    `yaml:"status"`
	CostLimit CostLimit `yaml:"cost_limit"`
	Version   string    `yaml:"farcast_version,omitempty"`
	CreatedAt time.Time `yaml:"created_at"`
	UpdatedAt time.Time `yaml:"updated_at"`

	// FatLineDeployed records that connect has applied FatLine into the cluster
	// (and, with Carrier set, provisioned its billable point of presence).
	FatLineDeployed bool     `yaml:"fatline_deployed,omitempty"`
	Carrier         *Carrier `yaml:"carrier,omitempty"`

	// Registry is the instance's own image registry (ADR 0007). It is a pointer
	// so metadata written before instances had one still loads — such an
	// instance converges on its next `farcast connect`, which re-ensures the
	// registry and fills this in.
	Registry *Registry `yaml:"registry,omitempty"`

	// Storage is the instance's DataSphere bucket (3.3), pointer-typed for the
	// same reason Registry is.
	Storage *Storage `yaml:"storage,omitempty"`
}

// MTLSMaterial is a per-instance data-plane mTLS identity, PEM-encoded. It is a
// plain byte holder so the config store stays independent of FatLine's crypto.
type MTLSMaterial struct {
	CACertPEM     []byte
	CAKeyPEM      []byte
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	ServerCertPEM []byte
	ServerKeyPEM  []byte
}

// InstanceCredentials is the secret credential material for an instance. An
// empty ServiceAccountKey means ambient / Application Default Credentials.
type InstanceCredentials struct {
	Provider          string `yaml:"provider"`
	ServiceAccountKey string `yaml:"service_account_key,omitempty"`
}

func (d Dir) instancesDir() string        { return filepath.Join(string(d), instancesSubdir) }
func (d Dir) instanceDir(n string) string { return filepath.Join(d.instancesDir(), n) }

// InstancePath returns an instance's on-disk directory (for display).
func (d Dir) InstancePath(name string) string { return d.instanceDir(name) }

// InstanceExists reports whether an instance directory already exists.
func (d Dir) InstanceExists(name string) (bool, error) {
	_, err := os.Stat(d.instanceDir(name))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// CreateInstance reserves a fresh instance directory (0700). It fails if one
// already exists, so install never clobbers an existing instance.
func (d Dir) CreateInstance(name string) error {
	if err := d.Ensure(); err != nil {
		return err
	}
	if err := os.MkdirAll(d.instancesDir(), 0o700); err != nil {
		return fmt.Errorf("create instances directory: %w", err)
	}
	if err := os.Mkdir(d.instanceDir(name), 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("instance %q already exists at %s", name, d.instanceDir(name))
		}
		return fmt.Errorf("create instance directory: %w", err)
	}
	return nil
}

// RemoveInstance deletes an instance directory and all of its state.
func (d Dir) RemoveInstance(name string) error {
	return os.RemoveAll(d.instanceDir(name))
}

// ListInstances returns the names of installed instances, sorted.
func (d Dir) ListInstances() ([]string, error) {
	entries, err := os.ReadDir(d.instancesDir())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// SaveInstanceMetadata writes metadata.yaml (0600) for an instance.
func (d Dir) SaveInstanceMetadata(name string, m *InstanceMetadata) error {
	data, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode instance metadata: %w", err)
	}
	return d.writeInstanceFile(name, metadataFile, data)
}

// LoadInstanceMetadata reads metadata.yaml for an instance.
func (d Dir) LoadInstanceMetadata(name string) (*InstanceMetadata, error) {
	path := filepath.Join(d.instanceDir(name), metadataFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m InstanceMetadata
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &m, nil
}

// SaveInstanceCredentials writes credentials.yaml (0600) for an instance.
func (d Dir) SaveInstanceCredentials(name string, c *InstanceCredentials) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("encode instance credentials: %w", err)
	}
	return d.writeInstanceFile(name, credentialsFile, data)
}

// LoadInstanceCredentials reads credentials.yaml for an instance.
func (d Dir) LoadInstanceCredentials(name string) (*InstanceCredentials, error) {
	path := filepath.Join(d.instanceDir(name), credentialsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c InstanceCredentials
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// SaveInstanceKubeconfig writes kubeconfig.yaml (0600) for an instance.
func (d Dir) SaveInstanceKubeconfig(name string, kubeconfig []byte) error {
	return d.writeInstanceFile(name, kubeconfigFile, kubeconfig)
}

// InstanceKubeconfigPath returns the path to an instance's kubeconfig (so the
// connect bootstrap can hand it to kubectl).
func (d Dir) InstanceKubeconfigPath(name string) string {
	return filepath.Join(d.instanceDir(name), kubeconfigFile)
}

// datasphereDir is where an instance's storage keyring lives.
func (d Dir) datasphereDir(name string) string {
	return filepath.Join(d.instanceDir(name), datasphereSubdir)
}

// InstanceKeyringPath is the path to an instance's DataSphere keyring. It is
// returned rather than read because losing this file is unrecoverable, so the
// caller that owns the operation owns the read, the write, and the warning.
func (d Dir) InstanceKeyringPath(name string) string {
	return filepath.Join(d.datasphereDir(name), keyringFile)
}

// InstanceKeyringExists reports whether an instance has a storage keyring yet.
func (d Dir) InstanceKeyringExists(name string) (bool, error) {
	_, err := os.Stat(d.InstanceKeyringPath(name))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// LoadInstanceKeyring reads an instance's keyring bytes, refusing a file that
// is readable by anyone else on the machine — the same permission discipline
// the credential store applies, on a file that is strictly more dangerous to
// lose control of.
func (d Dir) LoadInstanceKeyring(name string) ([]byte, error) {
	path := d.InstanceKeyringPath(name)
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("keyring %s is mode %04o; it must not be readable by other accounts on this machine", path, perm)
	}
	return os.ReadFile(path)
}

// CreateInstanceKeyring writes a new keyring, refusing to overwrite an
// existing one. The refusal is the point: overwriting this file is the
// key-loss catastrophe in one command.
func (d Dir) CreateInstanceKeyring(name string, data []byte) error {
	dir := d.datasphereDir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	path := d.InstanceKeyringPath(name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// SaveInstanceKeyring replaces an instance's keyring. Every caller of this
// must have merged rather than replaced its contents — see
// datasphere.Keyring.Merge — because a keyring written over another loses
// every key the other held.
func (d Dir) SaveInstanceKeyring(name string, data []byte) error {
	if err := os.MkdirAll(d.datasphereDir(name), 0o700); err != nil {
		return err
	}
	return os.WriteFile(d.InstanceKeyringPath(name), data, 0o600)
}

func (d Dir) fatlineDir(name string) string {
	return filepath.Join(d.instanceDir(name), fatlineSubdir)
}

// InstanceMTLSExists reports whether the data-plane mTLS identity has been
// minted for an instance (keyed on the CA certificate's presence).
func (d Dir) InstanceMTLSExists(name string) (bool, error) {
	_, err := os.Stat(filepath.Join(d.fatlineDir(name), caCertFile))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// SaveInstanceMTLS writes the per-instance mTLS material under <instance>/fatline/
// (dir 0700, files 0600). The CA private key is included here — on the operator's
// machine — but the caller must never push it to the cluster.
func (d Dir) SaveInstanceMTLS(name string, m MTLSMaterial) error {
	dir := d.fatlineDir(name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create fatline directory: %w", err)
	}
	files := []struct {
		name string
		data []byte
	}{
		{caCertFile, m.CACertPEM},
		{caKeyFile, m.CAKeyPEM},
		{clientCertFile, m.ClientCertPEM},
		{clientKeyFile, m.ClientKeyPEM},
		{serverCertFile, m.ServerCertPEM},
		{serverKeyFile, m.ServerKeyPEM},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	return nil
}

// LoadInstanceMTLS reads the per-instance mTLS material.
func (d Dir) LoadInstanceMTLS(name string) (MTLSMaterial, error) {
	dir := d.fatlineDir(name)
	read := func(file string) ([]byte, error) {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", file, err)
		}
		return b, nil
	}
	var m MTLSMaterial
	var err error
	if m.CACertPEM, err = read(caCertFile); err != nil {
		return MTLSMaterial{}, err
	}
	if m.CAKeyPEM, err = read(caKeyFile); err != nil {
		return MTLSMaterial{}, err
	}
	if m.ClientCertPEM, err = read(clientCertFile); err != nil {
		return MTLSMaterial{}, err
	}
	if m.ClientKeyPEM, err = read(clientKeyFile); err != nil {
		return MTLSMaterial{}, err
	}
	if m.ServerCertPEM, err = read(serverCertFile); err != nil {
		return MTLSMaterial{}, err
	}
	if m.ServerKeyPEM, err = read(serverKeyFile); err != nil {
		return MTLSMaterial{}, err
	}
	return m, nil
}

// writeInstanceFile writes data to <instance>/<file> at 0600. The instance
// directory must already exist (reserved via CreateInstance).
func (d Dir) writeInstanceFile(name, file string, data []byte) error {
	path := filepath.Join(d.instanceDir(name), file)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
