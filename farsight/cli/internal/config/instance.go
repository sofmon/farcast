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
