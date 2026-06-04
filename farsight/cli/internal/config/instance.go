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
)

// Instance lifecycle states recorded in metadata.yaml.
const (
	InstanceProvisioning = "provisioning"
	InstanceRunning      = "running"
	InstanceUnreachable  = "unreachable"
	InstanceError        = "error"
)

// CostLimit is the mandatory spend ceiling captured at install. For phase 1.3
// it is a monthly USD amount; enforcement is TechnoCore's job (4.1).
type CostLimit struct {
	Amount   float64 `yaml:"amount"`
	Currency string  `yaml:"currency"`
	Period   string  `yaml:"period"`
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

// SaveInstanceKubeconfig writes kubeconfig.yaml (0600) for an instance.
func (d Dir) SaveInstanceKubeconfig(name string, kubeconfig []byte) error {
	return d.writeInstanceFile(name, kubeconfigFile, kubeconfig)
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
