// Package config resolves and persists the operator's local FarCast state —
// CLI preferences now, and per-instance metadata and credentials in later
// phases — under strict filesystem permissions.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/goccy/go-yaml"
)

const (
	dirName  = "farcast"
	fileName = "config.yaml"

	// EnvConfigHome overrides the config directory location.
	EnvConfigHome = "FARCAST_CONFIG_HOME"
)

// Dir is a resolved config directory path.
type Dir string

// Resolve determines the config directory, in precedence order: the override
// argument (the --config flag), then $FARCAST_CONFIG_HOME, then the OS user
// config directory joined with "farcast".
func Resolve(override string) (Dir, error) {
	if override != "" {
		return Dir(override), nil
	}
	if env := os.Getenv(EnvConfigHome); env != "" {
		return Dir(env), nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine user config directory: %w", err)
	}
	return Dir(filepath.Join(base, dirName)), nil
}

// Path returns the directory path as a string.
func (d Dir) Path() string { return string(d) }

// Ensure creates the directory (0700) if absent and verifies it is not group-
// or world-accessible.
func (d Dir) Ensure() error {
	if err := os.MkdirAll(string(d), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	return d.CheckPerms()
}

// CheckPerms reports an error if the directory is group- or world-accessible.
func (d Dir) CheckPerms() error {
	info, err := os.Stat(string(d))
	if err != nil {
		return err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("config directory %s is too permissive (%#o); want 0700", string(d), perm)
	}
	return nil
}

// Config holds the CLI's persisted preferences. Per-instance metadata and
// credential schemas are added by `farcast install` (phase 1.3).
type Config struct {
	DefaultOutput string `yaml:"default_output,omitempty"`
}

// Load reads config.yaml from d. A missing file (or directory) yields default
// configuration without error.
func Load(d Dir) (*Config, error) {
	path := filepath.Join(string(d), fileName)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// Save writes config.yaml to d (0600), creating the directory if needed.
func (c *Config) Save(d Dir) error {
	if err := d.Ensure(); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	path := filepath.Join(string(d), fileName)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
