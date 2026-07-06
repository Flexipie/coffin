package config

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/Flexipie/coffin/internal/vault"
)

const (
	defaultSessionTTLMinutes     = 15
	defaultClipboardClearSeconds = 30
)

// Config is the decoded config.toml.
type Config struct {
	FormatVersion int        `toml:"format_version"`
	Settings      Settings   `toml:"settings"`
	Vaults        []VaultRef `toml:"vaults"`
}

// Settings is the [settings] table.
type Settings struct {
	SessionTTLMinutes     int `toml:"session_ttl_minutes"`
	ClipboardClearSeconds int `toml:"clipboard_clear_seconds"`
}

// VaultRef is one [[vaults]] registry entry.
type VaultRef struct {
	Name string `toml:"name"`
	Path string `toml:"path"`
	Kind string `toml:"kind"`
}

// Default is the config used when no config.toml exists yet.
func Default() *Config {
	return &Config{
		FormatVersion: vault.FormatVersion,
		Settings: Settings{
			SessionTTLMinutes:     defaultSessionTTLMinutes,
			ClipboardClearSeconds: defaultClipboardClearSeconds,
		},
	}
}

// Load reads config.toml, returning defaults if it does not exist.
func Load() (*Config, error) {
	path, err := ConfigPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Default(), nil
		}
		return nil, err
	}
	if err := vault.CheckVersion(path, data); err != nil {
		return nil, err
	}
	var c Config
	if err := toml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("coffin: parse %s: %w", path, err)
	}
	// A config written before a setting existed decodes to zero; fall
	// back to the default rather than a zero TTL.
	if c.Settings.SessionTTLMinutes <= 0 {
		c.Settings.SessionTTLMinutes = defaultSessionTTLMinutes
	}
	if c.Settings.ClipboardClearSeconds <= 0 {
		c.Settings.ClipboardClearSeconds = defaultClipboardClearSeconds
	}
	return &c, nil
}

// Save writes config.toml atomically, creating the config dir 0700.
func (c *Config) Save() error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path, err := ConfigPath()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := toml.NewEncoder(&buf)
	enc.Indent = ""
	if err := enc.Encode(c); err != nil {
		return err
	}
	return vault.WriteFileAtomic(path, buf.Bytes())
}

// AddVault registers a vault, rejecting duplicate names.
func (c *Config) AddVault(name, path, kind string) error {
	if _, ok := c.FindVault(name); ok {
		return fmt.Errorf("coffin: a vault named %q is already registered", name)
	}
	c.Vaults = append(c.Vaults, VaultRef{Name: name, Path: path, Kind: kind})
	return nil
}

// FindVault looks a vault up by registry name.
func (c *Config) FindVault(name string) (VaultRef, bool) {
	for _, v := range c.Vaults {
		if v.Name == name {
			return v, true
		}
	}
	return VaultRef{}, false
}

// SessionTTL is how long an unlock session lasts.
func (c *Config) SessionTTL() time.Duration {
	return time.Duration(c.Settings.SessionTTLMinutes) * time.Minute
}

// ClipboardClear is how long a copied secret stays on the clipboard.
func (c *Config) ClipboardClear() time.Duration {
	return time.Duration(c.Settings.ClipboardClearSeconds) * time.Second
}
