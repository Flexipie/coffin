// Package config manages ~/.config/coffin: the vault registry
// (config.toml) and the sealed identity (identity.toml).
package config

import (
	"os"
	"path/filepath"
)

// Dir returns the coffin config directory. FORMAT.md pins this to
// $XDG_CONFIG_HOME/coffin (falling back to ~/.config/coffin), so
// os.UserConfigDir is deliberately not used: on darwin it returns
// ~/Library/Application Support, which is not where the spec says the
// identity lives.
func Dir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "coffin"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "coffin"), nil
}

// IdentityPath is where the sealed identity lives.
func IdentityPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "identity.toml"), nil
}

// ConfigPath is where the vault registry lives.
func ConfigPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.toml"), nil
}

// DefaultVaultRoot is where "coffin init" puts the personal vault when
// --path is not given.
func DefaultVaultRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".vault", "personal"), nil
}
