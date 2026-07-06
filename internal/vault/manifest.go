package vault

import (
	"bytes"
	"fmt"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

// Manifest mirrors coffin.toml (FORMAT.md, "coffin.toml (manifest)").
type Manifest struct {
	FormatVersion int         `toml:"format_version"`
	Vault         VaultInfo   `toml:"vault"`
	Recipients    []Recipient `toml:"recipients"`
}

// VaultInfo is the [vault] table.
type VaultInfo struct {
	ID        string    `toml:"id"`
	Name      string    `toml:"name"`
	Kind      string    `toml:"kind"` // "personal" | "team"
	CreatedAt time.Time `toml:"created_at"`
}

// Recipient is one [[recipients]] element.
type Recipient struct {
	Name      string    `toml:"name"`
	PublicKey string    `toml:"public_key"`
	AddedAt   time.Time `toml:"added_at"`
}

func decodeManifest(path string, data []byte) (Manifest, error) {
	var m Manifest
	if err := toml.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("coffin: parse %s: %w", path, err)
	}
	return m, nil
}

func (v *Vault) saveManifest() error {
	var buf bytes.Buffer
	enc := toml.NewEncoder(&buf)
	enc.Indent = ""
	if err := enc.Encode(v.Manifest); err != nil {
		return err
	}
	return WriteFileAtomic(filepath.Join(v.Root, manifestName), buf.Bytes())
}
