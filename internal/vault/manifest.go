package vault

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
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

// Recipient is one [[recipients]] element. A nil Projects list means a
// full recipient; a non-empty list scopes the recipient to the env
// groups covered by those prefixes (FORMAT.md, "Recipient scope"). An
// empty non-nil list is invalid to write and covers nothing on read.
type Recipient struct {
	Name      string    `toml:"name"`
	PublicKey string    `toml:"public_key"`
	AddedAt   time.Time `toml:"added_at"`
	Projects  []string  `toml:"projects,omitempty"`
}

// Full reports whether the recipient can read the entire vault.
func (r Recipient) Full() bool {
	return r.Projects == nil
}

// Covers reports whether the recipient is in scope for an env group.
// Prefixes match segment-wise: "myapp" covers "myapp" and "myapp/api"
// but not "myapp2".
func (r Recipient) Covers(group string) bool {
	if r.Full() {
		return true
	}
	for _, p := range r.Projects {
		if group == p || strings.HasPrefix(group, p+"/") {
			return true
		}
	}
	return false
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
