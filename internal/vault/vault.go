// Package vault implements the on-disk vault model against
// docs/FORMAT.md: manifest, password entries, env groups, listing and
// fuzzy matching. It writes entry files by hand-rendering (so the byte
// shape is fully deterministic and matches the spec examples) and
// decodes them with BurntSushi/toml.
package vault

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"

	"github.com/Flexipie/coffin/internal/crypto"
)

const manifestName = "coffin.toml"

// Entry type values as stored in the "type" header field.
const (
	TypePassword = "password"
	TypeEnv      = "env"
	TypeEnvKey   = "env-key"
)

// Vault kinds as stored in the manifest.
const (
	KindPersonal = "personal"
	KindTeam     = "team"
)

// Vault is an opened vault directory.
type Vault struct {
	Root     string
	Manifest Manifest
	// Now overrides the timestamp source for writes (tests, golden
	// generation). Nil means time.Now.
	Now func() time.Time
}

// now returns the write timestamp, always UTC at second precision so
// the serialized form recomputes byte-identically in AAD.
func (v *Vault) now() time.Time {
	t := time.Now()
	if v.Now != nil {
		t = v.Now()
	}
	return t.UTC().Truncate(time.Second)
}

// Create makes a new vault directory (0700), gives it a random id, and
// writes the manifest with rec as the sole recipient.
func Create(root, name, kind string, rec Recipient) (*Vault, error) {
	if _, err := os.Stat(filepath.Join(root, manifestName)); err == nil {
		return nil, fmt.Errorf("%w: a vault is already at %s", ErrExists, root)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	if rec.AddedAt.IsZero() {
		rec.AddedAt = now
	} else {
		rec.AddedAt = rec.AddedAt.UTC().Truncate(time.Second)
	}
	v := &Vault{
		Root: root,
		Manifest: Manifest{
			FormatVersion: FormatVersion,
			Vault: VaultInfo{
				ID:        hex.EncodeToString(idBytes),
				Name:      name,
				Kind:      kind,
				CreatedAt: now,
			},
			Recipients: []Recipient{rec},
		},
	}
	if err := v.saveManifest(); err != nil {
		return nil, err
	}
	return v, nil
}

// Open loads the manifest at root. The format_version pre-check runs
// before the full decode, per FORMAT.md.
func Open(root string) (*Vault, error) {
	path := filepath.Join(root, manifestName)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("coffin: no vault at %s (missing %s)", root, manifestName)
		}
		return nil, err
	}
	if err := CheckVersion(path, data); err != nil {
		return nil, err
	}
	m, err := decodeManifest(path, data)
	if err != nil {
		return nil, err
	}
	// The vault id feeds every entry's AAD, which must be NUL-free.
	// It is plaintext metadata checked before any cryptography, so a
	// descriptive error is fine under the error doctrine.
	if !validVaultID(m.Vault.ID) {
		return nil, fmt.Errorf("coffin: %s is corrupt: vault id must be 32 lowercase hex characters", path)
	}
	return &Vault{Root: root, Manifest: m}, nil
}

// validVaultID reports whether id is exactly 16 bytes of lowercase hex,
// the only shape Create ever writes.
func validVaultID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// AgeRecipients parses every manifest recipient's public key,
// regardless of scope. Key wrapping never uses this directly; it goes
// through the scope-aware selectors below.
func (v *Vault) AgeRecipients() ([]age.Recipient, error) {
	return recipientsInScope(v.Manifest.Vault.Name, v.Manifest.Recipients,
		func(Recipient) bool { return true })
}

// recipientsInScope parses the public keys of the recipients the
// filter admits. Zero admitted recipients is an error: no key may ever
// be wrapped to nobody.
func recipientsInScope(vaultName string, list []Recipient, filter func(Recipient) bool) ([]age.Recipient, error) {
	var out []age.Recipient
	for _, r := range list {
		if !filter(r) {
			continue
		}
		rec, err := crypto.ParseRecipient(r.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("coffin: recipient %q has an invalid public key: %w", r.Name, err)
		}
		out = append(out, rec)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("coffin: vault %q has no recipients in scope", vaultName)
	}
	return out, nil
}

// passwordRecipients is the wrap set for password entry keys: full
// recipients only (FORMAT.md, "Recipient scope").
func passwordRecipients(vaultName string, list []Recipient) ([]age.Recipient, error) {
	return recipientsInScope(vaultName, list, Recipient.Full)
}

// groupRecipients is the wrap set for an env group key: full
// recipients plus scoped recipients covering the group.
func groupRecipients(vaultName string, list []Recipient, group string) ([]age.Recipient, error) {
	return recipientsInScope(vaultName, list, func(r Recipient) bool { return r.Covers(group) })
}
