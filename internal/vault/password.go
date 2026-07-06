package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/Flexipie/coffin/internal/crypto"
)

func (v *Vault) passwordPath(slug string) string {
	return filepath.Join(v.Root, "passwords", filepath.FromSlash(slug)+".toml")
}

// PutPassword writes (or overwrites) a self-contained password entry.
// Every write generates a fresh data key and wraps it to all current
// recipients, so this path is encrypt-only: adding or editing a
// password never needs the identity unlocked.
func (v *Vault) PutPassword(slug string, data PasswordData) error {
	slug, err := NormalizeSlug(slug)
	if err != nil {
		return err
	}
	recipients, err := v.AgeRecipients()
	if err != nil {
		return err
	}
	dataKey, err := crypto.NewDataKey()
	if err != nil {
		return err
	}
	wrapped, err := crypto.WrapKey(dataKey, recipients)
	if err != nil {
		return err
	}
	plaintext, err := json.Marshal(data)
	if err != nil {
		return err
	}
	canonical := "passwords/" + slug
	updatedAt := v.now()
	nonce, ct, err := crypto.Seal(dataKey, plaintext,
		crypto.EntryAAD(v.Manifest.Vault.ID, TypePassword, canonical, updatedAt))
	if err != nil {
		return err
	}
	path := v.passwordPath(slug)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return WriteFileAtomic(path, renderPasswordEntry(lastSegment(slug), updatedAt, wrapped, nonce, ct))
}

// GetPassword decrypts a password entry. The AAD is recomputed from
// the actual on-disk path plus the file's header fields.
func (v *Vault) GetPassword(slug string, id age.Identity) (PasswordData, error) {
	slug, err := NormalizeSlug(slug)
	if err != nil {
		return PasswordData{}, err
	}
	f, err := readEntryFile(v.passwordPath(slug))
	if err != nil {
		return PasswordData{}, err
	}
	dataKey, err := crypto.UnwrapKey(f.Key.Wrapped, id)
	if err != nil {
		return PasswordData{}, err
	}
	plaintext, err := openEntryPayload(f, v.Manifest.Vault.ID, "passwords/"+slug, dataKey)
	if err != nil {
		return PasswordData{}, err
	}
	var data PasswordData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		// A sealed payload that authenticates but does not parse means
		// corruption inside the envelope; keep it indistinguishable.
		return PasswordData{}, crypto.ErrDecrypt
	}
	return data, nil
}

// PasswordExists reports whether a password entry exists. Because only
// normalized names are written, a plain stat doubles as the
// case-insensitive uniqueness check.
func (v *Vault) PasswordExists(slug string) (bool, error) {
	slug, err := NormalizeSlug(slug)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(v.passwordPath(slug)); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// RemovePassword deletes a password entry and prunes any directories
// it leaves empty.
func (v *Vault) RemovePassword(slug string) error {
	slug, err := NormalizeSlug(slug)
	if err != nil {
		return err
	}
	path := v.passwordPath(slug)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	pruneEmptyDirs(v.Root, filepath.Dir(path))
	return nil
}

// pruneEmptyDirs removes dir and its parents while they are empty,
// stopping at root (exclusive). Failures are ignored: a non-empty
// directory is the normal stop condition.
func pruneEmptyDirs(root, dir string) {
	root = filepath.Clean(root)
	for dir = filepath.Clean(dir); dir != root && strings.HasPrefix(dir, root); dir = filepath.Dir(dir) {
		if os.Remove(dir) != nil {
			return
		}
	}
}
