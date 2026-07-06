package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/Flexipie/coffin/internal/crypto"
)

const envKeyName = "key.toml"

func (v *Vault) envDir(group string) string {
	return filepath.Join(v.Root, "env", filepath.FromSlash(group))
}

func (v *Vault) envKeyPath(group string) string {
	return filepath.Join(v.envDir(group), envKeyName)
}

func (v *Vault) envPath(group, env string) string {
	return filepath.Join(v.envDir(group), env+".toml")
}

func normalizeGroupEnv(group, env string) (string, string, error) {
	group, err := NormalizeSlug(group)
	if err != nil {
		return "", "", err
	}
	env, err = NormalizeSlug(env)
	if err != nil {
		return "", "", err
	}
	if strings.Contains(env, "/") {
		return "", "", fmt.Errorf("coffin: environment name %q must be a single segment", env)
	}
	if env == strings.TrimSuffix(envKeyName, ".toml") {
		return "", "", fmt.Errorf("coffin: %q is reserved for the group key file", env)
	}
	return group, env, nil
}

// PutEnv writes (or overwrites) one overlay of an env group. For a new
// group it generates a fresh group key and writes key.toml, all
// encrypt-only. For an existing group it calls ident() lazily to
// unwrap the shared key from key.toml; that is the only case that
// needs the identity.
func (v *Vault) PutEnv(group, env string, data EnvData, ident func() (age.Identity, error)) error {
	group, env, err := normalizeGroupEnv(group, env)
	if err != nil {
		return err
	}
	keyPath := v.envKeyPath(group)

	var dataKey []byte
	var newKeyFile []byte
	raw, err := os.ReadFile(keyPath)
	switch {
	case err == nil:
		if err := CheckVersion(keyPath, raw); err != nil {
			return err
		}
		var kf entryFile
		if err := decodeTOML(keyPath, raw, &kf); err != nil {
			return err
		}
		id, err := ident()
		if err != nil {
			return err
		}
		dataKey, err = crypto.UnwrapKey(kf.Key.Wrapped, id)
		if err != nil {
			return err
		}
	case os.IsNotExist(err):
		dataKey, err = crypto.NewDataKey()
		if err != nil {
			return err
		}
		recipients, err := v.AgeRecipients()
		if err != nil {
			return err
		}
		wrapped, err := crypto.WrapKey(dataKey, recipients)
		if err != nil {
			return err
		}
		newKeyFile = renderEnvKey(wrapped)
	default:
		return err
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return err
	}
	canonical := "env/" + group + "/" + env
	updatedAt := v.now()
	nonce, ct, err := crypto.Seal(dataKey, plaintext,
		crypto.EntryAAD(v.Manifest.Vault.ID, TypeEnv, canonical, updatedAt))
	if err != nil {
		return err
	}
	if newKeyFile != nil {
		if err := os.MkdirAll(v.envDir(group), 0o700); err != nil {
			return err
		}
		if err := WriteFileAtomic(keyPath, newKeyFile); err != nil {
			return err
		}
	}
	return WriteFileAtomic(v.envPath(group, env), renderEnvEntry(env, updatedAt, nonce, ct))
}

// GetEnv decrypts one overlay of an env group.
func (v *Vault) GetEnv(group, env string, id age.Identity) (EnvData, error) {
	group, env, err := normalizeGroupEnv(group, env)
	if err != nil {
		return EnvData{}, err
	}
	kf, err := readEntryFile(v.envKeyPath(group))
	if err != nil {
		return EnvData{}, err
	}
	dataKey, err := crypto.UnwrapKey(kf.Key.Wrapped, id)
	if err != nil {
		return EnvData{}, err
	}
	f, err := readEntryFile(v.envPath(group, env))
	if err != nil {
		return EnvData{}, err
	}
	plaintext, err := openEntryPayload(f, v.Manifest.Vault.ID, "env/"+group+"/"+env, dataKey)
	if err != nil {
		return EnvData{}, err
	}
	var data EnvData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return EnvData{}, crypto.ErrDecrypt
	}
	return data, nil
}

// RemoveEnv deletes one overlay. When the last overlay of a group is
// removed, the now-useless key.toml goes too and empty directories are
// pruned.
func (v *Vault) RemoveEnv(group, env string) error {
	group, env, err := normalizeGroupEnv(group, env)
	if err != nil {
		return err
	}
	if err := os.Remove(v.envPath(group, env)); err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	dir := v.envDir(group)
	if entries, err := os.ReadDir(dir); err == nil {
		hasOverlay := false
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".toml") && e.Name() != envKeyName {
				hasOverlay = true
				break
			}
		}
		if !hasOverlay {
			os.Remove(v.envKeyPath(group))
		}
	}
	pruneEmptyDirs(v.Root, dir)
	return nil
}

// EnvGroupExists reports whether a group already has a key.toml (and
// therefore whether PutEnv will need the identity).
func (v *Vault) EnvGroupExists(group string) (bool, error) {
	group, err := NormalizeSlug(group)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(v.envKeyPath(group)); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// EnvExists reports whether a specific overlay exists.
func (v *Vault) EnvExists(group, env string) (bool, error) {
	group, env, err := normalizeGroupEnv(group, env)
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(v.envPath(group, env)); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
