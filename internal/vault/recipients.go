package vault

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/Flexipie/coffin/internal/crypto"
)

// pendingWrite is one file computed in memory before anything touches
// disk: both recipient operations prepare every byte first so a
// failure (bad unwrap, tampered file) aborts with the vault unchanged.
type pendingWrite struct {
	rel  string // slash path relative to the vault root
	data []byte
}

// AddRecipient appends rec to the manifest and rewraps every key blob
// the new recipient is in scope for: all keys for a full recipient,
// only the covered env group keys for a scoped one. Data keys and
// payloads are unchanged (FORMAT.md, "Add recipient": rewrap only).
// It returns the vault-relative paths it wrote, manifest included, for
// the caller's git commit.
func (v *Vault) AddRecipient(rec Recipient, id age.Identity) ([]string, error) {
	if strings.TrimSpace(rec.Name) == "" {
		return nil, fmt.Errorf("coffin: recipient name must not be empty")
	}
	if _, err := crypto.ParseRecipient(rec.PublicKey); err != nil {
		return nil, fmt.Errorf("coffin: invalid public key: %w", err)
	}
	for _, r := range v.Manifest.Recipients {
		if r.Name == rec.Name {
			return nil, fmt.Errorf("%w: recipient %q", ErrExists, rec.Name)
		}
		if r.PublicKey == rec.PublicKey {
			return nil, fmt.Errorf("%w: recipient %q already holds this public key", ErrExists, r.Name)
		}
	}
	if rec.Projects != nil {
		if len(rec.Projects) == 0 {
			return nil, fmt.Errorf("coffin: a scoped recipient needs at least one project")
		}
		for i, p := range rec.Projects {
			norm, err := NormalizeSlug(p)
			if err != nil {
				return nil, err
			}
			rec.Projects[i] = norm
		}
	}
	if rec.AddedAt.IsZero() {
		rec.AddedAt = v.now()
	} else {
		rec.AddedAt = rec.AddedAt.UTC().Truncate(time.Second)
	}

	updated := append(append([]Recipient(nil), v.Manifest.Recipients...), rec)
	var writes []pendingWrite

	if rec.Full() {
		slugs, err := v.passwordSlugs()
		if err != nil {
			return nil, err
		}
		pwSet, err := passwordRecipients(v.Manifest.Vault.Name, updated)
		if err != nil {
			return nil, err
		}
		for _, slug := range slugs {
			w, err := v.rewrapPasswordEntry(slug, id, pwSet)
			if err != nil {
				return nil, err
			}
			writes = append(writes, w)
		}
	}
	groups, err := v.envGroups()
	if err != nil {
		return nil, err
	}
	for _, group := range groups {
		if !rec.Covers(group) {
			continue
		}
		set, err := groupRecipients(v.Manifest.Vault.Name, updated, group)
		if err != nil {
			return nil, err
		}
		kf, err := readEntryFile(v.envKeyPath(group))
		if err != nil {
			return nil, err
		}
		wrapped, err := crypto.Rewrap(kf.Key.Wrapped, id, set)
		if err != nil {
			return nil, err
		}
		writes = append(writes, pendingWrite{
			rel:  "env/" + group + "/" + envKeyName,
			data: renderEnvKey(wrapped),
		})
	}

	touched, err := v.flush(writes)
	if err != nil {
		return nil, err
	}
	// Manifest last: a crash before this line leaves blobs readable by
	// a recipient the manifest does not list yet, which is harmless.
	v.Manifest.Recipients = updated
	if err := v.saveManifest(); err != nil {
		return touched, err
	}
	return append(touched, manifestName), nil
}

// RevokeRecipient removes the named recipient and rotates everything
// they could read: every entry for a full recipient, only the covered
// env groups for a scoped one (FORMAT.md, "Revoke recipient"). It
// returns the written vault-relative paths and the canonical paths of
// every rotated entry, which is the needs-source-rotation checklist:
// the revoked party has seen those values, so they must be rotated at
// the source too.
func (v *Vault) RevokeRecipient(name string, id age.Identity) (touched, rotated []string, err error) {
	idx := -1
	for i, r := range v.Manifest.Recipients {
		if r.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, nil, fmt.Errorf("coffin: no recipient named %q in vault %q", name, v.Manifest.Vault.Name)
	}
	revoked := v.Manifest.Recipients[idx]
	remaining := append(append([]Recipient(nil), v.Manifest.Recipients[:idx]...), v.Manifest.Recipients[idx+1:]...)
	hasFull := false
	for _, r := range remaining {
		if r.Full() {
			hasFull = true
			break
		}
	}
	if !hasFull {
		return nil, nil, fmt.Errorf("coffin: cannot revoke %q: a vault must keep at least one full recipient", name)
	}

	var writes []pendingWrite

	if revoked.Full() {
		slugs, err := v.passwordSlugs()
		if err != nil {
			return nil, nil, err
		}
		pwSet, err := passwordRecipients(v.Manifest.Vault.Name, remaining)
		if err != nil {
			return nil, nil, err
		}
		for _, slug := range slugs {
			w, err := v.rotatePasswordEntry(slug, id, pwSet)
			if err != nil {
				return nil, nil, err
			}
			writes = append(writes, w)
			rotated = append(rotated, "passwords/"+slug)
		}
	}
	groups, err := v.envGroups()
	if err != nil {
		return nil, nil, err
	}
	for _, group := range groups {
		if !revoked.Covers(group) {
			continue
		}
		set, err := groupRecipients(v.Manifest.Vault.Name, remaining, group)
		if err != nil {
			return nil, nil, err
		}
		groupWrites, groupRotated, err := v.rotateEnvGroup(group, id, set)
		if err != nil {
			return nil, nil, err
		}
		writes = append(writes, groupWrites...)
		rotated = append(rotated, groupRotated...)
	}

	touched, err = v.flush(writes)
	if err != nil {
		return touched, rotated, err
	}
	// Manifest last, deliberately: if a crash interrupts the writes
	// above, the manifest still lists the revoked recipient, so the
	// half-rotated state is visible and a re-run completes it. The
	// reverse order would report a revocation that never happened.
	v.Manifest.Recipients = remaining
	if err := v.saveManifest(); err != nil {
		return touched, rotated, err
	}
	return append(touched, manifestName), rotated, nil
}

// rewrapPasswordEntry re-encrypts one entry's wrapped key to set,
// leaving the payload and header untouched so the AAD is unchanged.
func (v *Vault) rewrapPasswordEntry(slug string, id age.Identity, set []age.Recipient) (pendingWrite, error) {
	f, err := readEntryFile(v.passwordPath(slug))
	if err != nil {
		return pendingWrite{}, err
	}
	wrapped, err := crypto.Rewrap(f.Key.Wrapped, id, set)
	if err != nil {
		return pendingWrite{}, err
	}
	nonce, ct, err := decodePayload(f)
	if err != nil {
		return pendingWrite{}, err
	}
	return pendingWrite{
		rel:  "passwords/" + slug + ".toml",
		data: renderPasswordEntry(f.Name, f.UpdatedAt, wrapped, nonce, ct),
	}, nil
}

// rotatePasswordEntry decrypts one entry and reseals it under a fresh
// data key wrapped to set. updated_at bumps to now, and with it the
// AAD.
func (v *Vault) rotatePasswordEntry(slug string, id age.Identity, set []age.Recipient) (pendingWrite, error) {
	f, err := readEntryFile(v.passwordPath(slug))
	if err != nil {
		return pendingWrite{}, err
	}
	dataKey, err := crypto.UnwrapKey(f.Key.Wrapped, id)
	if err != nil {
		return pendingWrite{}, err
	}
	canonical := "passwords/" + slug
	plaintext, err := openEntryPayload(f, v.Manifest.Vault.ID, canonical, dataKey)
	if err != nil {
		return pendingWrite{}, err
	}
	updatedAt := v.now()
	wrapped, sealed, err := crypto.Rotate([]crypto.Payload{{
		Plaintext: plaintext,
		AAD:       crypto.EntryAAD(v.Manifest.Vault.ID, TypePassword, canonical, updatedAt),
	}}, set)
	if err != nil {
		return pendingWrite{}, err
	}
	return pendingWrite{
		rel:  canonical + ".toml",
		data: renderPasswordEntry(f.Name, updatedAt, wrapped, sealed[0].Nonce, sealed[0].Ciphertext),
	}, nil
}

// rotateEnvGroup decrypts every overlay of a group and reseals them
// all under one fresh group key wrapped to set.
func (v *Vault) rotateEnvGroup(group string, id age.Identity, set []age.Recipient) ([]pendingWrite, []string, error) {
	kf, err := readEntryFile(v.envKeyPath(group))
	if err != nil {
		return nil, nil, err
	}
	groupKey, err := crypto.UnwrapKey(kf.Key.Wrapped, id)
	if err != nil {
		return nil, nil, err
	}
	envs, err := v.groupOverlays(group)
	if err != nil {
		return nil, nil, err
	}
	updatedAt := v.now()
	payloads := make([]crypto.Payload, len(envs))
	names := make([]string, len(envs))
	for i, env := range envs {
		f, err := readEntryFile(v.envPath(group, env))
		if err != nil {
			return nil, nil, err
		}
		canonical := "env/" + group + "/" + env
		plaintext, err := openEntryPayload(f, v.Manifest.Vault.ID, canonical, groupKey)
		if err != nil {
			return nil, nil, err
		}
		payloads[i] = crypto.Payload{
			Plaintext: plaintext,
			AAD:       crypto.EntryAAD(v.Manifest.Vault.ID, TypeEnv, canonical, updatedAt),
		}
		names[i] = f.Name
	}
	wrapped, sealed, err := crypto.Rotate(payloads, set)
	if err != nil {
		return nil, nil, err
	}
	writes := []pendingWrite{{
		rel:  "env/" + group + "/" + envKeyName,
		data: renderEnvKey(wrapped),
	}}
	rotated := make([]string, 0, len(envs))
	for i, env := range envs {
		writes = append(writes, pendingWrite{
			rel:  "env/" + group + "/" + env + ".toml",
			data: renderEnvEntry(names[i], updatedAt, sealed[i].Nonce, sealed[i].Ciphertext),
		})
		rotated = append(rotated, "env/"+group+"/"+env)
	}
	return writes, rotated, nil
}

// flush writes every pending file atomically and returns their
// vault-relative paths.
func (v *Vault) flush(writes []pendingWrite) ([]string, error) {
	touched := make([]string, 0, len(writes))
	for _, w := range writes {
		if err := WriteFileAtomic(filepath.Join(v.Root, filepath.FromSlash(w.rel)), w.data); err != nil {
			return touched, err
		}
		touched = append(touched, w.rel)
	}
	return touched, nil
}

// decodePayload base64-decodes a stored payload; malformed base64 is
// tampering and surfaces as ErrDecrypt like every other decode
// failure.
func decodePayload(f entryFile) (nonce, ct []byte, err error) {
	nonce, err = base64.StdEncoding.DecodeString(f.Payload.Nonce)
	if err != nil {
		return nil, nil, crypto.ErrDecrypt
	}
	ct, err = base64.StdEncoding.DecodeString(f.Payload.Ciphertext)
	if err != nil {
		return nil, nil, crypto.ErrDecrypt
	}
	return nonce, ct, nil
}

// passwordSlugs lists every password entry's canonical slug, sorted so
// recipient operations touch files in a deterministic order.
func (v *Vault) passwordSlugs() ([]string, error) {
	base := filepath.Join(v.Root, "passwords")
	var out []string
	err := walkTOML(base, func(path string) error {
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		out = append(out, strings.TrimSuffix(filepath.ToSlash(rel), ".toml"))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// envGroups lists every env group (a directory holding a key.toml),
// sorted.
func (v *Vault) envGroups() ([]string, error) {
	base := filepath.Join(v.Root, "env")
	var out []string
	err := walkTOML(base, func(path string) error {
		if filepath.Base(path) != envKeyName {
			return nil
		}
		rel, err := filepath.Rel(base, filepath.Dir(path))
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// groupOverlays lists a group's overlay names (key.toml excluded),
// sorted.
func (v *Vault) groupOverlays(group string) ([]string, error) {
	entries, err := os.ReadDir(v.envDir(group))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".toml") || strings.HasPrefix(name, ".") || name == envKeyName {
			continue
		}
		out = append(out, strings.TrimSuffix(name, ".toml"))
	}
	sort.Strings(out)
	return out, nil
}

// walkTOML calls fn for every non-hidden .toml file under base; a
// missing base is an empty result, not an error.
func walkTOML(base string, fn func(path string) error) error {
	if _, err := os.Stat(base); os.IsNotExist(err) {
		return nil
	}
	return filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".toml") || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		return fn(path)
	})
}
