package vault

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// EntryRef identifies one entry. Path is the canonical vault-relative
// path without extension (e.g. "passwords/github",
// "env/myapp/staging"); it is the entry's identity because it is what
// gets bound into AAD. Name is the human form without the top-level
// prefix.
type EntryRef struct {
	VaultName string
	VaultRoot string
	Type      string
	Path      string
	Name      string
	UpdatedAt time.Time
}

// List walks the vault and returns every entry, decoding only the
// plaintext headers: no unlock needed, names are plaintext by design
// (FORMAT.md, "Slugs and names"). key.toml files are infrastructure,
// not entries, and are skipped.
func (v *Vault) List() ([]EntryRef, error) {
	var out []EntryRef
	for _, top := range []string{"passwords", "env"} {
		base := filepath.Join(v.Root, top)
		if _, err := os.Stat(base); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if d.IsDir() {
				return nil
			}
			// Skip non-entries: group key files, leftover temp files,
			// anything that is not TOML.
			if !strings.HasSuffix(name, ".toml") || strings.HasPrefix(name, ".") {
				return nil
			}
			if top == "env" && name == envKeyName {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := CheckVersion(path, data); err != nil {
				return err
			}
			var h struct {
				Type      string    `toml:"type"`
				UpdatedAt time.Time `toml:"updated_at"`
			}
			if err := decodeTOML(path, data, &h); err != nil {
				return err
			}
			rel, err := filepath.Rel(v.Root, path)
			if err != nil {
				return err
			}
			canonical := strings.TrimSuffix(filepath.ToSlash(rel), ".toml")
			// An overlay directly under env/ has no group, which no
			// coffin ever writes; skip it so env names always carry a
			// group/env split.
			if top == "env" && strings.Count(canonical, "/") < 2 {
				return nil
			}
			out = append(out, EntryRef{
				VaultName: v.Manifest.Vault.Name,
				VaultRoot: v.Root,
				Type:      h.Type,
				Path:      canonical,
				Name:      strings.TrimPrefix(canonical, top+"/"),
				UpdatedAt: h.UpdatedAt,
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
