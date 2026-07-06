package cli

import (
	"fmt"
	"strings"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/vault"
)

// openVaults opens every registered vault, or just the named one when
// --vault is given.
func openVaults(cfg *config.Config, only string) ([]*vault.Vault, error) {
	refs := cfg.Vaults
	if only != "" {
		ref, ok := cfg.FindVault(only)
		if !ok {
			return nil, fmt.Errorf("coffin: no vault named %q is registered", only)
		}
		refs = []config.VaultRef{ref}
	}
	if len(refs) == 0 {
		return nil, fmt.Errorf(`coffin: no vaults configured, run "coffin init" first`)
	}
	out := make([]*vault.Vault, 0, len(refs))
	for _, ref := range refs {
		v, err := vault.Open(ref.Path)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// pickVault selects the write target: the named vault, or the only one
// registered.
func pickVault(cfg *config.Config, name string) (*vault.Vault, error) {
	if name == "" && len(cfg.Vaults) > 1 {
		return nil, fmt.Errorf("coffin: multiple vaults configured, pass --vault")
	}
	if name == "" && len(cfg.Vaults) == 1 {
		name = cfg.Vaults[0].Name
	}
	vs, err := openVaults(cfg, name)
	if err != nil {
		return nil, err
	}
	return vs[0], nil
}

// resolveEntry fuzzy-matches query across the scoped vaults: zero
// matches and ambiguity are both errors, per the resolution UX.
func resolveEntry(cfg *config.Config, query, only string) (vault.EntryRef, *vault.Vault, error) {
	vaults, err := openVaults(cfg, only)
	if err != nil {
		return vault.EntryRef{}, nil, err
	}
	byRoot := make(map[string]*vault.Vault, len(vaults))
	var all []vault.EntryRef
	for _, v := range vaults {
		entries, err := v.List()
		if err != nil {
			return vault.EntryRef{}, nil, err
		}
		byRoot[v.Root] = v
		all = append(all, entries...)
	}
	matches := vault.Match(query, all)
	switch len(matches) {
	case 0:
		return vault.EntryRef{}, nil, fmt.Errorf("coffin: no entry matches %q", query)
	case 1:
		return matches[0], byRoot[matches[0].VaultRoot], nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "coffin: %q is ambiguous, matches:", query)
	for _, m := range matches {
		fmt.Fprintf(&b, "\n  %s (%s)", m.Name, m.VaultName)
	}
	return vault.EntryRef{}, nil, fmt.Errorf("%s", b.String())
}

// splitGroupEnv splits an env entry name "group.../env" into its group
// and environment parts. List never yields a slash-less env name, but
// guard anyway rather than panic on a malformed layout.
func splitGroupEnv(name string) (group, env string) {
	i := strings.LastIndexByte(name, '/')
	if i < 0 {
		return "", name
	}
	return name[:i], name[i+1:]
}
