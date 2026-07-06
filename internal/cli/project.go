package cli

import (
	"errors"
	"fmt"
	"strings"

	"filippo.io/age"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/crypto"
	"github.com/Flexipie/coffin/internal/project"
	"github.com/Flexipie/coffin/internal/vault"
)

// projectContext discovers .coffin.toml from the working directory and
// resolves the vault and overlay name for the dev-workflow commands
// (run, render, diff). Vault precedence: --vault flag, then the
// project file's vault key, then the single registered vault. Env
// precedence: -e flag, then default_env; never a silent default.
func projectContext(cfg *config.Config, vaultFlag, envFlag string) (*project.File, *vault.Vault, string, error) {
	pf, err := project.Find(".")
	if err != nil {
		return nil, nil, "", err
	}
	name := vaultFlag
	if name == "" {
		name = pf.Vault
	}
	if name == "" && len(cfg.Vaults) > 1 {
		return nil, nil, "", fmt.Errorf("coffin: multiple vaults configured; set vault in %s or pass --vault", pf.Path)
	}
	v, err := pickVault(cfg, name)
	if err != nil {
		return nil, nil, "", err
	}
	env := envFlag
	if env == "" {
		env = pf.DefaultEnv
	}
	if env == "" {
		return nil, nil, "", fmt.Errorf("coffin: no environment specified; pass -e or set default_env in %s", pf.Path)
	}
	return pf, v, env, nil
}

// loadEffectiveEnv resolves the effective variable set for one
// overlay: base (if present) overlaid by env, per FORMAT.md
// "Effective environment". A missing overlay is an error naming what
// exists, never a silent fallback.
func loadEffectiveEnv(v *vault.Vault, group, env string, id age.Identity) (vault.EnvData, error) {
	exists, err := v.EnvGroupExists(group)
	if err != nil {
		return vault.EnvData{}, err
	}
	if !exists {
		return vault.EnvData{}, fmt.Errorf("coffin: vault %q has no env group %q", v.Manifest.Vault.Name, group)
	}
	ok, err := v.EnvExists(group, env)
	if err != nil {
		return vault.EnvData{}, err
	}
	if !ok {
		msg := fmt.Sprintf("coffin: env group %s has no overlay %q", group, env)
		if overlays, lerr := envOverlays(v, group); lerr == nil && len(overlays) > 0 {
			msg += fmt.Sprintf(" (available: %s)", strings.Join(overlays, ", "))
		}
		return vault.EnvData{}, errors.New(msg)
	}
	overlay, err := v.GetEnv(group, env, id)
	if err != nil {
		return vault.EnvData{}, wrapScopeErr(err, v, group)
	}
	base := vault.EnvData{}
	if env != "base" {
		hasBase, err := v.EnvExists(group, "base")
		if err != nil {
			return vault.EnvData{}, err
		}
		if hasBase {
			base, err = v.GetEnv(group, "base", id)
			if err != nil {
				return vault.EnvData{}, wrapScopeErr(err, v, group)
			}
		}
	}
	return project.Merge(base, overlay), nil
}

// wrapScopeErr adds context to a group-key decrypt failure: the caller
// already proved the master password via acquireIdentity, so ErrDecrypt
// here almost always means the identity is not in the group's wrap set
// (a scoped recipient). UX on top of the generic error, not an oracle.
func wrapScopeErr(err error, v *vault.Vault, group string) error {
	if errors.Is(err, crypto.ErrDecrypt) {
		return fmt.Errorf("coffin: cannot decrypt env group %q in vault %q - your key may not be in scope for this project (ask an admin to run \"coffin share --project %s\"): %w",
			group, v.Manifest.Vault.Name, group, err)
	}
	return err
}

// envOverlays lists a group's overlay names from plaintext headers (no
// unlock needed), sorted by List's path ordering.
func envOverlays(v *vault.Vault, group string) ([]string, error) {
	entries, err := v.List()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.Type != vault.TypeEnv {
			continue
		}
		g, env := splitGroupEnv(e.Name)
		if g == group {
			out = append(out, env)
		}
	}
	return out, nil
}

// composeEnv overlays vars onto a parent environment in os.Environ()
// form: parent order kept, matching names replaced in place, new
// names appended in vars order.
func composeEnv(parent []string, vars []vault.EnvVar) []string {
	out := make([]string, len(parent), len(parent)+len(vars))
	copy(out, parent)
	index := make(map[string]int, len(out))
	for i, kv := range out {
		if j := strings.IndexByte(kv, '='); j >= 0 {
			index[kv[:j]] = i
		}
	}
	for _, v := range vars {
		if i, ok := index[v.Key]; ok {
			out[i] = v.Key + "=" + v.Value
		} else {
			index[v.Key] = len(out)
			out = append(out, v.Key+"="+v.Value)
		}
	}
	return out
}
