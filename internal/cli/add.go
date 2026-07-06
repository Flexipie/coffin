package cli

import (
	"errors"
	"fmt"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/vault"
)

const generatedPasswordLen = 24

func newAddCmd(d *deps) *cobra.Command {
	var typ, vaultName, fromFile string
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a password entry, or an env set as <group>/<env>",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			v, err := pickVault(cfg, vaultName)
			if err != nil {
				return err
			}
			if err := ensureCleanTeamVault(v); err != nil {
				return err
			}
			switch typ {
			case vault.TypePassword:
				err = addPassword(cmd, d, cfg, v, args[0], fromFile)
			case vault.TypeEnv:
				err = addEnv(cmd, d, cfg, v, args[0], fromFile)
			default:
				return fmt.Errorf("coffin: unknown --type %q (password or env)", typ)
			}
			if err != nil {
				return err
			}
			return teamCommit(cmd.ErrOrStderr(), v, "add "+commitSlug(args[0]))
		},
	}
	cmd.Flags().StringVar(&typ, "type", vault.TypePassword, "entry type: password or env")
	cmd.Flags().StringVar(&vaultName, "vault", "", "vault to add to")
	cmd.Flags().StringVar(&fromFile, "from-file", "", "read KEY=VALUE lines from a file (env only)")
	return cmd
}

// addPassword is encrypt-only: no unlock, ever.
func addPassword(cmd *cobra.Command, d *deps, cfg *config.Config, v *vault.Vault, name, fromFile string) error {
	if fromFile != "" {
		return errors.New("coffin: --from-file only applies to --type env")
	}
	slug, err := vault.NormalizeSlug(name)
	if err != nil {
		return err
	}
	exists, err := v.PasswordExists(slug)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("coffin: %q already exists in %s (use \"coffin edit %s\")",
			slug, v.Manifest.Vault.Name, slug)
	}

	username, err := d.prompt.Prompt("Username: ")
	if err != nil {
		return err
	}
	password, err := d.prompt.PromptHidden("Password (empty to auto-generate): ")
	if err != nil {
		return err
	}
	generated := false
	if password == "" {
		password, err = generatePassword(generatedPasswordLen, true)
		if err != nil {
			return err
		}
		generated = true
	}
	url, err := d.prompt.Prompt("URL: ")
	if err != nil {
		return err
	}
	notes, err := d.prompt.Prompt("Notes: ")
	if err != nil {
		return err
	}
	totp, err := d.prompt.PromptHidden("TOTP seed (optional): ")
	if err != nil {
		return err
	}

	// Copy before writing: if the clipboard is broken the user would
	// otherwise end up with a stored password they have never seen.
	if generated {
		if err := d.clip.Copy(password); err != nil {
			return fmt.Errorf("coffin: generated a password but %v; enter one explicitly or use \"coffin gen --show\"", err)
		}
	}
	if err := v.PutPassword(slug, vault.PasswordData{
		Username: username,
		Password: password,
		URL:      url,
		Notes:    notes,
		TOTPSeed: totp,
	}); err != nil {
		return err
	}
	errW := cmd.ErrOrStderr()
	fmt.Fprintf(errW, "Added %s to %s.\n", slug, v.Manifest.Vault.Name)
	if generated {
		return d.copyWithClear(errW, cfg,
			password, fmt.Sprintf("Generated a %d-character password and copied it.", generatedPasswordLen))
	}
	return nil
}

// addEnv needs the identity only when the group already exists (its
// shared key must be unwrapped); a fresh group is encrypt-only.
func addEnv(cmd *cobra.Command, d *deps, cfg *config.Config, v *vault.Vault, name, fromFile string) error {
	slug, err := vault.NormalizeSlug(name)
	if err != nil {
		return err
	}
	if !strings.Contains(slug, "/") {
		return fmt.Errorf("coffin: env entries need a group: use <group>/<env>, e.g. myapp/dev")
	}
	group, env := splitGroupEnv(slug)
	exists, err := v.EnvExists(group, env)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("coffin: %q already exists in %s (use \"coffin edit %s\")",
			slug, v.Manifest.Vault.Name, slug)
	}
	vars, err := readEnvVars(cmd, fromFile)
	if err != nil {
		return err
	}
	ident := func() (age.Identity, error) {
		id, _, err := acquireIdentity(d, cfg, cmd.ErrOrStderr())
		return id, err
	}
	if err := v.PutEnv(group, env, vault.EnvData{Vars: vars}, ident); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Added %s to %s (%d vars).\n", slug, v.Manifest.Vault.Name, len(vars))
	return nil
}
