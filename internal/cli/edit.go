package cli

import (
	"fmt"

	"filippo.io/age"
	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/vault"
)

func newEditCmd(d *deps) *cobra.Command {
	var vaultName, fromFile string
	cmd := &cobra.Command{
		Use:   "edit <query>",
		Short: "Edit an entry (empty input keeps the current value)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			ref, v, err := resolveEntry(cfg, args[0], vaultName)
			if err != nil {
				return err
			}
			id, _, err := acquireIdentity(d, cfg, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			switch ref.Type {
			case vault.TypePassword:
				if fromFile != "" {
					return fmt.Errorf("coffin: --from-file only applies to env entries")
				}
				return editPassword(cmd, d, v, ref, id)
			case vault.TypeEnv:
				return editEnv(cmd, v, ref, id, fromFile)
			}
			return fmt.Errorf("coffin: %s has unknown type %q", ref.Path, ref.Type)
		},
	}
	cmd.Flags().StringVar(&vaultName, "vault", "", "vault to search")
	cmd.Flags().StringVar(&fromFile, "from-file", "", "read replacement KEY=VALUE lines from a file (env only)")
	return cmd
}

// editPassword reseals with a fresh data key and updated_at; PutPassword
// does both on every write.
func editPassword(cmd *cobra.Command, d *deps, v *vault.Vault, ref vault.EntryRef, id age.Identity) error {
	current, err := v.GetPassword(ref.Name, id)
	if err != nil {
		return err
	}
	next := current
	if next.Username, err = promptWithDefault(d.prompt, "Username", current.Username); err != nil {
		return err
	}
	// Secret fields never echo their current value.
	password, err := d.prompt.PromptHidden("Password (empty keeps current): ")
	if err != nil {
		return err
	}
	if password != "" {
		next.Password = password
	}
	if next.URL, err = promptWithDefault(d.prompt, "URL", current.URL); err != nil {
		return err
	}
	if next.Notes, err = promptWithDefault(d.prompt, "Notes", current.Notes); err != nil {
		return err
	}
	totp, err := d.prompt.PromptHidden("TOTP seed (empty keeps current): ")
	if err != nil {
		return err
	}
	if totp != "" {
		next.TOTPSeed = totp
	}
	if err := v.PutPassword(ref.Name, next); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Updated %s in %s.\n", ref.Name, ref.VaultName)
	return nil
}

// editEnv replaces the whole variable set, reusing the group key.
func editEnv(cmd *cobra.Command, v *vault.Vault, ref vault.EntryRef, id age.Identity, fromFile string) error {
	vars, err := readEnvVars(cmd, fromFile)
	if err != nil {
		return err
	}
	group, env := splitGroupEnv(ref.Name)
	err = v.PutEnv(group, env, vault.EnvData{Vars: vars},
		func() (age.Identity, error) { return id, nil })
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Updated %s in %s (%d vars).\n", ref.Name, ref.VaultName, len(vars))
	return nil
}
