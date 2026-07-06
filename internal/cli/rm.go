package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/vault"
)

func newRmCmd(d *deps) *cobra.Command {
	var force bool
	var vaultName string
	cmd := &cobra.Command{
		Use:   "rm <query>",
		Short: "Remove an entry",
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
			if !force {
				answer, err := d.prompt.Prompt(fmt.Sprintf("Delete %s (%s)? [y/N]: ", ref.Name, ref.VaultName))
				if err != nil {
					// Not a terminal: deleting needs an explicit opt-in.
					return fmt.Errorf("coffin: cannot confirm deletion: %v (pass --force)", err)
				}
				switch strings.ToLower(strings.TrimSpace(answer)) {
				case "y", "yes":
				default:
					fmt.Fprintln(cmd.ErrOrStderr(), "Aborted.")
					return nil
				}
			}
			switch ref.Type {
			case vault.TypePassword:
				err = v.RemovePassword(ref.Name)
			case vault.TypeEnv:
				group, env := splitGroupEnv(ref.Name)
				err = v.RemoveEnv(group, env)
			default:
				err = fmt.Errorf("coffin: %s has unknown type %q", ref.Path, ref.Type)
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Removed %s from %s.\n", ref.Name, ref.VaultName)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "delete without confirmation")
	cmd.Flags().StringVar(&vaultName, "vault", "", "vault to search")
	return cmd
}
