package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
)

func newRevokeCmd(d *deps) *cobra.Command {
	var user, vaultName string
	cmd := &cobra.Command{
		Use:   "revoke --user <name>",
		Short: "Remove a recipient and rotate every key they could read",
		Args:  cobra.NoArgs,
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
			id, _, err := acquireIdentity(d, cfg, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			for _, r := range v.Manifest.Recipients {
				if r.Name == user && r.PublicKey == id.Recipient().String() {
					return fmt.Errorf("coffin: refusing to revoke yourself; another member must revoke you")
				}
			}
			touched, rotated, err := v.RevokeRecipient(user, id)
			if err != nil {
				return err
			}
			if err := teamCommit(cmd.ErrOrStderr(), v,
				fmt.Sprintf("revoke: remove %s, rotate %d keys", user, len(rotated)), touched...); err != nil {
				return err
			}

			errW := cmd.ErrOrStderr()
			fmt.Fprintf(errW, "Revoked %s from %s. Rotated %d entries.\n",
				user, v.Manifest.Vault.Name, len(rotated))
			if len(rotated) > 0 {
				fmt.Fprintf(errW, "\nneeds-source-rotation: %s has seen these values; rotate them at the source\n(new API key, new database password, ...). Coffin re-encrypted the files, but it\ncannot change what the revoked party already read:\n", user)
				for _, path := range rotated {
					fmt.Fprintf(errW, "  - %s\n", path)
				}
			}
			if isTeam(v) {
				fmt.Fprintln(errW, `
Run "coffin sync" to publish. Members read the vault as usual after their next sync.`)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&user, "user", "", "recipient name to revoke")
	cmd.Flags().StringVar(&vaultName, "vault", "", "vault to revoke from")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}
