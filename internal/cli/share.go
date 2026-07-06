package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/vault"
)

func newShareCmd(d *deps) *cobra.Command {
	var pubkey, name, vaultName string
	var projects []string
	cmd := &cobra.Command{
		Use:   "share --with <pubkey> --name <name>",
		Short: "Add a recipient to a vault (rewraps keys, no payload rewrite)",
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
			rec := vault.Recipient{Name: name, PublicKey: pubkey}
			if len(projects) > 0 {
				rec.Projects = projects
			}
			touched, err := v.AddRecipient(rec, id)
			if err != nil {
				return err
			}
			if err := teamCommit(cmd.ErrOrStderr(), v,
				fmt.Sprintf("share: add %s", name), touched...); err != nil {
				return err
			}

			errW := cmd.ErrOrStderr()
			if rec.Full() {
				fmt.Fprintf(errW, "Added %s to %s with full access.\n", name, v.Manifest.Vault.Name)
			} else {
				fmt.Fprintf(errW, "Added %s to %s, scoped to: %s.\n",
					name, v.Manifest.Vault.Name, strings.Join(rec.Projects, ", "))
			}
			if isTeam(v) {
				fmt.Fprintln(errW, `Run "coffin sync" to publish.`)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&pubkey, "with", "", "the new recipient's age public key")
	cmd.Flags().StringVar(&name, "name", "", "the new recipient's name in the manifest")
	cmd.Flags().StringArrayVar(&projects, "project", nil,
		"scope to an env project prefix (repeatable); omit for full access")
	cmd.Flags().StringVar(&vaultName, "vault", "", "vault to share")
	_ = cmd.MarkFlagRequired("with")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}
