package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/vault"
)

func newLsCmd(d *deps) *cobra.Command {
	var vaultName, project string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List entries (names are plaintext, no unlock needed)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			vaults, err := openVaults(cfg, vaultName)
			if err != nil {
				return err
			}
			var groupFilter string
			if project != "" {
				if groupFilter, err = vault.NormalizeSlug(project); err != nil {
					return err
				}
			}
			var entries []vault.EntryRef
			for _, v := range vaults {
				list, err := v.List()
				if err != nil {
					return err
				}
				for _, e := range list {
					if groupFilter != "" &&
						(e.Type != vault.TypeEnv || !strings.HasPrefix(e.Name, groupFilter+"/")) {
						continue
					}
					entries = append(entries, e)
				}
			}
			if jsonOut {
				out := make([]lsEntryJSON, 0, len(entries))
				for _, e := range entries {
					out = append(out, lsEntryJSON{
						Vault:     e.VaultName,
						Type:      e.Type,
						Name:      e.Name,
						UpdatedAt: e.UpdatedAt.UTC(),
					})
				}
				return printJSON(cmd.OutOrStdout(), out)
			}
			if len(entries) == 0 {
				fmt.Fprintln(cmd.ErrOrStderr(), "no entries")
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 2, 4, 2, ' ', 0)
			fmt.Fprintln(w, "VAULT\tTYPE\tNAME\tUPDATED")
			for _, e := range entries {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					e.VaultName, e.Type, e.Name, e.UpdatedAt.Local().Format("2006-01-02 15:04"))
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&vaultName, "vault", "", "vault to list")
	cmd.Flags().StringVar(&project, "project", "", "only env entries of this group")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print entries as JSON")
	return cmd
}

type lsEntryJSON struct {
	Vault     string    `json:"vault"`
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at"`
}
