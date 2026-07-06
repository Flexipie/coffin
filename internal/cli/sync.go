package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/git"
	"github.com/Flexipie/coffin/internal/vault"
)

func newSyncCmd(d *deps) *cobra.Command {
	var vaultName string
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Pull and push team vaults",
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
			errW := cmd.ErrOrStderr()
			synced := 0
			for _, v := range vaults {
				if !isTeam(v) {
					if vaultName != "" {
						return fmt.Errorf("coffin: %q is a personal vault; there is nothing to sync", v.Manifest.Vault.Name)
					}
					continue
				}
				if err := syncVault(v); err != nil {
					return err
				}
				fmt.Fprintf(errW, "Synced %s.\n", v.Manifest.Vault.Name)
				synced++
			}
			if synced == 0 {
				fmt.Fprintln(errW, "No team vaults registered; nothing to sync.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&vaultName, "vault", "", "sync only this vault")
	return cmd
}

// syncVault is pull then push. Conflict resolution is deliberately
// git's own flow (PRD, open question 5): coffin adds guidance, not a
// merge engine. Vault files are per-entry TOML, so two people editing
// different entries never conflict at all.
func syncVault(v *vault.Vault) error {
	if !git.IsRepo(v.Root) {
		return fmt.Errorf("coffin: team vault %s is not a git repository", v.Root)
	}
	hasRemote, err := git.HasRemote(v.Root)
	if err != nil {
		return err
	}
	if !hasRemote {
		return fmt.Errorf("coffin: team vault %s has no git remote; add one with\n  git -C %s remote add origin <url>", v.Root, v.Root)
	}
	if dirty, err := git.IsDirty(v.Root); err != nil {
		return err
	} else if dirty {
		return fmt.Errorf("coffin: team vault %s has uncommitted changes; commit them before syncing", v.Root)
	}
	// A branch that has never pushed has no upstream to pull from; the
	// first sync is publish-only and the push below sets the upstream.
	if git.HasUpstream(v.Root) {
		if err := git.Pull(v.Root); err != nil {
			return fmt.Errorf("%w\n\nResolve this in %s with your normal git tools (git status, fix, git add,\ngit commit), then run \"coffin sync\" again.", err, v.Root)
		}
	}
	return git.Push(v.Root)
}
