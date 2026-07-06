package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/git"
	"github.com/Flexipie/coffin/internal/vault"
)

func newJoinCmd(d *deps) *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "join <repo> [path]",
		Short: "Clone a team vault and print the public key a member must add",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			repo := args[0]
			dest := ""
			if len(args) == 2 {
				dest = args[1]
			} else {
				dest = cloneBaseName(repo)
			}

			// The identity must exist first: joining is pointless until
			// there is a public key to hand to a member.
			enc, err := config.LoadIdentity()
			if err != nil {
				return err
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if _, err := os.Stat(dest); err == nil {
				return fmt.Errorf("coffin: %s already exists; pass a different path", dest)
			}

			if err := git.Clone(repo, dest); err != nil {
				return err
			}
			v, err := vault.Open(dest)
			if err != nil {
				return fmt.Errorf("coffin: %s does not contain a vault: %w", repo, err)
			}
			if !isTeam(v) {
				return fmt.Errorf("coffin: %s is a %s vault, not a team vault", repo, v.Manifest.Vault.Kind)
			}
			if name == "" {
				name = v.Manifest.Vault.Name
			}
			absDest, err := filepath.Abs(dest)
			if err != nil {
				return err
			}
			if err := cfg.AddVault(name, absDest, vault.KindTeam); err != nil {
				return fmt.Errorf("%w; re-run with --name to register it under another name", err)
			}
			if err := cfg.Save(); err != nil {
				return err
			}

			errW := cmd.ErrOrStderr()
			fmt.Fprintf(errW, "Joined %q at %s.\n\n", name, absDest)
			fmt.Fprintf(errW, "Your public key:\n  %s\n\n", enc.PublicKey)
			fmt.Fprintln(errW, "You cannot read anything yet. Ask an existing member to run:")
			fmt.Fprintf(errW, "  coffin share --with %s --name <your-name>\n", enc.PublicKey)
			fmt.Fprintln(errW, `then run "coffin sync" to pull your access.`)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "registry name for the vault (default: the vault's own name)")
	return cmd
}

// cloneBaseName mirrors git's default target directory for a clone.
func cloneBaseName(repo string) string {
	base := filepath.Base(strings.TrimSuffix(strings.TrimRight(repo, "/"), ".git"))
	if base == "" || base == "." || base == string(os.PathSeparator) {
		return "vault"
	}
	return base
}
