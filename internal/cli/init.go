package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/crypto"
	"github.com/Flexipie/coffin/internal/git"
	"github.com/Flexipie/coffin/internal/vault"
)

const minPasswordLen = 8

func newInitCmd(d *deps) *cobra.Command {
	var path, name, teamPath string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create your identity and personal vault, or a team vault with --team",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			errW := cmd.ErrOrStderr()

			if teamPath != "" {
				if path != "" {
					return fmt.Errorf("coffin: --path does not apply to --team (the team path is the --team argument)")
				}
				if !cmd.Flags().Changed("name") {
					name = ""
				}
				return initTeamVault(cmd, d, teamPath, name)
			}

			exists, err := config.IdentityExists()
			if err != nil {
				return err
			}
			if exists {
				idPath, _ := config.IdentityPath()
				return fmt.Errorf("coffin: an identity already exists at %s; coffin will not overwrite it", idPath)
			}
			if path == "" {
				if path, err = config.DefaultVaultRoot(); err != nil {
					return err
				}
			}
			if _, err := os.Stat(vaultManifestPath(path)); err == nil {
				return fmt.Errorf("coffin: a vault already exists at %s", path)
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if _, ok := cfg.FindVault(name); ok {
				return fmt.Errorf("coffin: a vault named %q is already registered in config.toml", name)
			}

			defaultUser := os.Getenv("USER")
			if defaultUser == "" {
				defaultUser = "me"
			}
			userName, err := promptWithDefault(d.prompt, "Your name", defaultUser)
			if err != nil {
				return err
			}
			password, err := d.prompt.PromptHidden(fmt.Sprintf("Master password (min %d chars): ", minPasswordLen))
			if err != nil {
				return err
			}
			if len(password) < minPasswordLen {
				return fmt.Errorf("coffin: master password must be at least %d characters", minPasswordLen)
			}
			repeat, err := d.prompt.PromptHidden("Repeat master password: ")
			if err != nil {
				return err
			}
			if password != repeat {
				return fmt.Errorf("coffin: passwords do not match")
			}

			id, err := crypto.GenerateIdentity()
			if err != nil {
				return err
			}
			params, err := crypto.NewKDFParams()
			if err != nil {
				return err
			}
			enc, err := crypto.SealIdentity(id, []byte(password), params)
			if err != nil {
				return err
			}
			if err := config.SaveIdentity(enc); err != nil {
				return err
			}
			if _, err := vault.Create(path, name, "personal", vault.Recipient{
				Name:      userName,
				PublicKey: id.Recipient().String(),
			}); err != nil {
				return err
			}
			if err := cfg.AddVault(name, path, "personal"); err != nil {
				return err
			}
			if err := cfg.Save(); err != nil {
				return err
			}

			idPath, _ := config.IdentityPath()
			fmt.Fprintf(errW, "Identity created at %s\n", idPath)
			fmt.Fprintf(errW, "  public key: %s\n", id.Recipient().String())
			fmt.Fprintf(errW, "Vault %q created at %s\n\n", name, path)
			fmt.Fprintln(errW, "Next steps:")
			fmt.Fprintln(errW, "  coffin add <name>    store your first password")
			fmt.Fprintln(errW, "  coffin get <name>    copy it back (auto-clears)")
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "vault directory (default ~/.vault/personal)")
	cmd.Flags().StringVar(&name, "name", "personal", "vault name in the registry")
	cmd.Flags().StringVar(&teamPath, "team", "", "create a team vault at this path instead")
	return cmd
}

// initTeamVault creates a team vault in a git repo. It needs an
// existing identity (the creator is the first recipient) but no
// unlock: only the public key goes into the manifest.
func initTeamVault(cmd *cobra.Command, d *deps, path, name string) error {
	errW := cmd.ErrOrStderr()
	enc, err := config.LoadIdentity()
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if name == "" {
		name = filepath.Base(filepath.Clean(path))
	}
	if _, ok := cfg.FindVault(name); ok {
		return fmt.Errorf("coffin: a vault named %q is already registered; pass --name", name)
	}

	defaultUser := os.Getenv("USER")
	if defaultUser == "" {
		defaultUser = "me"
	}
	userName, err := promptWithDefault(d.prompt, "Your name (visible to the team)", defaultUser)
	if err != nil {
		return err
	}

	v, err := vault.Create(path, name, vault.KindTeam, vault.Recipient{
		Name:      userName,
		PublicKey: enc.PublicKey,
	})
	if err != nil {
		return err
	}
	if !git.IsRepo(v.Root) {
		if err := git.Init(v.Root); err != nil {
			return err
		}
	}
	if err := git.Commit(v.Root, fmt.Sprintf("init team vault %s", name), "."); err != nil {
		return err
	}
	abs, err := filepath.Abs(v.Root)
	if err != nil {
		return err
	}
	if err := cfg.AddVault(name, abs, vault.KindTeam); err != nil {
		return err
	}
	if err := cfg.Save(); err != nil {
		return err
	}

	fmt.Fprintf(errW, "Team vault %q created at %s.\n\n", name, abs)
	fmt.Fprintln(errW, "Next steps:")
	fmt.Fprintf(errW, "  git -C %s remote add origin <url>   connect it to a remote\n", abs)
	fmt.Fprintln(errW, "  coffin sync                          publish it")
	fmt.Fprintln(errW, "  (teammates run: coffin join <url>, then you share their printed key)")
	return nil
}

// vaultManifestPath mirrors the vault package's layout without
// exporting it just for this pre-check.
func vaultManifestPath(root string) string {
	return root + string(os.PathSeparator) + "coffin.toml"
}
