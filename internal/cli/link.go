package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/project"
	"github.com/Flexipie/coffin/internal/vault"
)

func newLinkCmd(d *deps) *cobra.Command {
	var vaultName, defaultEnv string
	cmd := &cobra.Command{
		Use:   "link <group>",
		Short: "Write .coffin.toml connecting this directory to an env group",
		Long: "Write a .coffin.toml in the current directory linking this repo to\n" +
			"a vault env group, so run/render/diff know what to read. The file is\n" +
			"secret-free and meant to be committed.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLink(cmd, args[0], vaultName, defaultEnv)
		},
	}
	cmd.Flags().StringVarP(&defaultEnv, "env", "e", "", "default_env to record")
	cmd.Flags().StringVar(&vaultName, "vault", "", "vault holding the group")
	return cmd
}

func runLink(cmd *cobra.Command, groupArg, vaultName, defaultEnv string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	v, err := pickVault(cfg, vaultName)
	if err != nil {
		return err
	}
	group, err := vault.NormalizeSlug(groupArg)
	if err != nil {
		return err
	}
	if defaultEnv != "" {
		defaultEnv, err = vault.NormalizeSlug(defaultEnv)
		if err != nil {
			return err
		}
		if strings.Contains(defaultEnv, "/") {
			return fmt.Errorf("coffin: default env %q must be a single segment", defaultEnv)
		}
		if defaultEnv == "key" {
			return fmt.Errorf("coffin: %q is reserved for the group key file", defaultEnv)
		}
	}
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, project.FileName)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("coffin: %s already exists; edit it directly", path)
	} else if !os.IsNotExist(err) {
		return err
	}

	errW := cmd.ErrOrStderr()
	exists, err := v.EnvGroupExists(group)
	if err != nil {
		return err
	}
	if !exists {
		fmt.Fprintf(errW, "warning: vault %q has no env group %q yet - \"coffin run\" will fail until you add one (coffin add %s/dev --type env)\n",
			v.Manifest.Vault.Name, group, group)
	}

	// Hand-rendered like every other coffin write; vault is always
	// written explicitly because teammates read this committed file.
	var b strings.Builder
	b.WriteString("format_version = 1\n\n[project]\n")
	fmt.Fprintf(&b, "vault = %q\n", v.Manifest.Vault.Name)
	fmt.Fprintf(&b, "group = %q\n", group)
	if defaultEnv != "" {
		fmt.Fprintf(&b, "default_env = %q\n", defaultEnv)
	}
	if err := vault.WriteFileAtomic(path, []byte(b.String())); err != nil {
		return err
	}
	msg := fmt.Sprintf("Linked %s to %s/%s", dir, v.Manifest.Vault.Name, group)
	if defaultEnv != "" {
		msg += fmt.Sprintf(" (default env: %s)", defaultEnv)
	}
	fmt.Fprintf(errW, "%s. Commit %s; keep .env gitignored.\n", msg, project.FileName)
	return nil
}
