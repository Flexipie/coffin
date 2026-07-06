package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/git"
	"github.com/Flexipie/coffin/internal/vault"
)

func newRenderCmd(d *deps) *cobra.Command {
	var envName, vaultName, outPath string
	var force bool
	cmd := &cobra.Command{
		Use:   "render [-e <env>] [-o <path>]",
		Short: "Write the project's env vars to a plaintext .env file",
		Long: "Write the project's effective env vars (base overlaid by the chosen\n" +
			"environment) to a dotenv file. This is the ONLY way coffin ever puts\n" +
			"plaintext secrets on disk; keep the output gitignored.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRender(cmd, d, envName, vaultName, outPath, force)
		},
	}
	cmd.Flags().StringVarP(&envName, "env", "e", "", "overlay to use (default: default_env from .coffin.toml)")
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "output path (default: .env next to .coffin.toml)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing file")
	cmd.Flags().StringVar(&vaultName, "vault", "", "vault holding the project group")
	return cmd
}

func runRender(cmd *cobra.Command, d *deps, envName, vaultName, outPath string, force bool) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	pf, v, env, err := projectContext(cfg, vaultName, envName)
	if err != nil {
		return err
	}
	target := outPath
	if target == "" {
		target = filepath.Join(pf.Dir, ".env")
	}
	if !force {
		if _, err := os.Stat(target); err == nil {
			return fmt.Errorf("coffin: %s already exists; pass --force to overwrite", target)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	id, _, err := acquireIdentity(d, cfg, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	data, err := loadEffectiveEnv(v, pf.Group, env, id)
	if err != nil {
		return err
	}
	content, err := renderDotenv(v.Manifest.Vault.Name, pf.Group, env, d.now(), data.Vars)
	if err != nil {
		return err
	}
	if err := vault.WriteFileAtomic(target, content); err != nil {
		return err
	}
	errW := cmd.ErrOrStderr()
	fmt.Fprintf(errW, "Wrote %d vars to %s - plaintext, keep it gitignored.\n", len(data.Vars), target)
	dir := filepath.Dir(target)
	if git.IsRepo(dir) && !git.IsIgnored(dir, target) {
		fmt.Fprintf(errW, "warning: %s is not gitignored\n", target)
	}
	return nil
}

// renderDotenv produces the dotenv file content. Every line it emits
// must round-trip through parseDotenv byte-identically (FORMAT.md,
// "Dotenv dialect"), so values the dialect cannot represent are
// rejected, naming the key and never the value.
func renderDotenv(vaultName, group, env string, at time.Time, vars []vault.EnvVar) ([]byte, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# Rendered by coffin from %s/%s (%s) at %s.\n",
		vaultName, group, env, at.UTC().Format(time.RFC3339))
	b.WriteString("# PLAINTEXT SECRETS - do not commit this file.\n")
	fmt.Fprintf(&b, "# Regenerate: coffin render -e %s --force\n", env)
	for _, v := range vars {
		if strings.ContainsAny(v.Value, "\n\r") {
			return nil, fmt.Errorf("coffin: %s has a line break in its value, which a dotenv file cannot represent; use \"coffin run\" instead", v.Key)
		}
		if strings.TrimRight(v.Value, " \t") != v.Value {
			return nil, fmt.Errorf("coffin: %s has trailing whitespace in its value, which a dotenv round-trip would drop; use \"coffin run\" instead", v.Key)
		}
		fmt.Fprintf(&b, "%s=%s\n", v.Key, v.Value)
	}
	return []byte(b.String()), nil
}
