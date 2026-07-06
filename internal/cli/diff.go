package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
)

func newDiffCmd(d *deps) *cobra.Command {
	var envName, vaultName, filePath string
	var showValues, jsonOut bool
	cmd := &cobra.Command{
		Use:   "diff [-e <env>] [-f <file>]",
		Short: "Compare the project's env group against a local .env file",
		Long: "Compare the project's effective env vars against a local dotenv\n" +
			"file and flag drift in both directions. Exits 1 on any drift, so it\n" +
			"works as a CI check. Values are never printed without --values.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return silenceExitCode(cmd, runDiff(cmd, d, envName, vaultName, filePath, showValues, jsonOut))
		},
	}
	cmd.Flags().StringVarP(&envName, "env", "e", "", "overlay to compare (default: default_env from .coffin.toml)")
	cmd.Flags().StringVarP(&filePath, "file", "f", "", "dotenv file to compare (default: .env next to .coffin.toml)")
	cmd.Flags().BoolVar(&showValues, "values", false, "print the differing values")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print the drift report as JSON")
	cmd.Flags().StringVar(&vaultName, "vault", "", "vault holding the project group")
	return cmd
}

func runDiff(cmd *cobra.Command, d *deps, envName, vaultName, filePath string, showValues, jsonOut bool) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	pf, v, env, err := projectContext(cfg, vaultName, envName)
	if err != nil {
		return err
	}
	target := filePath
	if target == "" {
		target = filepath.Join(pf.Dir, ".env")
	}
	f, err := os.Open(target)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("coffin: no dotenv file at %s - run \"coffin render\" first, or pass -f", target)
		}
		return err
	}
	localVars, err := parseDotenv(f)
	f.Close()
	if err != nil {
		return err
	}
	id, _, err := acquireIdentity(d, cfg, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	data, err := loadEffectiveEnv(v, pf.Group, env, id)
	if err != nil {
		return err
	}

	// Last occurrence wins on the local side, matching the merge rule;
	// the vault side is already key-unique after the merge.
	local := make(map[string]string, len(localVars))
	for _, lv := range localVars {
		local[lv.Key] = lv.Value
	}
	inVault := make(map[string]string, len(data.Vars))
	var vaultOnly, changed []string
	for _, vv := range data.Vars {
		inVault[vv.Key] = vv.Value
		lv, ok := local[vv.Key]
		switch {
		case !ok:
			vaultOnly = append(vaultOnly, vv.Key)
		case lv != vv.Value:
			changed = append(changed, vv.Key)
		}
	}
	var localOnly []string
	for k := range local {
		if _, ok := inVault[k]; !ok {
			localOnly = append(localOnly, k)
		}
	}
	sort.Strings(vaultOnly)
	sort.Strings(localOnly)
	sort.Strings(changed)
	if vaultOnly == nil {
		vaultOnly = []string{}
	}
	if localOnly == nil {
		localOnly = []string{}
	}

	out := cmd.OutOrStdout()
	matched := len(data.Vars) - len(vaultOnly) - len(changed)
	inSync := len(vaultOnly)+len(localOnly)+len(changed) == 0
	if jsonOut {
		report := diffJSON{
			Vault:     v.Manifest.Vault.Name,
			Group:     pf.Group,
			Env:       env,
			File:      target,
			InSync:    inSync,
			Matching:  matched,
			VaultOnly: vaultOnly,
			FileOnly:  localOnly,
			Changed:   make([]diffChangeJSON, 0, len(changed)),
		}
		for _, k := range changed {
			c := diffChangeJSON{Key: k}
			if showValues {
				c.VaultValue = inVault[k]
				c.LocalValue = local[k]
			}
			report.Changed = append(report.Changed, c)
		}
		if err := printJSON(out, report); err != nil {
			return err
		}
		if inSync {
			return nil
		}
		return &exitCodeError{code: 1}
	}
	if inSync {
		fmt.Fprintf(out, "In sync: %d vars match %s/%s (%s).\n", matched, v.Manifest.Vault.Name, pf.Group, env)
		return nil
	}
	fmt.Fprintf(out, "Comparing %s/%s (%s) against %s:\n", v.Manifest.Vault.Name, pf.Group, env, target)
	width := 0
	for _, keys := range [][]string{vaultOnly, localOnly, changed} {
		for _, k := range keys {
			if len(k) > width {
				width = len(k)
			}
		}
	}
	for _, k := range vaultOnly {
		fmt.Fprintf(out, "  + %-*s  only in vault (missing from the file)\n", width, k)
	}
	for _, k := range localOnly {
		fmt.Fprintf(out, "  - %-*s  only in the file (not in vault)\n", width, k)
	}
	for _, k := range changed {
		if showValues {
			fmt.Fprintf(out, "  ~ %-*s  vault: %s  local: %s\n", width, k, inVault[k], local[k])
		} else {
			fmt.Fprintf(out, "  ~ %-*s  values differ\n", width, k)
		}
	}
	fmt.Fprintf(out, "%d matching, %d only in vault, %d only in the file, %d changed.\n",
		matched, len(vaultOnly), len(localOnly), len(changed))
	return &exitCodeError{code: 1}
}

type diffJSON struct {
	Vault     string           `json:"vault"`
	Group     string           `json:"group"`
	Env       string           `json:"env"`
	File      string           `json:"file"`
	InSync    bool             `json:"in_sync"`
	Matching  int              `json:"matching"`
	VaultOnly []string         `json:"vault_only"`
	FileOnly  []string         `json:"file_only"`
	Changed   []diffChangeJSON `json:"changed"`
}

// diffChangeJSON carries the values only when --values is set; keys
// alone otherwise, same posture as the text output.
type diffChangeJSON struct {
	Key        string `json:"key"`
	VaultValue string `json:"vault_value,omitempty"`
	LocalValue string `json:"local_value,omitempty"`
}
