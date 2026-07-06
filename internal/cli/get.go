package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/vault"
)

func newGetCmd(d *deps) *cobra.Command {
	var show, jsonOut bool
	var field, vaultName string
	cmd := &cobra.Command{
		Use:   "get <query>",
		Short: "Copy a secret to the clipboard (or print with --show)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonOut && !show {
				return fmt.Errorf("coffin: --json prints secrets, so it requires --show")
			}
			if jsonOut && field != "" {
				return fmt.Errorf("coffin: --field and --json are mutually exclusive")
			}
			if field != "" {
				if _, err := passwordField(vault.PasswordData{}, field); err != nil {
					return err
				}
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			ref, v, err := resolveEntry(cfg, args[0], vaultName)
			if err != nil {
				return err
			}
			id, _, err := acquireIdentity(d, cfg, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			switch ref.Type {
			case vault.TypePassword:
				data, err := v.GetPassword(ref.Name, id)
				if err != nil {
					return err
				}
				if jsonOut {
					return printJSON(cmd.OutOrStdout(), struct {
						Name string `json:"name"`
						vault.PasswordData
					}{ref.Name, data})
				}
				return getPassword(cmd, d, cfg, ref, data, field, show)
			case vault.TypeEnv:
				if field != "" {
					return fmt.Errorf("coffin: --field only applies to password entries")
				}
				group, env := splitGroupEnv(ref.Name)
				data, err := v.GetEnv(group, env, id)
				if err != nil {
					return err
				}
				if jsonOut {
					// An object keyed by name reads best in scripts
					// (jq .DB_URL); a duplicated key's last occurrence
					// wins, matching the merge rule.
					obj := make(map[string]string, len(data.Vars))
					for _, ev := range data.Vars {
						obj[ev.Key] = ev.Value
					}
					return printJSON(cmd.OutOrStdout(), obj)
				}
				return getEnv(cmd, ref, data, show)
			}
			return fmt.Errorf("coffin: %s has unknown type %q", ref.Path, ref.Type)
		},
	}
	cmd.Flags().BoolVar(&show, "show", false, "print to stdout instead of copying")
	cmd.Flags().StringVar(&field, "field", "", "password field: username, password, url, notes, totp")
	cmd.Flags().StringVar(&vaultName, "vault", "", "vault to search")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print as JSON (requires --show)")
	return cmd
}

func passwordField(data vault.PasswordData, field string) (string, error) {
	switch field {
	case "username":
		return data.Username, nil
	case "password":
		return data.Password, nil
	case "url":
		return data.URL, nil
	case "notes":
		return data.Notes, nil
	case "totp":
		return data.TOTPSeed, nil
	}
	return "", fmt.Errorf("coffin: unknown field %q (username, password, url, notes, totp)", field)
}

func getPassword(cmd *cobra.Command, d *deps, cfg *config.Config, ref vault.EntryRef, data vault.PasswordData, field string, show bool) error {
	out, errW := cmd.OutOrStdout(), cmd.ErrOrStderr()
	if show {
		if field != "" {
			value, err := passwordField(data, field)
			if err != nil {
				return err
			}
			fmt.Fprintln(out, value)
			return nil
		}
		fmt.Fprintf(out, "name: %s\n", ref.Name)
		if data.Username != "" {
			fmt.Fprintf(out, "username: %s\n", data.Username)
		}
		fmt.Fprintf(out, "password: %s\n", data.Password)
		if data.URL != "" {
			fmt.Fprintf(out, "url: %s\n", data.URL)
		}
		if data.Notes != "" {
			fmt.Fprintf(out, "notes: %s\n", data.Notes)
		}
		if data.TOTPSeed != "" {
			fmt.Fprintf(out, "totp: %s\n", data.TOTPSeed)
		}
		return nil
	}

	if field == "" {
		field = "password"
	}
	value, err := passwordField(data, field)
	if err != nil {
		return err
	}
	if value == "" {
		return fmt.Errorf("coffin: %s has an empty %s", ref.Name, field)
	}
	err = d.copyWithClear(errW, cfg, value,
		fmt.Sprintf("Copied %s for %s (%s).", field, ref.Name, ref.VaultName))
	if err != nil {
		return err
	}
	if field == "password" {
		if data.Username != "" {
			fmt.Fprintf(errW, "  username: %s\n", data.Username)
		}
		if data.URL != "" {
			fmt.Fprintf(errW, "  url: %s\n", data.URL)
		}
	}
	return nil
}

func getEnv(cmd *cobra.Command, ref vault.EntryRef, data vault.EnvData, show bool) error {
	out := cmd.OutOrStdout()
	if show {
		for _, v := range data.Vars {
			fmt.Fprintf(out, "%s=%s\n", v.Key, v.Value)
		}
		return nil
	}
	for _, v := range data.Vars {
		fmt.Fprintf(out, "%s=•••\n", v.Key)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "(%d vars in %s; values hidden, use --show to print them)\n",
		len(data.Vars), ref.Name)
	return nil
}
