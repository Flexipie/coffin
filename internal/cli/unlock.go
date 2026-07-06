package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
)

func newUnlockCmd(d *deps) *cobra.Command {
	return &cobra.Command{
		Use:   "unlock",
		Short: "Start an unlock session (avoids repeated password prompts)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			_, res, err := acquireIdentity(d, cfg, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if res.FromSession {
				fmt.Fprintln(cmd.ErrOrStderr(), "Already unlocked.")
				return nil
			}
			if !res.Stored {
				fmt.Fprintln(cmd.ErrOrStderr(), "Session not stored; every command will prompt.")
				return nil
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Unlocked for %s.\n", formatTTL(cfg.SessionTTL()))
			return nil
		},
	}
}
