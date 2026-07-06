package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
)

func newLockCmd(d *deps) *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "End the unlock session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if err := sessionManager(d, cfg).Clear(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Locked.")
			return nil
		},
	}
}
