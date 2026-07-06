package cli

import (
	"github.com/spf13/cobra"
)

func newRootCmd(d *deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "coffin",
		Short:         "coffin is a local-first password and secrets manager",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	cmd.AddCommand(
		newVersionCmd(),
		newInitCmd(d),
		newAddCmd(d),
		newGetCmd(d),
		newLsCmd(d),
		newEditCmd(d),
		newRmCmd(d),
		newGenCmd(d),
		newUnlockCmd(d),
		newLockCmd(d),
		newClearClipCmd(d),
	)
	return cmd
}

// Execute runs the root command with production dependencies.
func Execute() error {
	return newRootCmd(productionDeps()).Execute()
}
