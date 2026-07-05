package cli

import (
	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "coffin",
		Short:         "coffin is a local-first password and secrets manager",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	cmd.AddCommand(newVersionCmd())
	return cmd
}

// Execute runs the root command.
func Execute() error {
	return newRootCmd().Execute()
}
