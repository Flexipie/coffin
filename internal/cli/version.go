package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is set at build time via
// -ldflags "-X github.com/Flexipie/coffin/internal/cli.version=v1.2.3".
var version = "dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the coffin version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "coffin %s\n", version)
		},
	}
}
