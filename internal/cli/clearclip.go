package cli

import (
	"bufio"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/clipboard"
)

// newClearClipCmd is the detached helper behind clipboard auto-clear:
// it reads the copied value's hash from stdin, sleeps, and clears the
// clipboard only if it still holds that value. It is hidden and never
// loud; nobody is watching its output and a failed clear must not
// leave error noise in a random terminal.
func newClearClipCmd(d *deps) *cobra.Command {
	return &cobra.Command{
		Use:           clipboard.ClearSubcommand + " <seconds>",
		Hidden:        true,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			seconds, err := strconv.Atoi(args[0])
			if err != nil || seconds < 0 {
				return nil
			}
			line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
			hash := strings.TrimSpace(line)
			if hash == "" && err != nil {
				return nil
			}
			time.Sleep(time.Duration(seconds) * time.Second)
			clipboard.ClearIfMatches(d.clip, hash)
			return nil
		},
	}
}
