package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// exitCodeError carries a specific process exit code through cobra.
// run uses it to propagate the child's status and diff uses it for
// the drift-means-nonzero contract; both have already produced their
// own output, so the error itself should not be printed.
type exitCodeError struct {
	code int
}

func (e *exitCodeError) Error() string {
	return fmt.Sprintf("exit code %d", e.code)
}

// ExitCode maps the error returned by Execute to a process exit code:
// nil is 0, an exitCodeError is its code, anything else is 1.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ec *exitCodeError
	if errors.As(err, &ec) {
		return ec.code
	}
	return 1
}

// silenceExitCode keeps cobra from printing an exitCodeError while
// leaving ordinary errors on the normal printing path. Cobra reads
// SilenceErrors after RunE returns, so flipping it here is enough.
func silenceExitCode(cmd *cobra.Command, err error) error {
	var ec *exitCodeError
	if errors.As(err, &ec) {
		cmd.SilenceErrors = true
	}
	return err
}
