//go:build !windows

package clipboard

import (
	"os/exec"
	"syscall"
)

// detach puts the clearer in its own session so it survives the parent
// exiting and is not part of the terminal's process group.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
