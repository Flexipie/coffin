//go:build windows

package clipboard

import (
	"os/exec"
	"syscall"
)

// detach on Windows: a new process group and no console window.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x08000000, // CREATE_NO_WINDOW
	}
}
