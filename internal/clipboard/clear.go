package clipboard

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// ClearSubcommand is the hidden CLI subcommand the detached clearer
// runs. Blocking the foreground command for the clear window would
// ruin the flow, so the parent re-execs itself detached instead.
const ClearSubcommand = "__clear-clipboard"

// HashValue is the SHA-256 hex fingerprint used to hand the copied
// value's identity to the clearer without ever exposing the value.
func HashValue(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

// SpawnClearer starts "<self> __clear-clipboard <seconds>" detached
// from this process. The hash travels on the child's stdin, never in
// argv where ps could see it (argv would only leak a hash, but stdin
// costs nothing). The write happens through a real pipe before Start
// so the parent can exit immediately without racing the child's read.
func SpawnClearer(exePath string, after time.Duration, value string) error {
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer r.Close()
	if _, err := w.WriteString(HashValue(value) + "\n"); err != nil {
		w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	cmd := exec.Command(exePath, ClearSubcommand, strconv.Itoa(int(after/time.Second)))
	cmd.Stdin = r
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	// No Wait: the child outlives us by design. Release lets the
	// runtime forget about it.
	return cmd.Process.Release()
}

// ClearIfMatches clears the clipboard only if it still holds the value
// with the given SHA-256 hex fingerprint, so a later user copy is
// never clobbered.
func ClearIfMatches(c Clipboard, hashHex string) error {
	current, err := c.Read()
	if err != nil {
		return err
	}
	if HashValue(current) != hashHex {
		return nil
	}
	return c.Copy("")
}
