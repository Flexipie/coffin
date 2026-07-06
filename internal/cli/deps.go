package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Flexipie/coffin/internal/clipboard"
	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/session"
)

// deps is the test seam: every side-effecting collaborator a command
// touches, swappable with fakes.
type deps struct {
	store    session.Store
	clip     clipboard.Clipboard
	prompt   prompter
	execPath func() (string, error)
	now      func() time.Time
}

func productionDeps() *deps {
	return &deps{
		store:    session.SystemStore(),
		clip:     clipboard.System(),
		prompt:   &terminalPrompter{},
		execPath: os.Executable,
		now:      time.Now,
	}
}

// copyWithClear copies value and schedules the detached auto-clear,
// then reports on stderr. A clearer that fails to spawn downgrades to
// a warning: the copy already happened.
func (d *deps) copyWithClear(errW io.Writer, cfg *config.Config, value, what string) error {
	if err := d.clip.Copy(value); err != nil {
		return err
	}
	if exe, err := d.execPath(); err == nil {
		if err := clipboard.SpawnClearer(exe, cfg.ClipboardClear(), value); err == nil {
			fmt.Fprintf(errW, "%s Clears in %ds.\n", what, int(cfg.ClipboardClear()/time.Second))
			return nil
		}
	}
	fmt.Fprintf(errW, "%s\nwarning: could not schedule the clipboard auto-clear\n", what)
	return nil
}

// formatTTL renders a duration the way humans say it (15m, 2h).
func formatTTL(ttl time.Duration) string {
	if ttl%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(ttl/time.Hour))
	}
	if ttl%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(ttl/time.Minute))
	}
	return ttl.String()
}
