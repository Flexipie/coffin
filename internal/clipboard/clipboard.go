// Package clipboard wraps the system clipboard and implements the
// detached auto-clear helper.
package clipboard

import (
	"errors"

	"github.com/atotto/clipboard"
)

// Clipboard is the copy/read seam; tests swap in a fake.
type Clipboard interface {
	Copy(text string) error
	Read() (string, error)
}

var errUnsupported = errors.New("coffin: no clipboard available on this system (use --show)")

// System returns the real clipboard. atotto shells out to
// pbcopy/xclip/xsel; on a system with none of those every call
// degrades to a clear "use --show" error.
//
// Phase 5: concealed-type support (org.nspasteboard.ConcealedType on
// macOS, so clipboard managers skip the secret) needs a native
// pasteboard helper; atotto/pbcopy cannot set it.
func System() Clipboard { return systemClipboard{} }

type systemClipboard struct{}

func (systemClipboard) Copy(text string) error {
	if clipboard.Unsupported {
		return errUnsupported
	}
	return clipboard.WriteAll(text)
}

func (systemClipboard) Read() (string, error) {
	if clipboard.Unsupported {
		return "", errUnsupported
	}
	return clipboard.ReadAll()
}
