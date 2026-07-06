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

// System returns the real clipboard. On macOS cgo builds, writes go
// through NSPasteboard marked org.nspasteboard.ConcealedType so
// clipboard history managers skip the secret. Everywhere else (and if
// the pasteboard write ever fails) atotto shells out to
// pbcopy/xclip/xsel; on a system with none of those every call
// degrades to a clear "use --show" error.
func System() Clipboard { return systemClipboard{} }

type systemClipboard struct{}

func (systemClipboard) Copy(text string) error {
	if concealSupported && copyConcealed(text) == nil {
		return nil
	}
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
