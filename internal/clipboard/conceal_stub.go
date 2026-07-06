//go:build !darwin || !cgo

package clipboard

import "errors"

const concealSupported = false

// copyConcealed is unavailable off macOS (and in cgo-disabled builds);
// System falls back to the plain copy path.
func copyConcealed(string) error {
	return errors.New("coffin: concealed clipboard not supported on this build")
}
