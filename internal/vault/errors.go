package vault

import (
	"errors"
	"fmt"
)

var (
	// ErrNotFound is returned when an entry (or env group) does not exist.
	ErrNotFound = errors.New("coffin: entry not found")
	// ErrExists is returned when creating something that already exists.
	ErrExists = errors.New("coffin: already exists")
)

// UnknownVersionError is returned when a file's format_version is not
// one this coffin understands. It is detected before any cryptography
// and must never be conflated with a decrypt failure (FORMAT.md,
// "Error doctrine").
type UnknownVersionError struct {
	Path    string
	Version int
}

func (e *UnknownVersionError) Error() string {
	return fmt.Sprintf("coffin: %s has format_version %d; this coffin only understands version %d (written by a newer coffin?)",
		e.Path, e.Version, FormatVersion)
}
