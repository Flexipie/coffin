package vault

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// FormatVersion is the on-disk format version this coffin reads and
// writes (docs/FORMAT.md).
const FormatVersion = 1

// WriteFileAtomic writes data to path atomically: a temp file in the
// same directory, chmod 0600 before any content is written, fsync,
// then rename over the target.
func WriteFileAtomic(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".coffin-tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// decodeTOML is toml.Unmarshal with the path in the error.
func decodeTOML(path string, data []byte, v any) error {
	if err := toml.Unmarshal(data, v); err != nil {
		return fmt.Errorf("coffin: parse %s: %w", path, err)
	}
	return nil
}

// CheckVersion decodes only format_version out of data and rejects
// anything but FormatVersion. Callers MUST run this before a full
// decode of any coffin file (FORMAT.md, "Universal rules").
func CheckVersion(path string, data []byte) error {
	var v struct {
		FormatVersion *int `toml:"format_version"`
	}
	if err := toml.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("coffin: parse %s: %w", path, err)
	}
	if v.FormatVersion == nil {
		return fmt.Errorf("coffin: %s is missing format_version", path)
	}
	if *v.FormatVersion != FormatVersion {
		return &UnknownVersionError{Path: path, Version: *v.FormatVersion}
	}
	return nil
}
