// Package session keeps the decrypted age identity in the OS keychain
// for a fixed TTL so one master-password prompt covers a burst of
// commands. The keychain encrypts at rest, which is what satisfies the
// "no plaintext secrets on disk" rule.
package session

import (
	"errors"

	"github.com/zalando/go-keyring"
)

const (
	service = "coffin"
	account = "session"
)

// Store is the one keychain item coffin uses. The bool on Get
// distinguishes a miss from a real error.
type Store interface {
	Get() (value string, found bool, err error)
	Set(value string) error
	Delete() error
}

// SystemStore wraps the OS keychain (macOS Keychain, Secret Service,
// Windows Credential Manager) via go-keyring.
func SystemStore() Store { return systemStore{} }

type systemStore struct{}

func (systemStore) Get() (string, bool, error) {
	v, err := keyring.Get(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (systemStore) Set(value string) error {
	return keyring.Set(service, account, value)
}

func (systemStore) Delete() error {
	err := keyring.Delete(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}
