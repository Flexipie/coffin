package session

import (
	"encoding/json"
	"time"

	"filippo.io/age"
)

// sessionPayload is the JSON value of the keychain item. SecretKey is
// the decrypted AGE-SECRET-KEY string.
type sessionPayload struct {
	PublicKey string    `json:"public_key"`
	SecretKey string    `json:"secret_key"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Manager reads and writes the unlock session.
type Manager struct {
	store Store
	ttl   time.Duration
	now   func() time.Time
}

// NewManager builds a Manager; a nil now means time.Now.
func NewManager(store Store, ttl time.Duration, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{store: store, ttl: ttl, now: now}
}

// Get returns the cached identity if the session is valid for
// publicKey. Garbage, a public-key mismatch, and expiry all count as
// misses and lazily delete the stale item; store errors are also just
// misses, because the session is an optimization, never a requirement.
func (m *Manager) Get(publicKey string) (*age.X25519Identity, bool) {
	raw, found, err := m.store.Get()
	if err != nil || !found {
		return nil, false
	}
	var p sessionPayload
	if json.Unmarshal([]byte(raw), &p) != nil {
		m.store.Delete()
		return nil, false
	}
	if p.PublicKey != publicKey || !m.now().Before(p.ExpiresAt) {
		m.store.Delete()
		return nil, false
	}
	id, err := age.ParseX25519Identity(p.SecretKey)
	if err != nil || id.Recipient().String() != publicKey {
		m.store.Delete()
		return nil, false
	}
	return id, true
}

// Put stores id with a fixed (not sliding) expiry of now + ttl.
func (m *Manager) Put(id *age.X25519Identity) error {
	raw, err := json.Marshal(sessionPayload{
		PublicKey: id.Recipient().String(),
		SecretKey: id.String(),
		ExpiresAt: m.now().Add(m.ttl),
	})
	if err != nil {
		return err
	}
	return m.store.Set(string(raw))
}

// Clear drops the session; clearing an absent session is not an error.
func (m *Manager) Clear() error {
	return m.store.Delete()
}
