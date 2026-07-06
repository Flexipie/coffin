package session

import (
	"testing"
	"time"

	"filippo.io/age"
)

// fakeStore is an in-memory Store; no real keychain in CI.
type fakeStore struct {
	value   string
	present bool
	deletes int
}

func (s *fakeStore) Get() (string, bool, error) { return s.value, s.present, nil }
func (s *fakeStore) Set(v string) error         { s.value, s.present = v, true; return nil }
func (s *fakeStore) Delete() error              { s.value, s.present = "", false; s.deletes++; return nil }

func testClock(t0 time.Time) (func() time.Time, *time.Time) {
	now := t0
	return func() time.Time { return now }, &now
}

func newTestIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSessionHit(t *testing.T) {
	id := newTestIdentity(t)
	store := &fakeStore{}
	clock, now := testClock(time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC))
	m := NewManager(store, 15*time.Minute, clock)

	if _, ok := m.Get(id.Recipient().String()); ok {
		t.Fatal("Get on empty store hit")
	}
	if err := m.Put(id); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(14 * time.Minute)
	got, ok := m.Get(id.Recipient().String())
	if !ok || got.String() != id.String() {
		t.Fatalf("session miss inside TTL: ok=%v", ok)
	}
}

func TestSessionExpirySelfDeletes(t *testing.T) {
	id := newTestIdentity(t)
	store := &fakeStore{}
	clock, now := testClock(time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC))
	m := NewManager(store, 15*time.Minute, clock)
	if err := m.Put(id); err != nil {
		t.Fatal(err)
	}
	// The TTL is fixed, not sliding: exactly at expiry is a miss.
	*now = now.Add(15 * time.Minute)
	if _, ok := m.Get(id.Recipient().String()); ok {
		t.Fatal("expired session hit")
	}
	if store.present || store.deletes != 1 {
		t.Fatalf("expired item not self-deleted: present=%v deletes=%d", store.present, store.deletes)
	}
}

func TestSessionPubkeyMismatch(t *testing.T) {
	id, other := newTestIdentity(t), newTestIdentity(t)
	store := &fakeStore{}
	clock, _ := testClock(time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC))
	m := NewManager(store, 15*time.Minute, clock)
	if err := m.Put(id); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Get(other.Recipient().String()); ok {
		t.Fatal("session for a different identity hit")
	}
	if store.present {
		t.Fatal("mismatched item not self-deleted")
	}
}

func TestSessionGarbageSelfDeletes(t *testing.T) {
	id := newTestIdentity(t)
	store := &fakeStore{value: "not json at all", present: true}
	clock, _ := testClock(time.Now())
	m := NewManager(store, 15*time.Minute, clock)
	if _, ok := m.Get(id.Recipient().String()); ok {
		t.Fatal("garbage session hit")
	}
	if store.present {
		t.Fatal("garbage item not self-deleted")
	}
}

func TestClearIdempotent(t *testing.T) {
	id := newTestIdentity(t)
	store := &fakeStore{}
	m := NewManager(store, 15*time.Minute, nil)
	if err := m.Put(id); err != nil {
		t.Fatal(err)
	}
	if err := m.Clear(); err != nil {
		t.Fatal(err)
	}
	if err := m.Clear(); err != nil {
		t.Fatalf("second Clear = %v, want nil", err)
	}
	if _, ok := m.Get(id.Recipient().String()); ok {
		t.Fatal("session survived Clear")
	}
}
