package crypto

import (
	"bytes"
	"testing"
	"time"

	"filippo.io/age"
)

// Fixed key for fuzzing only; fuzz corpora must be reproducible across
// runs, so nothing here may come from crypto/rand at F-setup time
// except values baked into the seed corpus below.
var fuzzKey = bytes.Repeat([]byte{0x42}, DataKeySize)

func FuzzOpen(f *testing.F) {
	aad := EntryAAD("9f3a", "password", "passwords/github", time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC))
	nonce, ct, err := Seal(fuzzKey, []byte("seed plaintext"), aad)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(nonce, ct, aad)
	f.Add([]byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, nonce, ct, aad []byte) {
		// Must never panic; failures must be the one generic error.
		if _, err := Open(fuzzKey, nonce, ct, aad); err != nil && err != ErrDecrypt {
			t.Fatalf("non-generic error: %v", err)
		}
	})
}

func FuzzUnwrapKey(f *testing.F) {
	id, err := GenerateIdentity()
	if err != nil {
		f.Fatal(err)
	}
	wrapped, err := WrapKey(fuzzKey, []age.Recipient{id.Recipient()})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wrapped)
	f.Add("")
	f.Add("-----BEGIN AGE ENCRYPTED FILE-----\n-----END AGE ENCRYPTED FILE-----\n")

	f.Fuzz(func(t *testing.T, wrapped string) {
		if _, err := UnwrapKey(wrapped, id); err != nil && err != ErrDecrypt {
			t.Fatalf("non-generic error: %v", err)
		}
	})
}
