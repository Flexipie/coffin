package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/crypto/chacha20poly1305"
)

// DataKeySize is the size of an entry data key in bytes.
const DataKeySize = chacha20poly1305.KeySize

var errNoRecipients = errors.New("coffin: refusing to wrap key to zero recipients")

// NewDataKey returns a fresh random 32-byte data key.
func NewDataKey() ([]byte, error) {
	k := make([]byte, DataKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// WrapKey encrypts dataKey to all recipients as one armored age blob.
// age produces one stanza per recipient inside the blob, so a single
// blob covers the whole recipient set. Wrapping to zero recipients is
// an error.
func WrapKey(dataKey []byte, recipients []age.Recipient) (string, error) {
	if len(recipients) == 0 {
		return "", errNoRecipients
	}
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recipients...)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(dataKey); err != nil {
		return "", err
	}
	// Both writers buffer; Close flushes. Order matters: the age
	// writer must close before the armor writer that wraps it.
	if err := w.Close(); err != nil {
		return "", err
	}
	if err := aw.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// UnwrapKey decrypts an armored wrapped key with identity. Every
// failure (no matching recipient stanza, bad armor, truncation, wrong
// length after decrypt) returns ErrDecrypt.
func UnwrapKey(wrapped string, identity age.Identity) ([]byte, error) {
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(wrapped)), identity)
	if err != nil {
		return nil, ErrDecrypt
	}
	dataKey, err := io.ReadAll(r)
	if err != nil || len(dataKey) != DataKeySize {
		wipe(dataKey)
		return nil, ErrDecrypt
	}
	return dataKey, nil
}

// Seal encrypts plaintext with XChaCha20-Poly1305 under dataKey,
// binding aad. The nonce is fresh random per call, never reused or
// derived.
func Seal(dataKey, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open decrypts a Seal output. Every failure returns ErrDecrypt.
func Open(dataKey, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, ErrDecrypt
	}
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, ErrDecrypt
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// Rewrap re-encrypts a wrapped data key to a new recipient set without
// changing the key. This is the add-recipient path only; revocation
// must go through Rotate.
func Rewrap(wrapped string, identity age.Identity, newRecipients []age.Recipient) (string, error) {
	dataKey, err := UnwrapKey(wrapped, identity)
	if err != nil {
		return "", err
	}
	defer wipe(dataKey)
	return WrapKey(dataKey, newRecipients)
}

// Payload is a plaintext and the AAD to bind when it is re-encrypted.
type Payload struct {
	Plaintext []byte
	AAD       []byte
}

// Sealed is the encrypted form of a Payload.
type Sealed struct {
	Nonce      []byte
	Ciphertext []byte
}

// Rotate is the revoke path: it generates a fresh data key, seals every
// payload under it, and wraps the new key to the remaining recipients.
// The new key never leaves this function. Rotating to zero recipients
// is an error.
func Rotate(payloads []Payload, recipients []age.Recipient) (string, []Sealed, error) {
	if len(recipients) == 0 {
		return "", nil, errNoRecipients
	}
	dataKey, err := NewDataKey()
	if err != nil {
		return "", nil, err
	}
	defer wipe(dataKey)
	wrapped, err := WrapKey(dataKey, recipients)
	if err != nil {
		return "", nil, err
	}
	sealed := make([]Sealed, len(payloads))
	for i, p := range payloads {
		nonce, ct, err := Seal(dataKey, p.Plaintext, p.AAD)
		if err != nil {
			return "", nil, err
		}
		sealed[i] = Sealed{Nonce: nonce, Ciphertext: ct}
	}
	return wrapped, sealed, nil
}
