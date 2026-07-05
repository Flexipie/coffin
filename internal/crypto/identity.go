package crypto

import (
	"crypto/rand"
	"errors"

	"filippo.io/age"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// KDF defaults for newly created identities. Read paths always use the
// parameters stored in the identity file, never these constants.
const (
	defaultKDFTime        = 3
	defaultKDFMemoryKiB   = 256 * 1024
	defaultKDFParallelism = 4
	kdfSaltSize           = 16
	// maxKDFMemoryKiB caps stored memory at 4 GiB. A tampered identity
	// file could otherwise demand up to 4 TiB and OOM the process on
	// unlock.
	maxKDFMemoryKiB = 4 * 1024 * 1024
)

// KDFParams are the argon2id parameters used to derive the identity
// encryption key from the user's password.
type KDFParams struct {
	Time        uint32
	MemoryKiB   uint32
	Parallelism uint8
	Salt        []byte
}

// NewKDFParams returns the default parameters with a fresh random salt.
func NewKDFParams() (KDFParams, error) {
	salt := make([]byte, kdfSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return KDFParams{}, err
	}
	return KDFParams{
		Time:        defaultKDFTime,
		MemoryKiB:   defaultKDFMemoryKiB,
		Parallelism: defaultKDFParallelism,
		Salt:        salt,
	}, nil
}

// validate rejects parameter combinations argon2.IDKey would panic on
// (Time or Parallelism below 1), a missing salt, and memory values
// large enough to be an allocation attack from a tampered file.
func (p KDFParams) validate() error {
	if p.Time < 1 || p.Parallelism < 1 || len(p.Salt) == 0 || p.MemoryKiB > maxKDFMemoryKiB {
		return errors.New("coffin: invalid kdf parameters")
	}
	return nil
}

// EncryptedIdentity is a sealed age identity together with everything
// needed to open it again except the password.
type EncryptedIdentity struct {
	PublicKey  string
	Params     KDFParams
	Nonce      []byte
	Ciphertext []byte
}

// GenerateIdentity creates a new age X25519 identity.
func GenerateIdentity() (*age.X25519Identity, error) {
	return age.GenerateX25519Identity()
}

// ParseRecipient parses an "age1..." public key.
func ParseRecipient(publicKey string) (*age.X25519Recipient, error) {
	return age.ParseX25519Recipient(publicKey)
}

// SealIdentity encrypts the identity's secret key string under a key
// derived from password with params. The AAD binds the public key so
// the blob cannot be re-homed under a different identity file.
func SealIdentity(id *age.X25519Identity, password []byte, params KDFParams) (*EncryptedIdentity, error) {
	// Write path: a descriptive error is fine, the oracle doctrine only
	// covers decrypt failures.
	if err := params.validate(); err != nil {
		return nil, err
	}
	key := deriveKey(password, params)
	defer wipe(key)
	secret := []byte(id.String())
	defer wipe(secret)
	pub := id.Recipient().String()
	nonce, ct, err := Seal(key, secret, IdentityAAD(pub))
	if err != nil {
		return nil, err
	}
	return &EncryptedIdentity{
		PublicKey:  pub,
		Params:     params,
		Nonce:      nonce,
		Ciphertext: ct,
	}, nil
}

// OpenIdentity decrypts a sealed identity with the given password.
// Every failure mode returns ErrDecrypt.
func OpenIdentity(enc *EncryptedIdentity, password []byte) (*age.X25519Identity, error) {
	// Invalid stored params mean a corrupt or tampered identity file;
	// that must stay indistinguishable from any other decrypt failure.
	if err := enc.Params.validate(); err != nil {
		return nil, ErrDecrypt
	}
	key := deriveKey(password, enc.Params)
	defer wipe(key)
	secret, err := Open(key, enc.Nonce, enc.Ciphertext, IdentityAAD(enc.PublicKey))
	if err != nil {
		return nil, ErrDecrypt
	}
	defer wipe(secret)
	id, err := age.ParseX25519Identity(string(secret))
	if err != nil {
		return nil, ErrDecrypt
	}
	return id, nil
}

func deriveKey(password []byte, p KDFParams) []byte {
	return argon2.IDKey(password, p.Salt, p.Time, p.MemoryKiB, p.Parallelism, chacha20poly1305.KeySize)
}
