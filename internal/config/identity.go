package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/Flexipie/coffin/internal/crypto"
	"github.com/Flexipie/coffin/internal/vault"
)

// ErrNoIdentity means identity.toml does not exist yet.
var ErrNoIdentity = errors.New(`coffin: no identity found, run "coffin init" first`)

const kdfAlgorithm = "argon2id"

// identityFile mirrors identity.toml (FORMAT.md, "Identity file").
type identityFile struct {
	FormatVersion int        `toml:"format_version"`
	PublicKey     string     `toml:"public_key"`
	KDF           kdfSection `toml:"kdf"`
	EncryptedKey  encSection `toml:"encrypted_key"`
}

type kdfSection struct {
	Algorithm   string `toml:"algorithm"`
	Time        uint32 `toml:"time"`
	MemoryKiB   uint32 `toml:"memory_kib"`
	Parallelism uint8  `toml:"parallelism"`
	Salt        string `toml:"salt"`
}

type encSection struct {
	Nonce      string `toml:"nonce"`
	Ciphertext string `toml:"ciphertext"`
}

// SaveIdentity writes the sealed identity atomically: dir 0700,
// file 0600.
func SaveIdentity(enc *crypto.EncryptedIdentity) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path, err := IdentityPath()
	if err != nil {
		return err
	}
	f := identityFile{
		FormatVersion: vault.FormatVersion,
		PublicKey:     enc.PublicKey,
		KDF: kdfSection{
			Algorithm:   kdfAlgorithm,
			Time:        enc.Params.Time,
			MemoryKiB:   enc.Params.MemoryKiB,
			Parallelism: enc.Params.Parallelism,
			Salt:        base64.StdEncoding.EncodeToString(enc.Params.Salt),
		},
		EncryptedKey: encSection{
			Nonce:      base64.StdEncoding.EncodeToString(enc.Nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(enc.Ciphertext),
		},
	}
	var buf bytes.Buffer
	e := toml.NewEncoder(&buf)
	e.Indent = ""
	if err := e.Encode(f); err != nil {
		return err
	}
	return vault.WriteFileAtomic(path, buf.Bytes())
}

// LoadIdentity reads the sealed identity. A missing file is
// ErrNoIdentity; any corruption of the crypto material surfaces as
// ErrDecrypt so this path cannot be used as an oracle.
func LoadIdentity() (*crypto.EncryptedIdentity, error) {
	path, err := IdentityPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoIdentity
		}
		return nil, err
	}
	if err := vault.CheckVersion(path, data); err != nil {
		return nil, err
	}
	var f identityFile
	if err := toml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("coffin: parse %s: %w", path, err)
	}
	// A different KDF would come with a format_version bump, so an
	// unexpected algorithm here is tampering, not a newer coffin.
	if f.KDF.Algorithm != kdfAlgorithm {
		return nil, crypto.ErrDecrypt
	}
	// public_key feeds IdentityAAD, which must be NUL-free. TOML basic
	// strings can smuggle a NUL, so a tampered key must fail here as a
	// decrypt error rather than panic in the AAD builder.
	if strings.IndexByte(f.PublicKey, 0) >= 0 {
		return nil, crypto.ErrDecrypt
	}
	salt, err := base64.StdEncoding.DecodeString(f.KDF.Salt)
	if err != nil {
		return nil, crypto.ErrDecrypt
	}
	nonce, err := base64.StdEncoding.DecodeString(f.EncryptedKey.Nonce)
	if err != nil {
		return nil, crypto.ErrDecrypt
	}
	ct, err := base64.StdEncoding.DecodeString(f.EncryptedKey.Ciphertext)
	if err != nil {
		return nil, crypto.ErrDecrypt
	}
	return &crypto.EncryptedIdentity{
		PublicKey: f.PublicKey,
		Params: crypto.KDFParams{
			Time:        f.KDF.Time,
			MemoryKiB:   f.KDF.MemoryKiB,
			Parallelism: f.KDF.Parallelism,
			Salt:        salt,
		},
		Nonce:      nonce,
		Ciphertext: ct,
	}, nil
}

// IdentityExists reports whether identity.toml is present.
func IdentityExists() (bool, error) {
	path, err := IdentityPath()
	if err != nil {
		return false, err
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
