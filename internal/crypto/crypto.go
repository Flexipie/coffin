// Package crypto implements coffin's cryptographic core: age identity
// handling, password-based identity encryption, data-key envelopes
// (XChaCha20-Poly1305), and AAD construction. It is stateless and has
// no filesystem access; callers hand it bytes and get bytes back.
//
// Zeroization of key material is best-effort only. Go's runtime may
// retain copies of buffers (GC, stack growth), so wiping is hygiene,
// not a guarantee. The threat model excludes an attacker with access
// to a compromised, unlocked machine.
package crypto

import "errors"

// ErrDecrypt is returned for every decrypt, unwrap, or unlock failure.
// All causes (wrong password, non-recipient identity, tampered
// ciphertext, AAD mismatch, corrupt key material) are deliberately
// indistinguishable so this package cannot be used as an oracle.
var ErrDecrypt = errors.New("coffin: decryption failed")

// wipe zeroes b. Best-effort, see the package comment.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
