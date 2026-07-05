package crypto

import (
	"strings"
	"time"
)

// AAD context strings are versioned independently of format_version so
// a future AAD change is a new context, never a silent reinterpretation.
const (
	entryAADContext    = "coffin.entry.v1"
	identityAADContext = "coffin.identity.v1"
)

// EntryAAD builds the additional authenticated data bound into every
// entry payload:
//
//	"coffin.entry.v1" || 0x00 || vault_id_hex || 0x00 || type || 0x00 || canonical_path || 0x00 || RFC3339(updated_at)
//
// canonicalPath is the vault-relative path without extension, e.g.
// "passwords/github" or "env/nice/api-server/staging". updatedAt is
// truncated to second precision and rendered in UTC, matching the
// on-disk header exactly so the AAD recomputes byte-identically.
//
// This function and IdentityAAD are the only way AAD is built; callers
// never assemble the byte string themselves. Fields must be NUL-free
// (the vault layer's slug rules, hex vault id, and fixed timestamp
// format guarantee this); a NUL would make the 0x00-joined encoding
// ambiguous, so joinAAD panics on one. That is a coffin bug, never
// user input.
func EntryAAD(vaultID, entryType, canonicalPath string, updatedAt time.Time) []byte {
	ts := updatedAt.UTC().Truncate(time.Second).Format(time.RFC3339)
	return joinAAD(entryAADContext, vaultID, entryType, canonicalPath, ts)
}

// IdentityAAD builds the AAD for the encrypted identity file:
//
//	"coffin.identity.v1" || 0x00 || public_key
func IdentityAAD(publicKey string) []byte {
	return joinAAD(identityAADContext, publicKey)
}

func joinAAD(parts ...string) []byte {
	n := len(parts) - 1
	for _, p := range parts {
		if strings.IndexByte(p, 0x00) >= 0 {
			panic("coffin: AAD field contains NUL byte, encoding would be ambiguous")
		}
		n += len(p)
	}
	out := make([]byte, 0, n)
	for i, p := range parts {
		if i > 0 {
			out = append(out, 0x00)
		}
		out = append(out, p...)
	}
	return out
}
