# coffin on-disk format, version 1

This document is the contract for everything coffin writes to disk. Code
implements this spec; when they disagree, this spec wins and the code is the
bug.

## Universal rules

- Every file coffin writes is TOML with a top-level `format_version = 1`.
- All ciphertext and wrapped keys are ASCII (armored age or base64) inside
  TOML strings. No binary files, so no `.gitattributes` is needed and every
  diff is text.
- Readers MUST decode `format_version` alone before attempting a full decode.
  An unknown version is a clear, distinct error ("this vault was written by a
  newer coffin"), never a decrypt failure.
- Timestamps are RFC 3339 in UTC with second precision. Sub-second precision
  is forbidden because timestamps are bound into AAD and must recompute
  byte-identically from the serialized form.
- Writes are atomic: write to a temp file in the same directory (created
  0600), then rename over the target.
- One git commit per logical operation (add entry, rotate, add recipient).

## Vault layout

```
<vault>/
  coffin.toml                  vault manifest
  passwords/<slug>.toml        one self-contained password entry each
  env/<group...>/key.toml      the group's shared wrapped data key
  env/<group...>/<env>.toml    overlay payloads (base, dev, staging, prod, ...)
```

### coffin.toml (manifest)

```toml
format_version = 1

[vault]
id = "9f3a1c0d2b4e5f60718293a4b5c6d7e8"   # 16 random bytes, lowercase hex
name = "personal"
kind = "personal"                          # "personal" | "team"
created_at = 2026-07-06T00:00:00Z

[[recipients]]
name = "felix"
public_key = "age1..."
added_at = 2026-07-06T00:00:00Z
```

`vault.id` exists to be bound into AAD so ciphertext cannot be transplanted
between vaults (see AAD below).

### Password entry: passwords/<slug>.toml

Self-contained: its own wrapped data key plus payload.

```toml
format_version = 1
type = "password"
name = "github"
updated_at = 2026-07-06T00:00:00Z

[key]
wrapped = """
-----BEGIN AGE ENCRYPTED FILE-----
...
-----END AGE ENCRYPTED FILE-----
"""

[payload]
nonce = "base64 of 24 bytes"
ciphertext = "base64"
```

### Env group

`env/<group...>/key.toml` holds the group's single shared data key:

```toml
format_version = 1
type = "env-key"

[key]
wrapped = """..."""            # same armored age blob format as passwords
```

Each overlay file (`base.toml`, `dev.toml`, `staging.toml`, `prod.toml`, ...)
carries only a header and payload; the key lives in the sibling `key.toml`:

```toml
format_version = 1
type = "env"
name = "staging"
updated_at = 2026-07-06T00:00:00Z

[payload]
nonce = "base64 of 24 bytes"
ciphertext = "base64"
```

## Cryptography

### Wrapped data key

Each entry (or env group) has a random 32-byte data key. It is encrypted to
ALL current recipients as ONE armored age blob via a single
`age.Encrypt(w, recipients...)` call. age natively produces one stanza per
recipient inside that blob; storing N separate blobs would re-implement what
age already does and would only make remove-without-rotate easier, which is
forbidden (revocation always rotates, see below).

### AEAD

XChaCha20-Poly1305 with a fresh random 24-byte nonce per encryption, from
`crypto/rand`. The nonce is stored next to the ciphertext, base64-encoded.

### AAD (load-bearing)

Every payload encryption binds additional authenticated data:

```
"coffin.entry.v1" || 0x00 || vault_id_hex || 0x00 || type || 0x00 || canonical_path || 0x00 || RFC3339(updated_at)
```

- `vault_id_hex` is `vault.id` from the manifest.
- `type` is the entry's `type` field ("password" or "env").
- `canonical_path` is the entry's vault-relative path without extension, e.g.
  `passwords/github` or `env/nice/api-server/staging`, always with `/`
  separators.
- `updated_at` is the header timestamp, RFC 3339 UTC, second precision.

All AAD fields are NUL-free by construction (slug rules forbid NUL, the
vault id is hex, the timestamp format is fixed), so the 0x00-joined
encoding is unambiguous. The crypto core enforces this and treats a NUL
in any field as a broken invariant.

On load, the AAD is recomputed from the file's actual on-disk path plus its
header fields, never from stored AAD. This is what makes the format resistant
to file shuffling:

- Cross-entry swap: moving `prod.toml`'s payload into `staging.toml` fails
  even though both are sealed with the same group key, because
  `canonical_path` differs.
- Cross-vault transplant: same path in another vault fails because `vault.id`
  differs.
- Cross-type confusion: a password payload cannot be opened as an env payload.
- Header tampering: editing `updated_at` (or `type`) breaks authentication.

### Identity file

`~/.config/coffin/identity.toml` on Unix-likes (respecting
`$XDG_CONFIG_HOME`). Directory 0700, file 0600.

```toml
format_version = 1
public_key = "age1..."

[kdf]
algorithm = "argon2id"
time = 3
memory_kib = 262144          # 256 MiB
parallelism = 4
salt = "base64 of 16 bytes"

[encrypted_key]
nonce = "base64 of 24 bytes"
ciphertext = "base64"        # XChaCha20-Poly1305 of the AGE-SECRET-KEY-1... string
```

- The key is derived with argon2id using the parameters stored in the file,
  ALWAYS read from the file, never hardcoded on the read path. Defaults for
  new identities: time=3, memory=256 MiB, parallelism=4, fresh 16-byte salt.
- AAD: `"coffin.identity.v1" || 0x00 || public_key`. Swapping an encrypted
  key blob under a different public key fails authentication.

## Plaintext inner schemas

The decrypted payload is JSON (encrypted, so TOML-ness does not apply):

- password: `{"username": "", "password": "", "url": "", "notes": "", "totp_seed": ""}`
- env: `{"vars": [{"key": "", "value": ""}, ...]}`, an ordered array so
  round-tripping preserves the user's ordering.

## Slugs and names

- Entry slugs and env group path segments: Unicode-normalized to NFC, then
  lowercased; each segment must match `^[a-z0-9][a-z0-9._-]*$`.
- Uniqueness is case-insensitive (macOS and Windows filesystems are
  case-insensitive by default).
- Windows-reserved names (`con`, `prn`, `aux`, `nul`, `com1`..`com9`,
  `lpt1`..`lpt9`) are rejected as segments.
- Tradeoff, by design: entry names and file names are plaintext. A host that
  sees the repo (e.g. a git remote) learns entry names and change times, but
  never values, usernames, URLs, or notes.

## Error doctrine

Every decrypt failure (wrong password, non-recipient identity, tampered
ciphertext or nonce or armor, AAD mismatch, corrupt decrypted key) surfaces
as ONE generic error with no distinguishing message. No oracle: an attacker
probing a file cannot learn which layer rejected it. The single exception is
`format_version` mismatch, which is detected before any cryptography and
reported distinctly.

## Recipient operations

- **Add recipient**: rewrap only. The data key is unchanged; the wrapped blob
  is re-encrypted to the enlarged recipient set. Cheap, no payload rewrite.
- **Revoke recipient**: always rotate. Generate a new data key, re-encrypt
  every payload under it, wrap the new key to the remaining recipients. Old
  ciphertext in git history remains sealed to the old key, which the revoked
  party held; this is accepted and documented (PRD section 6.7): revocation
  protects the future, not the past.
- Rotating to zero recipients is an error.
