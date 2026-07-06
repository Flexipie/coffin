# coffin threat model

Honest and specific: what coffin defends against, what it deliberately
does not, and the design decisions that back each claim. Format
details live in [FORMAT.md](FORMAT.md).

## What coffin protects against

**Loss or theft of the disk.** Every secret on disk is
XChaCha20-Poly1305 ciphertext under a random per-entry (or per-group)
data key, wrapped with age X25519 to each recipient. The master
identity is sealed with a key derived from your master password via
argon2id (256 MiB, time 3 by default). Nothing usable leaves the
process without a successful unlock.

**A git host that sees the repo.** A team vault syncs through any git
remote; the remote only ever holds ciphertext, armored age blobs, and
plaintext *names*. GitHub (or a laptop backup, or a leaked tarball)
learns which entries exist and when they changed, never their
contents. This metadata tradeoff is deliberate and documented in
FORMAT.md ("Slugs and names").

**Accidental `.env` commits.** The dev workflow exists to make the
safe path the easy one: `coffin run` injects env vars into the child
process and writes nothing. Plaintext only ever reaches disk through
an explicit `coffin render`, which warns, chmods 0600, and complains
when the output is not gitignored.

**A revoked teammate, going forward.** `coffin revoke` always rotates
the data keys the revoked member could read, re-encrypts those
payloads, and rewraps to the remaining members. Removing someone from
the recipient list without rotating is not an operation coffin has.

**A scoped teammate reading beyond their scope.** Per-project sharing
is enforced by encryption, not policy: a scoped recipient's identity
is simply absent from the wrap set of out-of-scope keys, so there is
nothing their key can decrypt.

**File shuffling and tampering.** Every payload binds AAD (vault id,
entry type, canonical path, timestamp), so ciphertext cannot be moved
between entries, vaults, or types without breaking authentication.
All decrypt failures surface as one generic error; a probe cannot
learn which layer rejected it.

**Clipboard history managers (macOS).** Copies are marked
`org.nspasteboard.ConcealedType` (on cgo builds), so well-behaved
clipboard managers skip them, and coffin auto-clears the clipboard
after 30 seconds if it still holds the copied value.

## What coffin does not protect against

**Malware on an unlocked machine.** Once you unlock, the session key
sits in the OS keychain until the TTL (default 15 minutes) expires,
and decrypted secrets pass through process memory, the clipboard, and
child-process environments. A keylogger or a hostile process running
as you wins. This is out of scope, as it is for every tool in this
class.

**A malicious *current* teammate.** Anyone in the wrap set can
decrypt what they were given and exfiltrate it. Cryptography cannot
revoke trust you actively extended.

**A revoked teammate's memory of the past.** Old ciphertext in git
history stays sealed under keys the revoked member held. Rotation
protects the future, not the past; that is why `revoke` prints the
`needs-source-rotation` checklist telling you which *source* secrets
(API keys, database passwords) to rotate at their origin.

**What you do with `render` output.** A rendered `.env` is plaintext
by request. It is 0600 and warned about, but from that point its
safety is yours.

**Nation-state attackers, side channels, hardware attacks.**
Non-goals (PRD section 3).

## Design commitments backing this

- Established primitives only, no hand-rolled crypto:
  `filippo.io/age`, `x/crypto/argon2`, `x/crypto/chacha20poly1305`.
- One generic decrypt error, no oracle (FORMAT.md "Error doctrine").
- KDF parameters are validated on read; a tampered identity file
  cannot trigger an allocation attack or an argon2 panic.
- Atomic 0600 writes everywhere; secrets never touch a temp file with
  looser permissions.
- Sessions live only in the OS keychain, never on disk in plaintext,
  and expire on a fixed (non-sliding) TTL.
- Personal and team vaults are structurally separate registries;
  a personal entry cannot end up in a team repo by accident.
