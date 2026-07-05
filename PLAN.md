# Coffin — Implementation Plan

Companion to `PRD.md`. This is the build plan: phases, deliverables, tech choices, and acceptance criteria. Timeline target: ~2 weeks, solo + AI-assisted.

## Locked decisions

| Decision | Choice |
|---|---|
| Language | Go |
| Name / binary | `coffin` |
| Crypto | `filippo.io/age` (X25519 identity + envelope), `x/crypto/argon2` (KDF), `x/crypto/chacha20poly1305` (AEAD) |
| CLI | `spf13/cobra` |
| TUI (stretch) | Bubble Tea + Lipgloss + `charmbracelet/huh` |
| Session | `zalando/go-keyring` (macOS Keychain first) |
| Data-key granularity | Hybrid: per project group for `env`, per entry for `password` |
| Git | shell out to system `git` |
| Release | `goreleaser` (binaries, `curl \| sh`, Homebrew tap) |

Still open: conflict UX (v1 punts to git's own conflict flow with good messaging).

## Dependencies to approve before Phase 1

These are the external modules the plan assumes. Flagging per repo policy — confirm before I `go get` them:

- `filippo.io/age`
- `golang.org/x/crypto` (argon2, chacha20poly1305)
- `github.com/spf13/cobra`
- `github.com/BurntSushi/toml` (manifest + `.coffin.toml`)
- `github.com/zalando/go-keyring`
- `github.com/atotto/clipboard` (baseline copy; concealed-clipboard is custom — see Risks)
- TUI only (Phase 6+): `github.com/charmbracelet/bubbletea`, `lipgloss`, `huh`

## Proposed repo layout

```
coffin/
  cmd/coffin/main.go          # entrypoint, wires cobra
  internal/
    cli/                      # cobra command definitions (one file per command)
    crypto/                   # keygen, KDF, envelope encrypt/decrypt (thin wrapper over age)
    vault/                    # vault model: manifest, entries, load/save, format versioning
    session/                  # keychain-backed unlock session + TTL
    clipboard/                # copy + auto-clear + concealed-type handling
    git/                      # shell-out git helpers (pull/push/commit/status)
    project/                  # .coffin.toml discovery + env overlay resolution
    config/                   # ~/.config/coffin registry of vaults
  docs/
    FORMAT.md                 # vault-on-disk format spec (the agent-proofing doc)
    THREAT_MODEL.md           # promoted from README section
  testdata/
  .goreleaser.yaml
```

---

## Phase 0 — Scaffolding (0.5 day)

**Goal:** compiling skeleton, CI, one working command.

- `go mod init`, cobra root command, `coffin version`.
- GitHub Actions: `go test ./...` + `go vet` + build on push.
- `.gitignore`, MIT license, README stub.

**Done when:** `go build` produces a `coffin` binary; `coffin version` prints; CI green.

---

## Phase 1 — Format spec + crypto core (Days 1–2)

**Goal:** the security foundation, fully tested, before any UX is built.

1. **Write `docs/FORMAT.md`** — the on-disk vault format. Directory layout, manifest schema (recipients as name↔pubkey, format version), per-entry file layout, how data keys are wrapped per recipient, hybrid granularity rules (env group key vs per-password key). This doc is the contract; everything downstream implements it.
2. **`internal/crypto`** — thin wrapper over age/x-crypto:
   - X25519 keypair generation.
   - Master password → Argon2id → key that encrypts the private key at rest.
   - Envelope: random data key, AEAD-encrypt payload, wrap data key per recipient pubkey.
   - Decrypt path: generic failure on wrong password (no oracle, no timing tell).
3. **Tests:** encrypt→decrypt round-trip; wrong-password fails cleanly; add/remove recipient re-wrap; tamper detection (AEAD auth failure); rotation produces new data keys.

**Done when:** `go test ./internal/crypto/...` passes including round-trip, tamper, and re-wrap/rotation cases; `FORMAT.md` reviewed.

---

## Phase 2 — Personal vault + core commands (Days 3–5)

**Goal:** Coffin usable daily for personal passwords, offline.

- `internal/vault` load/save against `FORMAT.md`; `internal/config` vault registry.
- `internal/session` keychain-backed unlock, default 15-min TTL, configurable; session key never on disk in plaintext.
- `internal/clipboard` copy + auto-clear after 30s (only if clipboard still holds our value).
- Commands: `init`, `add` (`--type env|password`), `get` (fuzzy, clipboard by default, `--show`), `ls`, `edit`, `rm`, `gen`, `unlock`, `lock`.

**Done when:** Felix can `init`, add a password, `get` it (auto-clears), regenerate, all within one unlock. Real daily-driver test starts here.

---

## Phase 3 — Team vault: sharing, sync, revocation (Days 6–7)

**Goal:** the three-step team loop works end to end.

- `internal/git` shell-out helpers with clear error surfacing.
- `init --team <path>`, `join <repo>` (clones, prints your pubkey).
- `share --with <pubkey> [--project <p>]` — add recipient, re-wrap, commit.
- `revoke --user <name>` — rotate data keys, re-encrypt, re-wrap for remaining, commit, print `needs-source-rotation` checklist.
- `sync` — git pull + push with conflict guidance (punt to git's flow, good messaging).

**Done when:** person A pushes a team vault, person B `join`s + `sync`s + reads it; `revoke` rotates keys and B can still read while the revoked key cannot.

---

## Phase 4 — Dev workflow, the differentiator (Week 2, Days 1–3)

**Goal:** `coffin run` / `render` replace hand-shared `.env` files.

- `.coffin.toml` discovery (walk up from cwd): declares vault, project group, default env. Committed, secret-free.
- `run [-e staging] -- <cmd>` — inject env vars into child process, nothing written.
- `render [-e staging] [-o .env]` — write gitignored `.env` with a plaintext warning.
- `diff` — compare vault project group vs local `.env`, flag drift both directions.
- Env overlays: `dev`/`staging`/`prod` merge semantics defined and tested.

**Done when:** a real Laravel project runs via `coffin run` with no local secrets file; `render` produces a working `.env`; `diff` catches an intentional drift.

---

## Phase 5 — Polish & ship (Week 2, Days 4–5)

**Goal:** shippable, installable, documented.

- Helpful errors (missing `.coffin.toml`, not unlocked, git remote issues).
- `--json` on read commands; shell completions via cobra.
- Concealed-clipboard handling (macOS `org.nspasteboard.ConcealedType`).
- `goreleaser`: static binaries, `curl | sh`, Homebrew tap.
- README: quickstart, the three-step team loop, `THREAT_MODEL.md`, non-goals, demo GIF.

**Done when:** a new teammate goes zero→running in <5 min from README only; threat model documented.

---

## Phase 6 — Buffer / v1.1 / TUI spike (Week 2, Days 6–7)

Pick based on what shipped. Candidates:
- **Audit:** `audit` (pending rotations, expired/`rotate_every`, weak/reused), `history`/`blame`.
- **TOTP:** seed on password entries, `otp <name>`.
- **TUI:** `coffin` with no args → Bubble Tea fuzzy finder (filter, enter=copy, tab=cycle vaults, o=OTP). Primary demo asset.

---

## Cross-cutting

- **Never** write plaintext secrets to disk except explicit `render` output.
- Format version field checked on every load; unknown version = clear error, not a crash.
- Personal vs team separation enforced structurally (registry marks vault kind; personal entries cannot be committed to a team repo).
- Every command usable offline except `sync`/`join`.

## Risks & unknowns

1. **Concealed clipboard on macOS** — `atotto/clipboard` shells to `pbcopy` and can't set `org.nspasteboard.ConcealedType`. Likely needs a small cgo/NSPasteboard helper or a bundled tool. Spike early in Phase 5; fall back to plain copy + auto-clear if it slips.
2. **Keychain UX across machines** — `go-keyring` on macOS may prompt for keychain access; validate the unlock flow feels smooth in Phase 2.
3. **Rotation correctness** — the revoke→rotate path is the highest-stakes code. Heavy test coverage in Phase 1/3; a subtle bug here leaks access.
4. **Git conflict ergonomics** — punting to git is fine only if messaging is genuinely helpful; revisit if real team use hits friction.

## Suggested milestone ordering vs PRD §9

Matches the PRD week-by-week milestones, with Phase 0 scaffolding prepended and the format spec pulled to the very front of Phase 1 (it's the contract the AI-assisted work reads against).
