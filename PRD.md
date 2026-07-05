# PRD — Coffin

**Local-first password & secrets manager for individuals and small dev teams**

> Name: **coffin** (binary and command). The doc below still uses `vault <cmd>` in older examples; read those as `coffin <cmd>`. `PLAN.md` uses `coffin` throughout.

| | |
|---|---|
| Author | Felix |
| Status | Draft v1 |
| Date | July 2026 |
| Target | v1.0 in ~2 weeks, solo development (AI-assisted) |

---

## 1. Problem

Small dev teams (3–10 people) have no good lightweight option for sharing secrets. Hosted secret managers (Doppler, Infisical, Vault) are overkill, require accounts and infrastructure, and cost money. `.env` files get shared over Slack, go stale, and drift between machines. Personal password managers don't handle env vars or project-scoped secrets. The team at NICE tried an existing tool and it didn't work well.

Individuals have the adjacent problem: they want one local, trustworthy place for personal passwords *and* project secrets, without a cloud dependency.

## 2. Product vision

One CLI tool, one unlock, two kinds of vaults:

- **Personal vault** — local only, never leaves the machine. Passwords, accounts, anything.
- **Team vault(s)** — a git repository containing encrypted secrets. Sharing = `git push` / `git pull`. No server, no accounts, no sync service.

**The core team workflow must be this simple:**

1. One person adds/updates secrets in the team vault and pushes.
2. Everyone else runs `vault sync` (git pull under the hood).
3. They run their app with `vault run` — or `vault render` to materialize a local `.env` — and have everything.

That three-step loop is the product. Everything else supports it.

## 3. Goals & non-goals

### Goals
- Local-first: fully functional offline; no telemetry, no server, no account.
- Personal and team secrets feel seamless (one tool, one unlock, unified search) while being physically separated (different vault files/repos; personal secrets cannot end up in a team repo by accident).
- Env vars and passwords are distinct first-class entry types.
- Secure by construction using established primitives only — no hand-rolled crypto.
- Excellent CLI ergonomics; a joy to use daily.
- Honest, documented threat model.

### Non-goals (v1)
- Browser extension / autofill.
- Hosted sync server or relay (the entry format must not preclude one later).
- Mobile apps.
- GUI. (A TUI is a stretch goal, not a commitment.)
- Protecting against a compromised machine, malicious teammates, or nation-state attackers.

## 4. Users

- **Primary:** Felix — personal passwords + Laravel project env vars, daily driver.
- **Secondary:** the NICE dev team — shared project secrets, occasional shared account credentials.
- **Tertiary:** other solo devs / small teams via GitHub (portfolio audience).

## 5. Architecture overview

### 5.1 Identity & keys
- Each user has an **age-style keypair** (X25519). Public key is shareable; private key is stored locally, encrypted at rest under a key derived from the **master password** via **Argon2id**.
- Unlocking = decrypting the private key into memory for a session. One unlock opens every vault the user is a recipient of.

### 5.2 Vaults
- A vault is a directory: manifest + encrypted entry files.
- **Personal vault:** `~/.vault/personal/`, single recipient (the user), no git remote required.
- **Team vault:** any directory that is a git repo (e.g. `~/code/nice-secrets/`), multiple recipients, synced via an ordinary git remote (private GitHub repo).
- A machine can have any number of vaults; a config file registers them. Commands search all vaults by default, scoped with `--vault <name>`.

### 5.3 Encryption model (envelope, per entry)
- Every entry (or project group — see open questions) has a random symmetric **data key**.
- Entry contents are encrypted with the data key using **XChaCha20-Poly1305** (or AES-256-GCM).
- The data key is encrypted once per recipient public key and stored alongside the ciphertext.
- Adding a recipient = re-wrap data keys, commit. Removing a recipient = **generate new data keys**, re-encrypt, re-wrap for remaining recipients (never merely remove them from the recipient list — old keys live in their git history).
- Vault files carry a format version field for future migration.

### 5.4 Entry types
- **`password`** — username, password, URL, notes, optional TOTP seed (v1.1).
- **`env`** — key/value pairs, grouped into **project groups** (e.g. `nice/api-server`), with optional per-environment overlays (`dev` / `staging` / `prod`).

### 5.5 Threat model (to be documented in README)
- **Protects against:** loss/theft of the disk, casual snooping, leaking secrets via git hosting (repo contents are ciphertext), accidental `.env` commits.
- **Does not protect against:** malware on an unlocked machine, a malicious current teammate, or a revoked teammate retaining secrets they already saw (see §6.7 — rotation is the answer, and the tool assists).

## 6. Features

### 6.1 Vault & identity management — MVP
- `vault init` — create identity (keypair + master password) and personal vault.
- `vault init --team <path>` — create a team vault in a git repo.
- `vault join <repo>` — clone a team vault; prints your public key for an existing member to add.
- `vault unlock` / session handling: after one unlock, subsequent commands within a TTL (default 15 min, configurable) don't re-prompt. Implemented via a lightweight agent process or OS keychain-backed session token. Session key is never written to disk in plaintext.

### 6.2 Core entry operations — MVP
- `vault add <name>` — interactive add (type inferred or `--type env|password`).
- `vault get <name>` — fuzzy match across vaults; copies password to clipboard by default, `--show` to print.
- `vault ls [--vault <v>] [--project <p>]`
- `vault edit <name>`, `vault rm <name>`
- `vault gen [--len 24] [--no-symbols]` — password generator, copies to clipboard.

### 6.3 Team sharing — MVP
- `vault sync` — git pull + push with sane conflict guidance.
- `vault share --with <pubkey> [--project <p>]` — add recipient, re-wrap, commit.
- `vault revoke --user <name>` — remove recipient, **rotate data keys**, re-encrypt, commit, and print the rotation checklist: every secret the user could read, flagged `needs-source-rotation` until marked done.
- Recipients are named in the manifest (name ↔ pubkey), so history and audit are human-readable.

### 6.4 Dev workflow — MVP (the differentiator)
- `.vault.toml` in a project repo (committed, secret-free) declares: which vault, which project group, optional environment default.
- `vault run [-e staging] -- <command>` — injects the project's env vars into the child process. No file written. Auto-detects project via `.vault.toml`.
- `vault render [-e staging] [-o .env]` — writes a local `.env` (gitignored) for tools that need a file. Prints a warning that the file is plaintext.
- `vault diff` — compares vault project group against local `.env`, flags drift both ways.

### 6.5 Clipboard hygiene — MVP
- Auto-clear clipboard 30s after copy (configurable).
- Clear only if clipboard still holds our value (never clobber the user's later copy).
- Mark clipboard content transient/concealed where the OS supports it (macOS `org.nspasteboard.ConcealedType`, Wayland primary-selection exclusion) so it stays out of clipboard history managers.

### 6.6 Audit & history — v1.1
- `vault history <name>` / `vault blame` — formatted `git log` for team vaults.
- `vault audit` — vault health: entries pending post-revocation rotation, entries past `rotate_every`/`expires`, weak/reused passwords.
- Optional `rotate_every: 90d` / `expires:` metadata per entry.

### 6.7 Revocation semantics (documented behavior)
- Crypto-level revocation is instant for *future* changes: new data keys, seamless for remaining members (they just pull).
- Already-seen secret *values* must be rotated at the source (new API key, new DB password). The tool cannot do this but tracks it: revocation produces a checklist, `vault audit` nags until each affected entry is marked rotated.

### 6.8 TOTP — v1.1
- Store TOTP seed on password entries; `vault otp <name>` prints/copies current code. Solves the shared-account-2FA-on-one-phone problem.

### 6.9 TUI — stretch
- `vault` with no args → full-screen fuzzy finder: type to filter, `enter` copy, `tab` cycle vaults, `o` OTP. Ratatui (Rust) or Bubble Tea (Go). Primary README demo asset.

## 7. CLI experience requirements

- Colored, aligned, quiet-by-default output; `--json` on read commands for scripting.
- Helpful errors ("no `.vault.toml` found — run `vault link` to connect this repo to a project group").
- Shell completions (bash/zsh/fish) generated by the CLI framework.
- Single static binary, installable via `curl | sh`, Homebrew tap later.
- Wrong master password yields a generic decryption failure — no oracle, no timing distinction.

## 8. Tech stack

- **Language:** Go. Chosen for velocity on a 2-week timeline, age being Go-native, and the strongest TUI/prompt ecosystem. (The Rust `zeroize` argument is largely out of scope per the §5.5 threat model, which excludes malware on an unlocked machine.)
- **Crypto:** `filippo.io/age` (reference implementation) for the X25519 identity/recipient/envelope model; `golang.org/x/crypto/argon2` for the master-password KDF; `golang.org/x/crypto/chacha20poly1305` for symmetric AEAD. Established primitives only; the project must never implement a primitive.
- **CLI:** `spf13/cobra` (commands + generated bash/zsh/fish completions).
- **TUI (stretch):** Bubble Tea + Lipgloss; `charmbracelet/huh` for interactive add/edit forms.
- **Session:** `zalando/go-keyring` (macOS Keychain first; Secret Service / DPAPI later).
- **Storage:** encrypted entry files + TOML manifest in a directory; git via shelling out to system `git` (v1) rather than embedding a git library.
- **Release:** `goreleaser` for cross-platform static binaries, `curl | sh` installer, and Homebrew tap.

## 9. Milestones

| Week | Deliverable |
|---|---|
| 1, days 1–2 | Written vault format spec (agent-proofing doc); crypto core: keygen, Argon2id, envelope encrypt/decrypt round-trip with tests |
| 1, days 3–5 | Personal vault + `init/add/get/ls/gen`, session/agent, clipboard hygiene |
| 1, days 6–7 | Team vault: recipients, `share`, `sync`, `join`; `revoke` with key rotation |
| 2, days 1–3 | `vault run`, `render`, `diff`, `.vault.toml` auto-detection, env overlays |
| 2, days 4–5 | Polish: errors, completions, `--json`, README with threat model + demo GIF |
| 2, days 6–7 | Buffer / v1.1 picks (audit, TOTP) — or TUI spike |

## 10. Success criteria

- Felix uses it daily for personal passwords and at least one Laravel project within week 1.
- The NICE team's flow — one person pushes secrets, others `vault sync` + `vault run`/`render` — works end-to-end with ≥2 real users.
- A new teammate goes from zero to running the app in under 5 minutes using only the README.
- Zero plaintext secrets ever written to disk except explicit `vault render` output.
- README documents the threat model and non-goals explicitly.

## 11. Decisions & open questions

### Resolved
1. **Data-key granularity — HYBRID.** Per project group for `env` entries (fewer re-wraps, simpler sharing UX); per entry for `password` entries (finer revocation blast radius).
2. **Session mechanism — OS KEYCHAIN TOKEN.** Ephemeral session token in the OS keychain (macOS Keychain first; Secret Service / DPAPI later). No daemon lifecycle. Session key never written to disk in plaintext.

3. **Language — GO.** age is Go-native, best TUI ecosystem, best velocity; zeroize benefit out of scope per §5.5.
4. **Name — COFFIN.** Binary and command name. Free Homebrew formula name, no dominant CLI collision.

### Open
5. **Conflict UX:** two people edit the same entry and both push — surface as git conflict with guidance, or last-write-wins with a warning? v1 punts to git's own conflict flow, with a good error message and guidance.
