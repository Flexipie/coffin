# Coffin — Implementation Plan

Companion to `PRD.md`. This is the build plan: phases, deliverables, tech choices, and acceptance criteria. Timeline target: ~2 weeks, solo + AI-assisted.

## Status (2026-07-06)

- **Phase 0: done.** Repo scaffolded, cobra root + `coffin version`, CI (vet, race-enabled tests, build on ubuntu + macos), MIT license, README stub. Repo live at `github.com/Flexipie/coffin`, pushed as one commit.
- **Phase 1: done.** `docs/FORMAT.md` written and reviewed; `internal/crypto` implemented (identity gen, argon2id identity sealing, envelope wrap/unwrap, AAD construction, rewrap + rotate) with round-trip, tamper-matrix, cross-entry-swap, rewrap/rotate, golden, and fuzz tests.
- **Post-review hardening applied** before the initial push: KDF params validated on read (invalid = generic `ErrDecrypt`, no argon2 panic, memory capped at 4 GiB) and write (plain error); AAD fields rejected if they contain NUL (panic, broken invariant); `UnwrapKey` wipes wrong-length key material; CI runs `go test -race`.
- **Phase 2: done.** `internal/vault` (manifest, password entries, env groups with shared keys, list, tiered fuzzy match, hand-rendered writes so the byte shape can't drift, golden mini-vault + tamper-matrix tests), `internal/config` (XDG registry + identity.toml), `internal/session` (keychain-backed, fixed TTL, self-deleting stale items), `internal/clipboard` (copy + hash-guarded detached auto-clear via hidden `__clear-clipboard`), and the commands `init/add/get/ls/edit/rm/gen/unlock/lock`. Env CRUD included (`add --type env`, group key reuse, last-overlay cleanup). Acceptance test drives the whole flow through the real command wiring; a scripted-pty shakedown on macOS validated the real Keychain, pbcopy, and the 3s auto-clear end to end.
- **Phase 2 post-review hardening applied.** Deep review of the change set found and fixed: tampered TOML could smuggle a NUL (via the TOML unicode escape for U+0000, which BurntSushi decodes without error) into AAD construction and panic; now the entry type header is whitelisted, the manifest vault id is validated as 32 lowercase hex, and identity `public_key` is NUL-checked, all surfacing as `ErrDecrypt` (or a clear corrupt-manifest error) per the FORMAT.md error doctrine. Also fixed: `List` skips groupless env overlays and `splitGroupEnv` no longer panics on them, `unlock` reports honestly when the keychain store fails, dotenv keys are validated (`[A-Za-z_][A-Za-z0-9_]*`), and the `ErrExists` message reads correctly. All covered by new tamper/list/config/dotenv tests.
- **Phase 3: done.** `internal/git` (shell-out helpers surfacing git's own stderr), team commands (`init --team`, `join`, `share`, `revoke`, `sync`), and auto-commit wiring so every mutation on a team vault is one git commit (with a dirty-tree guard before each mutation). **Per-project sharing shipped in v1** (decided 2026-07-06, replacing the deferred-to-later plan): recipients carry an optional `projects` scope in the manifest; scoped members are only in the wrap set for env group keys under their prefixes, so they cannot decrypt passwords or other projects, enforced by encryption, not policy. Revoking a scoped member rotates only their groups (smaller blast radius); revoking a full member rotates everything; both print the `needs-source-rotation` checklist (print-only for now, persistence lands with `audit` in v1.1). Sync is pull+push, publish-only on first push, conflicts punt to git's flow with guidance. Two-user acceptance test (`internal/cli/team_accept_test.go`) drives the full loop against a local bare remote: join-before-share reads nothing, scoped share reads exactly one project, revoke locks out while the remaining member still reads.
- **Phase 4: done.** `internal/project` (`.coffin.toml` walk-up discovery with a you-are-inside-a-vault hint, parse/validate, overlay `Merge`), FORMAT.md gained the project-file and dotenv-dialect sections (spec'd before code, per doctrine), and the commands `link`, `run`, `render`, `diff`. Overlay semantics: effective set = optional `base` overlaid by the chosen env (override in place, append new, last-wins within one side); missing overlay errors listing what exists; no `-e` and no `default_env` errors (never a silent default). `run` uses os/exec with signal forwarding and propagates the child's exit code (128+sig on signal death) via a new exit-code path (`cli.ExitCode` in main); `render` writes 0600 atomic output that must round-trip through `parseDotenv` byte-identically (values with line breaks or trailing whitespace are refused, naming the key, never the value) and warns when the target is not gitignored (`git.IsIgnored`); `diff` compares the effective set against a local dotenv, prints keys only (`--values` opts in), exits 1 on drift for CI. A scoped recipient hitting an out-of-scope group gets the generic decrypt error wrapped with scope guidance (UX, not an oracle). Acceptance test `internal/cli/dev_accept_test.go` encodes the "done when" (link → run with no local file → render → diff catches intentional drift → fix confirms); unit coverage in `internal/project/project_test.go` and `internal/cli/dev_test.go` (cheap-KDF identity fixture for fast unlocks).
- **Phase 5: done (code + docs); first release tag pending.** Concealed clipboard shipped as a cgo NSPasteboard helper behind `darwin && cgo` build tags (`internal/clipboard/conceal_darwin.go`) with automatic fallback to the plain pbcopy path elsewhere; verified against the real pasteboard (marker present in `NSPasteboard.types`) via the env-guarded `TestConcealedCopyManual`. `--json` landed on `ls`, `get --show` (refused without `--show`, mutually exclusive with `--field`), and `diff` (keys-only unless `--values`, still exits 1 on drift). The helpful-errors audit found the key paths already pointing at fixes (no identity -> init, no terminal -> unlock, no project file -> link, git remote issues surface git's stderr with guidance), so no changes were needed; cobra's built-in `completion` subcommand verified for zsh. Release: `.goreleaser.yaml` (darwin cgo builds for both arches, linux CGO_ENABLED=0 static, version ldflags), tag-triggered `release.yml` on a macOS runner, and a checksum-verifying `install.sh`; a full local snapshot build produced all four artifacts. README rewritten as the real quickstart (install, personal, three-step team loop, dev workflow, scripting, security summary, non-goals; GIF placeholder per decision), and `docs/THREAT_MODEL.md` promoted from PRD 5.5. **Decisions (2026-07-06): curl|sh only, Homebrew tap deferred; GIF placeholder.**
- **To ship v0.1.0:** push a `v*` tag; the release workflow does the rest. The README's `curl | sh` and `go install` paths only work after that first release exists. Manual macOS shakedown of `coffin run` Ctrl-C feel still pending (tests can't capture it).

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

Conflict UX resolved in Phase 3 as planned: `sync` punts to git's own conflict flow with guidance messaging. Per-entry files mean two people editing different entries never conflict at all.

## Dependencies

Approved and in use (Phase 0/1/2):

- `filippo.io/age`
- `golang.org/x/crypto` (argon2, chacha20poly1305)
- `golang.org/x/term` (hidden prompts)
- `github.com/spf13/cobra`
- `github.com/BurntSushi/toml` (decode side; entry files are hand-rendered on write)
- `github.com/zalando/go-keyring`
- `github.com/atotto/clipboard` (baseline copy; concealed-clipboard is custom — see Risks)

Still to approve before their phase (flagging per repo policy, confirm before `go get`):

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

## Phase 0 — Scaffolding (0.5 day) ✅ DONE

**Goal:** compiling skeleton, CI, one working command.

- `go mod init`, cobra root command, `coffin version`.
- GitHub Actions: `go test -race ./...` + `go vet` + build on push (ubuntu + macos matrix).
- `.gitignore`, MIT license, README stub.

**Done when:** `go build` produces a `coffin` binary; `coffin version` prints; CI green. ✅

---

## Phase 1 — Format spec + crypto core (Days 1–2) ✅ DONE

**Goal:** the security foundation, fully tested, before any UX is built.

1. **Write `docs/FORMAT.md`** — the on-disk vault format. Directory layout, manifest schema (recipients as name↔pubkey, format version), per-entry file layout, how data keys are wrapped per recipient, hybrid granularity rules (env group key vs per-password key). This doc is the contract; everything downstream implements it.
2. **`internal/crypto`** — thin wrapper over age/x-crypto:
   - X25519 keypair generation.
   - Master password → Argon2id → key that encrypts the private key at rest.
   - Envelope: random data key, AEAD-encrypt payload, wrap data key per recipient pubkey.
   - Decrypt path: generic failure on wrong password (no oracle, no timing tell).
3. **Tests:** encrypt→decrypt round-trip; wrong-password fails cleanly; add/remove recipient re-wrap; tamper detection (AEAD auth failure); rotation produces new data keys.

**Done when:** `go test ./internal/crypto/...` passes including round-trip, tamper, and re-wrap/rotation cases; `FORMAT.md` reviewed. ✅

Delivered beyond the letter of the phase: golden-file tests pinning the on-disk byte layout, fuzz targets (`FuzzOpen` among them), and the post-review hardening listed in Status (KDF param validation, NUL-free AAD enforcement, key wipe on the wrong-length unwrap path).

---

## Phase 2 — Personal vault + core commands (Days 3–5) ✅ DONE

**Goal:** Coffin usable daily for personal passwords, offline.

- `internal/vault` load/save against `FORMAT.md`; `internal/config` vault registry.
- `internal/session` keychain-backed unlock, default 15-min TTL, configurable; session key never on disk in plaintext.
- `internal/clipboard` copy + auto-clear after 30s (only if clipboard still holds our value).
- Commands: `init`, `add` (`--type env|password`), `get` (fuzzy, clipboard by default, `--show`), `ls`, `edit`, `rm`, `gen`, `unlock`, `lock`.

**Done when:** Felix can `init`, add a password, `get` it (auto-clears), regenerate, all within one unlock. Real daily-driver test starts here. ✅ (encoded as `internal/cli/accept_test.go`; macOS keychain/pbcopy/auto-clear validated with a scripted pty shakedown)

---

## Phase 3 — Team vault: sharing, sync, revocation (Days 6–7) ✅ DONE

**Goal:** the three-step team loop works end to end.

- `internal/git` shell-out helpers with clear error surfacing.
- `init --team <path>`, `join <repo>` (clones, prints your pubkey).
- `share --with <pubkey> --name <n> [--project <p>]...` — add recipient (optionally scoped to env project prefixes), re-wrap in-scope keys, commit.
- `revoke --user <name>` — rotate data keys the revoked member could read, re-encrypt, re-wrap for remaining, commit, print `needs-source-rotation` checklist.
- `sync` — git pull + push with conflict guidance (punt to git's flow, good messaging).

**Done when:** person A pushes a team vault, person B `join`s + `sync`s + reads it; `revoke` rotates keys and B can still read while the revoked key cannot. ✅ (encoded as `internal/cli/team_accept_test.go`, plus scoped-recipient unit coverage in `internal/vault/recipients_test.go`)

Delivered beyond the letter of the phase: per-project sharing (scoped recipients, spec'd in FORMAT.md "Recipient scope") rather than vault-wide-only, scope-aware revocation blast radius, and auto-commit on `add`/`edit`/`rm` for team vaults per FORMAT.md's one-commit-per-operation rule.

---

## Phase 4 — Dev workflow, the differentiator (Week 2, Days 1–3) ✅ DONE

**Goal:** `coffin run` / `render` replace hand-shared `.env` files.

- `.coffin.toml` discovery (walk up from cwd): declares vault, project group, default env. Committed, secret-free.
- `run [-e staging] -- <cmd>` — inject env vars into child process, nothing written.
- `render [-e staging] [-o .env]` — write gitignored `.env` with a plaintext warning.
- `diff` — compare vault project group vs local `.env`, flag drift both directions.
- Env overlays: `dev`/`staging`/`prod` merge semantics defined and tested.

**Done when:** a real Laravel project runs via `coffin run` with no local secrets file; `render` produces a working `.env`; `diff` catches an intentional drift. ✅ (encoded as `internal/cli/dev_accept_test.go`; the real-project run on macOS is the pending manual shakedown noted in Status)

Delivered beyond the letter of the phase: the `link` command (the PRD's Phase-5 error copy references it, so it shipped with the files it creates), exit-code plumbing so `run` propagates the child's status and `diff` exits 1 for CI, the dotenv round-trip guarantee spec'd in FORMAT.md, and the gitignore warning on `render`.

---

## Phase 5 — Polish & ship (Week 2, Days 4–5) ✅ DONE (tag pending)

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

1. **Concealed clipboard on macOS** — resolved in Phase 5: cgo NSPasteboard helper behind `darwin && cgo` tags, plain copy + auto-clear everywhere else. The release pipeline builds darwin with cgo on a macOS runner so shipped binaries have it; `go install` without cgo silently gets the fallback.
2. **Keychain UX across machines** — `go-keyring` on macOS may prompt for keychain access; validate the unlock flow feels smooth in Phase 2.
3. **Rotation correctness** — the revoke→rotate path is the highest-stakes code. Heavy test coverage in Phase 1/3; a subtle bug here leaks access.
4. **Git conflict ergonomics** — punting to git is fine only if messaging is genuinely helpful; revisit if real team use hits friction.

## Suggested milestone ordering vs PRD §9

Matches the PRD week-by-week milestones, with Phase 0 scaffolding prepended and the format spec pulled to the very front of Phase 1 (it's the contract the AI-assisted work reads against).
