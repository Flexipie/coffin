# coffin

A local-first password and secrets manager for developers and small
teams. Your secrets live in a git repo as encrypted TOML files;
nothing ever leaves your machines unencrypted. No server, no account,
no telemetry.

> Demo GIF coming soon.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/Flexipie/coffin/main/install.sh | sh
```

Or with Go:

```sh
go install github.com/Flexipie/coffin/cmd/coffin@latest
```

(The `go install` build skips the macOS concealed-clipboard helper
unless cgo is enabled; the release binaries include it.)

Shell completions: `coffin completion zsh --help` explains setup for
zsh, bash, and fish.

## Quickstart (personal vault)

```sh
coffin init                 # keypair + master password + vault
coffin add github           # interactive add
coffin get github           # fuzzy match, copies, auto-clears in 30s
coffin get github --show    # print instead
coffin gen --len 32         # password generator
coffin ls
```

One unlock covers 15 minutes of commands (configurable); the session
key lives in the OS keychain, never on disk.

## Team vault in three steps

Share secrets through any git remote, including a private GitHub repo:

```sh
# 1. One person creates and pushes the vault
coffin init --team ~/team-vault
git -C ~/team-vault remote add origin git@github.com:you/team-vault.git
coffin sync

# 2. A teammate joins and sends you their public key
coffin join git@github.com:you/team-vault.git

# 3. You add them; they sync and read
coffin share --with age1... --name bob
coffin sync         # both sides
```

Every mutation is one git commit; `coffin sync` is pull + push, and
conflicts fall back to git's own flow with guidance.

Scope someone to a single project with
`coffin share --with age1... --name bob --project myapp`: their key is
only in the wrap set for that project's env groups, so everything else
is unreadable to them by encryption, not policy. `coffin revoke --user
bob` rotates every key bob could read and prints which source secrets
to rotate at their origin.

## The dev workflow (replaces shared .env files)

Store per-project env vars in the vault as overlays (`base`, `dev`,
`staging`, `prod`, ...), then link the project repo once:

```sh
coffin add myapp/base --type env      # paste or --from-file .env
coffin add myapp/staging --type env   # overrides on top of base
coffin link myapp -e dev              # writes .coffin.toml (commit it)
```

From then on, anyone on the vault runs the app with no secrets file:

```sh
coffin run -- npm start               # injects base+dev, writes nothing
coffin run -e staging -- ./deploy.sh  # same project, staging overlay
```

Need a real file for tooling? Render one explicitly, and keep it
honest with drift checks:

```sh
coffin render                 # writes .env (0600, warns, gitignore check)
coffin diff                   # vault vs .env, both directions, exits 1 on drift
coffin diff --json            # machine-readable, for CI
```

## Scripting

Read commands take `--json`: `coffin ls --json`,
`coffin get <name> --show --json`, `coffin diff --json`. Values only
print with an explicit `--show`/`--values`, same as the text output.

## Security

The full [threat model](docs/THREAT_MODEL.md) is short and honest;
the on-disk format is specified in [docs/FORMAT.md](docs/FORMAT.md).
The one-paragraph version: everything on disk or on the git remote is
ciphertext (age X25519 envelopes, argon2id-sealed identity,
XChaCha20-Poly1305 payloads with path-binding AAD); entry *names* are
plaintext by design; revocation always rotates keys; and coffin does
not defend against malware on an unlocked machine or a malicious
current teammate.

Non-goals (v1): browser extension/autofill, hosted sync, mobile, GUI.

## License

MIT, see [LICENSE](LICENSE). Product spec in [PRD.md](PRD.md).
