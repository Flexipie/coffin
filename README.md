# coffin

A local-first password and secrets manager. Your secrets live in a git repo as encrypted TOML files; nothing ever leaves your machines unencrypted.

**Status: under construction.** Nothing here is stable yet.

## What works today

Personal vault:

```
coffin init                      # create a vault + master identity
coffin add github                # add a password entry
coffin get github                # fuzzy match, copy, auto-clear
coffin add myapp/dev --type env  # add an env set (KEY=VALUE lines)
coffin ls / edit / rm / gen / unlock / lock
```

Team vault (shared through any git remote):

```
coffin init --team <path>        # team vault in a git repo
coffin join <repo>               # clone + print your public key
coffin share --with <pubkey> --name bob [--project myapp]
coffin revoke --user bob         # rotates what bob could read
coffin sync                      # pull + push
```

Sharing can be scoped per project: a `--project`-scoped member can only decrypt env groups under that prefix, enforced by encryption, not policy.

Dev workflow (replaces hand-shared `.env` files):

```
coffin link myapp -e dev         # write .coffin.toml (committed, secret-free)
coffin run -- npm start          # inject env vars, nothing on disk
coffin render                    # write a gitignored .env (plaintext, explicit)
coffin diff                      # flag drift between vault and .env, exits 1
```

A project's `.coffin.toml` names the vault, env group, and default environment. Overlays (`base`, `dev`, `staging`, `prod`, ...) merge as base-plus-override.

See [PRD.md](PRD.md) for the product spec and [docs/FORMAT.md](docs/FORMAT.md) for the on-disk format.
