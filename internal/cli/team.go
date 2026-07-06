package cli

import (
	"fmt"
	"io"

	"github.com/Flexipie/coffin/internal/git"
	"github.com/Flexipie/coffin/internal/vault"
)

// commitSlug normalizes a user-typed name for a commit message,
// falling back to the raw input (the operation already succeeded, so
// this only ever runs on a name that normalized cleanly).
func commitSlug(name string) string {
	if slug, err := vault.NormalizeSlug(name); err == nil {
		return slug
	}
	return name
}

// isTeam reads the kind from the manifest, not the registry, so a
// cloned vault keeps team behavior even if the local registry entry is
// stale or hand-edited.
func isTeam(v *vault.Vault) bool {
	return v.Manifest.Vault.Kind == vault.KindTeam
}

// ensureCleanTeamVault refuses to mutate a team vault whose work tree
// is dirty: FORMAT.md wants one commit per logical operation, and a
// dirty tree would smuggle unrelated changes into this operation's
// commit.
func ensureCleanTeamVault(v *vault.Vault) error {
	if !isTeam(v) || !git.IsRepo(v.Root) {
		return nil
	}
	dirty, err := git.IsDirty(v.Root)
	if err != nil {
		return err
	}
	if dirty {
		return fmt.Errorf("coffin: team vault %s has uncommitted changes; commit or stash them first", v.Root)
	}
	return nil
}

// teamCommit commits a completed mutation on a team vault. Personal
// vaults never touch git. A team vault that somehow is not a repo gets
// a warning instead of an error: the data write already happened.
// paths defaults to the whole tree, which is safe because
// ensureCleanTeamVault ran before the mutation.
func teamCommit(errW io.Writer, v *vault.Vault, msg string, paths ...string) error {
	if !isTeam(v) {
		return nil
	}
	if !git.IsRepo(v.Root) {
		fmt.Fprintf(errW, "warning: team vault %s is not a git repository; the change was not committed\n", v.Root)
		return nil
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	return git.Commit(v.Root, msg, paths...)
}
