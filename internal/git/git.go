// Package git shells out to the system git binary (a locked decision:
// no go-git dependency). Every helper surfaces git's own stderr on
// failure so the user sees the real reason, never a swallowed exit
// code.
package git

import (
	"fmt"
	"os/exec"
	"strings"
)

// run executes git with args in dir and returns trimmed stdout.
func run(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = strings.TrimSpace(out.String())
		}
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("coffin: git %s: %s", args[0], msg)
	}
	return strings.TrimSpace(out.String()), nil
}

// IsRepo reports whether dir is inside a git work tree.
func IsRepo(dir string) bool {
	out, err := run(dir, "rev-parse", "--is-inside-work-tree")
	return err == nil && out == "true"
}

// IsIgnored reports whether path (relative to dir or absolute) is
// ignored by dir's repository. check-ignore exits 1 for "not ignored",
// which run would misreport as a failure, so this shells out directly;
// any git error just means "not ignored" for the caller's purposes.
func IsIgnored(dir, path string) bool {
	cmd := exec.Command("git", "check-ignore", "-q", "--", path)
	cmd.Dir = dir
	return cmd.Run() == nil
}

// Init creates a repository in dir.
func Init(dir string) error {
	_, err := run(dir, "init")
	return err
}

// Clone clones url into dest.
func Clone(url, dest string) error {
	_, err := run(".", "clone", "--", url, dest)
	return err
}

// IsDirty reports whether the work tree has uncommitted changes,
// including untracked files.
func IsDirty(dir string) (bool, error) {
	out, err := run(dir, "status", "--porcelain")
	if err != nil {
		return false, err
	}
	return out != "", nil
}

// HasRemote reports whether the repository has any remote configured.
func HasRemote(dir string) (bool, error) {
	out, err := run(dir, "remote")
	if err != nil {
		return false, err
	}
	return out != "", nil
}

// Commit stages paths (relative to dir) and commits them. FORMAT.md
// requires one commit per logical operation, so callers pass exactly
// the files that operation touched. Paths that no longer exist are
// staged as deletions by git add -A.
func Commit(dir, message string, paths ...string) error {
	if len(paths) == 0 {
		return fmt.Errorf("coffin: git commit with no paths")
	}
	args := append([]string{"add", "-A", "--"}, paths...)
	if _, err := run(dir, args...); err != nil {
		return err
	}
	// Plain commit takes the index, which holds exactly the paths
	// staged above (team operations refuse to start on a dirty tree,
	// so nothing else can be staged).
	_, err := run(dir, "commit", "-m", message)
	return err
}

// Pull fetches and merges from the default upstream. A merge conflict
// comes back with git's own message intact so the caller can add
// guidance on top.
func Pull(dir string) error {
	_, err := run(dir, "pull", "--no-rebase")
	return err
}

// HasUpstream reports whether the current branch tracks a remote
// branch (false on a freshly created repo that has never pushed).
func HasUpstream(dir string) bool {
	_, err := run(dir, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
	return err == nil
}

// Push publishes the current branch to its upstream, setting one on
// the first push.
func Push(dir string) error {
	branch, err := run(dir, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return err
	}
	_, err = run(dir, "push", "-u", "origin", branch)
	return err
}
