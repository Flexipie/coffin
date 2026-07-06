package cli

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var pubkeyRe = regexp.MustCompile(`age1[a-z0-9]+`)

// gitOut runs git in dir for test setup and assertions.
func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestTeamAcceptance encodes the Phase 3 "done when": alice creates
// and pushes a team vault, bob joins and syncs but cannot read, alice
// shares him scoped to one project, bob reads exactly that project and
// nothing else, alice revokes him with a rotation checklist, and after
// the next sync bob is locked out while alice still reads everything.
func TestTeamAcceptance(t *testing.T) {
	if testing.Short() {
		t.Skip("acceptance test runs the real argon2id KDF")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("no git binary: %v", err)
	}
	// Commits must not depend on the machine's git config.
	for _, k := range []string{"GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"} {
		t.Setenv(k, "tester")
	}
	for _, k := range []string{"GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"} {
		t.Setenv(k, "tester@example.com")
	}

	// A local bare repo stands in for the team's remote.
	remote := filepath.Join(t.TempDir(), "remote.git")
	gitOut(t, t.TempDir(), "init", "--bare", remote)

	const aliceMaster = "alice master pw"
	const bobMaster = "bob master pw"

	// Alice: identity + personal vault, then the team vault.
	alice := newTestEnv(t)
	alice.mustRun(t, []string{"alice", aliceMaster, aliceMaster}, "",
		"init", "--path", filepath.Join(t.TempDir(), "personal"))
	work := filepath.Join(t.TempDir(), "work")
	_, stderr := alice.mustRun(t, []string{"alice"}, "", "init", "--team", work)
	if !strings.Contains(stderr, `Team vault "work" created`) {
		t.Fatalf("init --team stderr = %q", stderr)
	}
	gitOut(t, work, "remote", "add", "origin", remote)
	alice.mustRun(t, nil, "", "sync")
	// The bare repo's HEAD must follow whatever branch name alice's
	// git created, or clones check out nothing.
	branch := gitOut(t, work, "rev-parse", "--abbrev-ref", "HEAD")
	gitOut(t, remote, "symbolic-ref", "HEAD", "refs/heads/"+branch)

	// Alice fills the team vault: a password, an in-scope project, an
	// out-of-scope project. All encrypt-only, each op its own commit.
	alice.mustRun(t, []string{"svc", "teampass", "", "", ""}, "",
		"add", "deploy", "--vault", "work")
	alice.mustRun(t, nil, "DB=1\n", "add", "myapp/api/staging", "--type", "env", "--vault", "work")
	alice.mustRun(t, nil, "SECRET=2\n", "add", "otherapp/prod", "--type", "env", "--vault", "work")
	alice.mustRun(t, nil, "", "sync")

	// Bob: own identity, then join. The join prints his public key.
	bob := newTestEnv(t)
	bob.mustRun(t, []string{"bob", bobMaster, bobMaster}, "",
		"init", "--path", filepath.Join(t.TempDir(), "personal"))
	bobWork := filepath.Join(t.TempDir(), "bob", "work")
	_, stderr = bob.mustRun(t, nil, "", "join", remote, bobWork)
	if !strings.Contains(stderr, "You cannot read anything yet.") {
		t.Fatalf("join stderr = %q", stderr)
	}
	bobPub := pubkeyRe.FindString(stderr)
	if bobPub == "" {
		t.Fatalf("join printed no public key:\n%s", stderr)
	}

	// Joined but not shared: bob sees the entry names (by design) and
	// can decrypt nothing.
	stdout, _ := bob.mustRun(t, nil, "", "ls", "--vault", "work")
	if !strings.Contains(stdout, "deploy") {
		t.Fatalf("bob's ls = %q, names are plaintext by design", stdout)
	}
	if _, _, err := bob.run(t, []string{bobMaster}, "", "get", "deploy"); err == nil ||
		!strings.Contains(err.Error(), "decryption failed") {
		t.Fatalf("unshared bob read a password: %v", err)
	}

	// Alice shares bob, scoped to myapp only, and publishes.
	_, stderr = alice.mustRun(t, []string{aliceMaster}, "",
		"share", "--with", bobPub, "--name", "bob", "--project", "myapp", "--vault", "work")
	if !strings.Contains(stderr, "scoped to: myapp") {
		t.Fatalf("share stderr = %q", stderr)
	}
	alice.mustRun(t, nil, "", "sync")

	// Bob pulls his access: the scoped project opens, everything else
	// stays sealed. His session was cached by the failed get above, so
	// no more password prompts.
	bob.mustRun(t, nil, "", "sync")
	stdout, _ = bob.mustRun(t, nil, "", "get", "staging", "--show")
	if stdout != "DB=1\n" {
		t.Fatalf("bob's scoped get = %q", stdout)
	}
	if _, _, err := bob.run(t, nil, "", "get", "deploy"); err == nil ||
		!strings.Contains(err.Error(), "decryption failed") {
		t.Fatalf("scoped bob read a password: %v", err)
	}
	if _, _, err := bob.run(t, nil, "", "get", "prod"); err == nil ||
		!strings.Contains(err.Error(), "decryption failed") {
		t.Fatalf("scoped bob read another project: %v", err)
	}

	// Alice revokes bob. Only his project rotates, and the checklist
	// names exactly the entries he could have read.
	_, stderr = alice.mustRun(t, nil, "", "revoke", "--user", "bob", "--vault", "work")
	if !strings.Contains(stderr, "needs-source-rotation") ||
		!strings.Contains(stderr, "env/myapp/api/staging") {
		t.Fatalf("revoke stderr = %q, want the rotation checklist", stderr)
	}
	if strings.Contains(stderr, "passwords/deploy") || strings.Contains(stderr, "otherapp") {
		t.Fatalf("revoke checklist lists entries bob never had: %q", stderr)
	}
	alice.mustRun(t, nil, "", "sync")

	// Bob is out: after his next sync the rotated project is sealed to
	// him. Alice still reads it.
	bob.mustRun(t, nil, "", "sync")
	if _, _, err := bob.run(t, nil, "", "get", "staging", "--show"); err == nil ||
		!strings.Contains(err.Error(), "decryption failed") {
		t.Fatalf("revoked bob still reads the rotated project: %v", err)
	}
	stdout, _ = alice.mustRun(t, nil, "", "get", "staging", "--show")
	if stdout != "DB=1\n" {
		t.Fatalf("alice lost the rotated project: %q", stdout)
	}

	// One commit per logical operation, in order.
	log := gitOut(t, work, "log", "--format=%s")
	for _, want := range []string{
		"init team vault work",
		"add deploy",
		"add myapp/api/staging",
		"add otherapp/prod",
		"share: add bob",
		"revoke: remove bob, rotate 1 keys",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("git log missing %q:\n%s", want, log)
		}
	}
}
