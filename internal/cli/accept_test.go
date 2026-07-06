package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flexipie/coffin/internal/vault"
)

// TestAcceptance encodes the Phase 2 "done when": init, add, lock, get
// (prompts + copies + auto-clear scheduled), get again within the
// session (no prompt), env add from a file, get --show, ls, edit with
// keep-on-empty, gen, rm, empty ls. It drives the real command wiring
// with fakes only at the OS seams (keychain, clipboard, terminal).
func TestAcceptance(t *testing.T) {
	if testing.Short() {
		t.Skip("acceptance test runs the real argon2id KDF")
	}
	e := newTestEnv(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")
	const master = "correct horse battery"

	// init: name prompt, password twice.
	_, stderr := e.mustRun(t, []string{"felix", master, master}, "",
		"init", "--path", vaultDir)
	if !strings.Contains(stderr, "public key: age1") {
		t.Fatalf("init stderr = %q, want public key", stderr)
	}
	if _, err := os.Stat(filepath.Join(vaultDir, "coffin.toml")); err != nil {
		t.Fatal(err)
	}

	// A second init must refuse.
	if _, _, err := e.run(t, nil, "", "init", "--path", vaultDir); err == nil {
		t.Fatal("second init did not refuse")
	}

	// add is encrypt-only: no master password among the prompts.
	_, stderr = e.mustRun(t,
		[]string{"octocat", "hunter2", "https://github.com", "work account", ""}, "",
		"add", "github")
	if !strings.Contains(stderr, "Added github to personal.") {
		t.Fatalf("add stderr = %q", stderr)
	}

	// Duplicate add points at edit.
	if _, _, err := e.run(t, nil, "", "add", "github"); err == nil ||
		!strings.Contains(err.Error(), "coffin edit") {
		t.Fatal("duplicate add did not point at edit")
	}

	// lock, then get: must prompt for the master password and copy.
	e.mustRun(t, nil, "", "lock")
	_, stderr = e.mustRun(t, []string{master}, "", "get", "github")
	if e.clip.value != "hunter2" {
		t.Fatalf("clipboard = %q, want the password", e.clip.value)
	}
	if !strings.Contains(stderr, "Copied password for github (personal). Clears in 30s.") {
		t.Fatalf("get stderr = %q", stderr)
	}
	if !strings.Contains(stderr, "username: octocat") {
		t.Fatalf("get stderr = %q, want username context", stderr)
	}

	// get again inside the session: zero prompts.
	e.clip.value = ""
	e.mustRun(t, nil, "", "get", "github")
	if e.clip.value != "hunter2" {
		t.Fatal("session get did not copy")
	}

	// Wrong master password after lock surfaces the one generic error.
	e.mustRun(t, nil, "", "lock")
	if _, _, err := e.run(t, []string{"wrong password"}, "", "get", "github"); err == nil ||
		!strings.Contains(err.Error(), "decryption failed") {
		t.Fatalf("wrong password error = %v", err)
	}
	e.mustRun(t, []string{master}, "", "unlock")

	// add env from a file: a fresh group needs no unlock.
	envFile := filepath.Join(t.TempDir(), "staging.env")
	if err := os.WriteFile(envFile, []byte("# staging secrets\nDB_URL=postgres://localhost/dev\nexport API_KEY=sekrit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr = e.mustRun(t, nil, "", "add", "myapp/api/staging", "--type", "env", "--from-file", envFile)
	if !strings.Contains(stderr, "Added myapp/api/staging to personal (2 vars).") {
		t.Fatalf("env add stderr = %q", stderr)
	}

	// get --show prints dotenv lines in order (session hit, no prompt).
	stdout, _ := e.mustRun(t, nil, "", "get", "staging", "--show")
	if stdout != "DB_URL=postgres://localhost/dev\nAPI_KEY=sekrit\n" {
		t.Fatalf("env get --show = %q", stdout)
	}

	// Default env get masks values.
	stdout, stderr = e.mustRun(t, nil, "", "get", "staging")
	if strings.Contains(stdout, "sekrit") || !strings.Contains(stdout, "API_KEY=") {
		t.Fatalf("env get leaked or missed keys: %q", stdout)
	}
	if !strings.Contains(stderr, "--show") {
		t.Fatalf("env get stderr = %q, want a --show hint", stderr)
	}

	// ls shows both, no unlock involved.
	stdout, _ = e.mustRun(t, nil, "", "ls")
	for _, want := range []string{"VAULT", "github", "myapp/api/staging", "personal"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("ls output missing %q:\n%s", want, stdout)
		}
	}
	stdout, _ = e.mustRun(t, nil, "", "ls", "--project", "myapp/api")
	if strings.Contains(stdout, "github") || !strings.Contains(stdout, "myapp/api/staging") {
		t.Fatalf("ls --project = %q", stdout)
	}

	// edit: empty keeps, new password replaces.
	_, stderr = e.mustRun(t, []string{"", "newpass42", "", "", ""}, "", "edit", "github")
	if !strings.Contains(stderr, "Updated github in personal.") {
		t.Fatalf("edit stderr = %q", stderr)
	}
	stdout, _ = e.mustRun(t, nil, "", "get", "github", "--show")
	if !strings.Contains(stdout, "password: newpass42") || !strings.Contains(stdout, "username: octocat") {
		t.Fatalf("get --show after edit = %q", stdout)
	}

	// get --field.
	e.mustRun(t, nil, "", "get", "github", "--field", "username")
	if e.clip.value != "octocat" {
		t.Fatalf("--field username copied %q", e.clip.value)
	}
	if _, _, err := e.run(t, nil, "", "get", "github", "--field", "totp"); err == nil ||
		!strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty field error = %v", err)
	}

	// rm: non-TTY without --force refuses, --force removes.
	if _, _, err := e.run(t, nil, "", "rm", "github", "--force=false"); err == nil ||
		!strings.Contains(err.Error(), "--force") {
		t.Fatalf("rm without terminal = %v, want a --force pointer", err)
	}
	_, stderr = e.mustRun(t, nil, "", "rm", "github", "--force")
	if !strings.Contains(stderr, "Removed github from personal.") {
		t.Fatalf("rm stderr = %q", stderr)
	}
	if _, _, err := e.run(t, nil, "", "get", "github"); err == nil {
		t.Fatal("get after rm succeeded")
	}
	e.mustRun(t, nil, "", "rm", "staging", "--force")

	// Last env overlay removed => key.toml and dirs pruned.
	if _, err := os.Stat(filepath.Join(vaultDir, "env")); !os.IsNotExist(err) {
		t.Fatalf("env dir not pruned after last rm: %v", err)
	}

	// Empty vault: ls says so on stderr and exits 0.
	stdout, stderr, err := e.run(t, nil, "", "ls")
	if err != nil || stdout != "" || !strings.Contains(stderr, "no entries") {
		t.Fatalf("empty ls = %q / %q / %v", stdout, stderr, err)
	}
}

// TestResolutionUX pins the 0/1/many behavior without the KDF cost.
func TestResolutionUX(t *testing.T) {
	e := newTestEnv(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")

	// Build a vault + registry without init (no identity needed for ls/rm).
	id := mustGenerateIdentity(t)
	v, err := vault.Create(vaultDir, "personal", "personal",
		vault.Recipient{Name: "t", PublicKey: id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.PutPassword("github", vault.PasswordData{Password: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := v.PutPassword("github-work", vault.PasswordData{Password: "y"}); err != nil {
		t.Fatal(err)
	}
	writeRegistry(t, "personal", vaultDir)

	if _, _, err := e.run(t, nil, "", "rm", "nothere", "--force"); err == nil ||
		!strings.Contains(err.Error(), "no entry matches") {
		t.Fatalf("zero matches = %v", err)
	}
	// "gith" prefixes both entries: ambiguous, both listed.
	_, _, err = e.run(t, nil, "", "rm", "gith", "--force")
	if err == nil || !strings.Contains(err.Error(), "ambiguous") ||
		!strings.Contains(err.Error(), "github-work") {
		t.Fatalf("ambiguous match = %v", err)
	}
	// Exact name shadows the prefix match.
	_, stderr := e.mustRun(t, nil, "", "rm", "github", "--force")
	if !strings.Contains(stderr, "Removed github from personal.") {
		t.Fatalf("rm stderr = %q", stderr)
	}
}

func TestVaultFlagUnknown(t *testing.T) {
	e := newTestEnv(t)
	_, _, err := e.run(t, nil, "", "ls", "--vault", "nope")
	if err == nil || !strings.Contains(err.Error(), "no vault") {
		t.Fatalf("unknown --vault = %v", err)
	}
}
