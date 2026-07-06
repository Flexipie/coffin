package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flexipie/coffin/internal/git"
)

// TestDevAcceptance encodes the Phase 4 "done when": a project linked
// via .coffin.toml runs through `coffin run` with no local secrets
// file and base+staging merge applied, `render` produces a working
// .env, and `diff` catches an intentional drift (then confirms the
// fix). Real command wiring, real git repo, fakes only at the OS
// seams.
func TestDevAcceptance(t *testing.T) {
	if testing.Short() {
		t.Skip("acceptance test runs the real argon2id KDF")
	}
	e := newTestEnv(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")
	const master = "correct horse battery"

	e.mustRun(t, []string{"felix", master, master}, "", "init", "--path", vaultDir)
	e.mustRun(t, []string{master}, "", "unlock")

	// Seed the group: base plus a staging overlay that overrides one
	// var and adds one.
	baseFile := filepath.Join(t.TempDir(), "base.env")
	if err := os.WriteFile(baseFile, []byte("DB_URL=postgres://localhost/base\nBASE_ONLY=b1\nOVERRIDE_ME=base\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stagingFile := filepath.Join(t.TempDir(), "staging.env")
	if err := os.WriteFile(stagingFile, []byte("OVERRIDE_ME=staging\nSTAGING_ONLY=s1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.mustRun(t, nil, "", "add", "myapp/base", "--type", "env", "--from-file", baseFile)
	e.mustRun(t, nil, "", "add", "myapp/staging", "--type", "env", "--from-file", stagingFile)

	// The "project repo": a real git repo so the gitignore advice path
	// is exercised end to end.
	proj := t.TempDir()
	if err := git.Init(proj); err != nil {
		t.Fatal(err)
	}
	t.Chdir(proj)
	_, stderr := e.mustRun(t, nil, "", "link", "myapp", "-e", "staging")
	if !strings.Contains(stderr, "Linked") {
		t.Fatalf("link stderr = %q", stderr)
	}

	// run: injection with the merge applied, and nothing on disk.
	stdout, stderr := e.mustRun(t, nil, "", "run", "--",
		"sh", "-c", `printf "%s|%s|%s|%s" "$DB_URL" "$BASE_ONLY" "$OVERRIDE_ME" "$STAGING_ONLY"`)
	if stdout != "postgres://localhost/base|b1|staging|s1" {
		t.Fatalf("run stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "Running with 4 vars from myapp (staging, vault personal).") {
		t.Fatalf("run stderr = %q", stderr)
	}
	if _, err := os.Stat(filepath.Join(proj, ".env")); !os.IsNotExist(err) {
		t.Fatal("run left a file behind")
	}

	// render: a working .env, with a warning because it is not yet
	// gitignored.
	_, stderr = e.mustRun(t, nil, "", "render")
	if !strings.Contains(stderr, "Wrote 4 vars") || !strings.Contains(stderr, "not gitignored") {
		t.Fatalf("render stderr = %q", stderr)
	}
	f, err := os.Open(filepath.Join(proj, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	vars, err := parseDotenv(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(vars) != 4 || vars[2].Key != "OVERRIDE_ME" || vars[2].Value != "staging" {
		t.Fatalf("rendered .env parses to %+v", vars)
	}

	// Gitignoring the file silences the warning.
	if err := os.WriteFile(filepath.Join(proj, ".gitignore"), []byte(".env\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stderr = e.mustRun(t, nil, "", "render", "--force")
	if strings.Contains(stderr, "not gitignored") {
		t.Fatalf("render warned despite .gitignore: %q", stderr)
	}

	// diff: in sync right after render.
	stdout, _, err = e.run(t, nil, "", "diff")
	if err != nil || !strings.Contains(stdout, "In sync: 4 vars") {
		t.Fatalf("post-render diff = %q, %v", stdout, err)
	}

	// Intentional drift: tamper a value, drop a vault var, add a local
	// one. diff must flag all three and exit 1.
	drifted := "DB_URL=postgres://localhost/base\nBASE_ONLY=b1\nOVERRIDE_ME=tampered\nEXTRA=local\n"
	if err := os.WriteFile(filepath.Join(proj, ".env"), []byte(drifted), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err = e.run(t, nil, "", "diff")
	if ExitCode(err) != 1 {
		t.Fatalf("drift diff ExitCode = %d (%v), want 1", ExitCode(err), err)
	}
	for _, want := range []string{"+ STAGING_ONLY", "- EXTRA", "~ OVERRIDE_ME"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("drift diff missing %q:\n%s", want, stdout)
		}
	}

	// Fix the drift and confirm.
	e.mustRun(t, nil, "", "render", "--force")
	stdout, _, err = e.run(t, nil, "", "diff")
	if err != nil || !strings.Contains(stdout, "In sync: 4 vars") {
		t.Fatalf("post-fix diff = %q, %v", stdout, err)
	}
}
