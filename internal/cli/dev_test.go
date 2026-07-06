package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/crypto"
	"github.com/Flexipie/coffin/internal/vault"
)

const devMaster = "test master password"

// saveFastIdentity seals id with cheap argon2id parameters so unit
// tests can unlock without the production KDF cost.
func saveFastIdentity(t *testing.T, id *age.X25519Identity) {
	t.Helper()
	p, err := crypto.NewKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	p.Time = 1
	p.MemoryKiB = 8 * 1024
	enc, err := crypto.SealIdentity(id, []byte(devMaster), p)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.SaveIdentity(enc); err != nil {
		t.Fatal(err)
	}
}

// setupDevFixture builds a registered vault whose myapp group has base
// and staging overlays, plus a cheap identity, and returns the vault.
func setupDevFixture(t *testing.T, e *testEnv) *vault.Vault {
	t.Helper()
	vaultDir := filepath.Join(t.TempDir(), "vault")
	id := mustGenerateIdentity(t)
	v, err := vault.Create(vaultDir, "personal", "personal",
		vault.Recipient{Name: "t", PublicKey: id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	ident := func() (age.Identity, error) { return id, nil }
	base := vault.EnvData{Vars: []vault.EnvVar{
		{Key: "DB_URL", Value: "postgres://localhost/base"},
		{Key: "BASE_ONLY", Value: "b1"},
		{Key: "OVERRIDE_ME", Value: "base"},
	}}
	staging := vault.EnvData{Vars: []vault.EnvVar{
		{Key: "OVERRIDE_ME", Value: "staging"},
		{Key: "STAGING_ONLY", Value: "s1"},
	}}
	if err := v.PutEnv("myapp", "base", base, ident); err != nil {
		t.Fatal(err)
	}
	if err := v.PutEnv("myapp", "staging", staging, ident); err != nil {
		t.Fatal(err)
	}
	writeRegistry(t, "personal", vaultDir)
	saveFastIdentity(t, id)
	return v
}

const devProjectFile = "format_version = 1\n\n[project]\nvault = \"personal\"\ngroup = \"myapp\"\ndefault_env = \"staging\"\n"

// enterProjectDir chdirs into a fresh directory holding content as its
// .coffin.toml and returns it.
func enterProjectDir(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".coffin.toml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	return dir
}

// mergedDotenv is the effective staging set as dotenv lines.
const mergedDotenv = "DB_URL=postgres://localhost/base\nBASE_ONLY=b1\nOVERRIDE_ME=staging\nSTAGING_ONLY=s1\n"

func TestComposeEnv(t *testing.T) {
	parent := []string{"KEEP=1", "REPLACE=old", "PATH=/bin"}
	got := composeEnv(parent, []vault.EnvVar{
		{Key: "REPLACE", Value: "new"},
		{Key: "ADDED", Value: "2"},
	})
	want := []string{"KEEP=1", "REPLACE=new", "PATH=/bin", "ADDED=2"}
	if len(got) != len(want) {
		t.Fatalf("composeEnv = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("composeEnv[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if parent[1] != "REPLACE=old" {
		t.Fatal("composeEnv mutated its input")
	}
}

func TestRunInjectsAndMerges(t *testing.T) {
	e := newTestEnv(t)
	setupDevFixture(t, e)
	dir := enterProjectDir(t, devProjectFile)
	t.Setenv("OVERRIDE_ME", "parent value")
	e.mustRun(t, []string{devMaster}, "", "unlock")

	stdout, stderr := e.mustRun(t, nil, "", "run", "--",
		"sh", "-c", `printf "%s|%s|%s|%s" "$DB_URL" "$BASE_ONLY" "$OVERRIDE_ME" "$STAGING_ONLY"`)
	if stdout != "postgres://localhost/base|b1|staging|s1" {
		t.Fatalf("run stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "Running with 4 vars from myapp (staging, vault personal).") {
		t.Fatalf("run stderr = %q", stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, ".env")); !os.IsNotExist(err) {
		t.Fatal("run must not write anything to disk")
	}

	// Without "--" the child's own flags still pass through untouched.
	stdout, _ = e.mustRun(t, nil, "", "run", "-e", "base",
		"sh", "-c", `printf "%s" "$OVERRIDE_ME"`, "sh", "-e")
	if stdout != "base" {
		t.Fatalf("run -e base stdout = %q", stdout)
	}
}

func TestRunExitCodeAndSilence(t *testing.T) {
	e := newTestEnv(t)
	setupDevFixture(t, e)
	enterProjectDir(t, devProjectFile)
	e.mustRun(t, []string{devMaster}, "", "unlock")

	_, stderr, err := e.run(t, nil, "", "run", "sh", "-c", "exit 3")
	if ExitCode(err) != 3 {
		t.Fatalf("ExitCode = %d (%v), want 3", ExitCode(err), err)
	}
	if strings.Contains(stderr, "Error:") {
		t.Fatalf("exit-code error must be silent, stderr = %q", stderr)
	}

	// A start failure is a normal, printed coffin error with exit 1.
	_, _, err = e.run(t, nil, "", "run", "definitely-not-a-command-xyz")
	if err == nil || ExitCode(err) != 1 {
		t.Fatalf("start failure = %v (code %d), want plain error", err, ExitCode(err))
	}
}

func TestRunErrors(t *testing.T) {
	e := newTestEnv(t)
	setupDevFixture(t, e)

	// No .coffin.toml anywhere up from an isolated dir.
	t.Chdir(t.TempDir())
	_, _, err := e.run(t, nil, "", "run", "true")
	if err == nil || !strings.Contains(err.Error(), "coffin link") {
		t.Fatalf("no project file error = %v, want a link hint", err)
	}

	// Missing overlay lists what exists.
	enterProjectDir(t, devProjectFile)
	e.mustRun(t, []string{devMaster}, "", "unlock")
	_, _, err = e.run(t, nil, "", "run", "-e", "prod", "true")
	if err == nil || !strings.Contains(err.Error(), `no overlay "prod"`) ||
		!strings.Contains(err.Error(), "available: base, staging") {
		t.Fatalf("missing overlay error = %v", err)
	}

	// Unknown group names the vault.
	enterProjectDir(t, "format_version = 1\n\n[project]\ngroup = \"ghost\"\ndefault_env = \"dev\"\n")
	_, _, err = e.run(t, nil, "", "run", "true")
	if err == nil || !strings.Contains(err.Error(), `no env group "ghost"`) {
		t.Fatalf("missing group error = %v", err)
	}

	// No -e and no default_env: explicit error, never a silent default.
	enterProjectDir(t, "format_version = 1\n\n[project]\ngroup = \"myapp\"\n")
	_, _, err = e.run(t, nil, "", "run", "true")
	if err == nil || !strings.Contains(err.Error(), "pass -e or set default_env") {
		t.Fatalf("no env error = %v", err)
	}
}

func TestRenderWritesRoundTrippableDotenv(t *testing.T) {
	e := newTestEnv(t)
	setupDevFixture(t, e)
	dir := enterProjectDir(t, devProjectFile)
	e.mustRun(t, []string{devMaster}, "", "unlock")

	_, stderr := e.mustRun(t, nil, "", "render")
	target := filepath.Join(dir, ".env")
	if !strings.Contains(stderr, "Wrote 4 vars to") || !strings.Contains(stderr, "plaintext") {
		t.Fatalf("render stderr = %q", stderr)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf(".env mode = %o, want 0600", perm)
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	if !strings.HasPrefix(content, "# Rendered by coffin from personal/myapp (staging)") {
		t.Fatalf(".env header = %q", content)
	}
	if !strings.Contains(content, "PLAINTEXT SECRETS") {
		t.Fatal(".env is missing the plaintext warning")
	}
	if !strings.HasSuffix(content, mergedDotenv) {
		t.Fatalf(".env body = %q, want suffix %q", content, mergedDotenv)
	}
	// The file must parse back to exactly the effective set.
	vars, err := parseDotenv(strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if len(vars) != 4 || vars[2].Key != "OVERRIDE_ME" || vars[2].Value != "staging" {
		t.Fatalf("round-trip = %+v", vars)
	}

	// Existing file refuses without --force.
	_, _, err = e.run(t, nil, "", "render")
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("overwrite without --force = %v", err)
	}
	e.mustRun(t, nil, "", "render", "--force")

	// -o writes elsewhere.
	alt := filepath.Join(t.TempDir(), "alt.env")
	e.mustRun(t, nil, "", "render", "-o", alt)
	if _, err := os.Stat(alt); err != nil {
		t.Fatal(err)
	}
}

func TestRenderRejectsUnrepresentableValues(t *testing.T) {
	e := newTestEnv(t)
	v := setupDevFixture(t, e)
	// Plant a value the dotenv dialect cannot carry; the CLI ingestion
	// path can never create one, so go through the vault API directly.
	bad := vault.EnvData{Vars: []vault.EnvVar{{Key: "BAD", Value: "line1\nline2"}}}
	if err := v.PutEnv("multiline", "dev", bad, func() (age.Identity, error) {
		t.Fatal("fresh group must not need the identity")
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	enterProjectDir(t, "format_version = 1\n\n[project]\ngroup = \"multiline\"\ndefault_env = \"dev\"\n")
	e.mustRun(t, []string{devMaster}, "", "unlock")
	_, _, err := e.run(t, nil, "", "render")
	if err == nil || !strings.Contains(err.Error(), "BAD") ||
		!strings.Contains(err.Error(), "line break") {
		t.Fatalf("multiline render error = %v", err)
	}
	if strings.Contains(err.Error(), "line2") {
		t.Fatalf("render error leaked the value: %v", err)
	}
}

func TestDiffDriftAndSync(t *testing.T) {
	e := newTestEnv(t)
	setupDevFixture(t, e)
	dir := enterProjectDir(t, devProjectFile)
	e.mustRun(t, []string{devMaster}, "", "unlock")

	// No file yet: point at render.
	_, _, err := e.run(t, nil, "", "diff")
	if err == nil || !strings.Contains(err.Error(), "coffin render") {
		t.Fatalf("missing file error = %v", err)
	}

	e.mustRun(t, nil, "", "render")
	stdout, _, err := e.run(t, nil, "", "diff")
	if err != nil || !strings.Contains(stdout, "In sync: 4 vars") {
		t.Fatalf("in-sync diff = %q, %v", stdout, err)
	}

	// Drift all three ways: change a value, drop a vault var, add a
	// local-only one.
	drifted := "DB_URL=postgres://localhost/base\nBASE_ONLY=b1\nOVERRIDE_ME=tampered\nEXTRA=local\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(drifted), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := e.run(t, nil, "", "diff")
	if ExitCode(err) != 1 {
		t.Fatalf("drift ExitCode = %d (%v), want 1", ExitCode(err), err)
	}
	if strings.Contains(stderr, "Error:") {
		t.Fatalf("drift must not print an error, stderr = %q", stderr)
	}
	for _, want := range []string{"+ STAGING_ONLY", "- EXTRA", "~ OVERRIDE_ME", "values differ"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("diff output missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "tampered") {
		t.Fatalf("diff leaked values without --values:\n%s", stdout)
	}

	// --values prints both sides of a changed key.
	stdout, _, err = e.run(t, nil, "", "diff", "--values")
	if ExitCode(err) != 1 {
		t.Fatalf("diff --values ExitCode = %d", ExitCode(err))
	}
	if !strings.Contains(stdout, "vault: staging") || !strings.Contains(stdout, "local: tampered") {
		t.Fatalf("diff --values output:\n%s", stdout)
	}

	// -f compares an explicit file.
	alt := filepath.Join(t.TempDir(), "other.env")
	if err := os.WriteFile(alt, []byte(mergedDotenv), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err = e.run(t, nil, "", "diff", "-f", alt)
	if err != nil || !strings.Contains(stdout, "In sync") {
		t.Fatalf("diff -f = %q, %v", stdout, err)
	}
}

func TestLinkWritesProjectFile(t *testing.T) {
	e := newTestEnv(t)
	setupDevFixture(t, e)
	dir := t.TempDir()
	t.Chdir(dir)

	_, stderr := e.mustRun(t, nil, "", "link", "MyApp", "-e", "staging")
	if !strings.Contains(stderr, "Linked") || strings.Contains(stderr, "warning") {
		t.Fatalf("link stderr = %q", stderr)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".coffin.toml"))
	if err != nil {
		t.Fatal(err)
	}
	want := "format_version = 1\n\n[project]\nvault = \"personal\"\ngroup = \"myapp\"\ndefault_env = \"staging\"\n"
	if string(raw) != want {
		t.Fatalf(".coffin.toml = %q, want %q", raw, want)
	}

	// Linked dir is immediately runnable.
	e.mustRun(t, []string{devMaster}, "", "unlock")
	stdout, _ := e.mustRun(t, nil, "", "run", "sh", "-c", `printf "%s" "$OVERRIDE_ME"`)
	if stdout != "staging" {
		t.Fatalf("run after link = %q", stdout)
	}

	// A second link refuses.
	if _, _, err := e.run(t, nil, "", "link", "myapp"); err == nil ||
		!strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second link = %v", err)
	}

	// Linking a group that does not exist yet warns but writes.
	t.Chdir(t.TempDir())
	_, stderr = e.mustRun(t, nil, "", "link", "ghost")
	if !strings.Contains(stderr, `no env group "ghost"`) {
		t.Fatalf("link ghost stderr = %q", stderr)
	}
}

// TestRunScopedRecipientError pins the UX when a scoped member is not
// in a group's wrap set: the generic decrypt error gains scope context
// without becoming an oracle.
func TestRunScopedRecipientError(t *testing.T) {
	e := newTestEnv(t)
	owner := mustGenerateIdentity(t)
	me := mustGenerateIdentity(t)
	vaultDir := filepath.Join(t.TempDir(), "vault")
	v, err := vault.Create(vaultDir, "team", "team",
		vault.Recipient{Name: "owner", PublicKey: owner.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	ident := func() (age.Identity, error) { return owner, nil }
	data := vault.EnvData{Vars: []vault.EnvVar{{Key: "K", Value: "v"}}}
	if err := v.PutEnv("myapp", "staging", data, ident); err != nil {
		t.Fatal(err)
	}
	if err := v.PutEnv("otherproj", "staging", data, ident); err != nil {
		t.Fatal(err)
	}
	// I am scoped to otherproj only; myapp's key was never wrapped to me.
	if _, err := v.AddRecipient(vault.Recipient{
		Name:      "me",
		PublicKey: me.Recipient().String(),
		Projects:  []string{"otherproj"},
	}, owner); err != nil {
		t.Fatal(err)
	}
	writeRegistry(t, "team", vaultDir)
	saveFastIdentity(t, me)
	enterProjectDir(t, "format_version = 1\n\n[project]\nvault = \"team\"\ngroup = \"myapp\"\ndefault_env = \"staging\"\n")

	_, _, err = e.run(t, []string{devMaster}, "", "run", "true")
	if err == nil || !strings.Contains(err.Error(), "in scope") {
		t.Fatalf("scoped run error = %v, want scope context", err)
	}

	// The covered group still works.
	enterProjectDir(t, "format_version = 1\n\n[project]\nvault = \"team\"\ngroup = \"otherproj\"\ndefault_env = \"staging\"\n")
	stdout, _ := e.mustRun(t, nil, "", "run", "sh", "-c", `printf "%s" "$K"`)
	if stdout != "v" {
		t.Fatalf("scoped covered run = %q", stdout)
	}
}
