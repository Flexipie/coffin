package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// initRepo creates a repo with committer identity configured locally
// so tests never depend on the machine's global git config.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	configureCommitter(t, dir)
	return dir
}

func configureCommitter(t *testing.T, dir string) {
	t.Helper()
	for _, kv := range [][2]string{
		{"user.name", "tester"},
		{"user.email", "tester@example.com"},
	} {
		if _, err := run(dir, "config", kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInitAndIsRepo(t *testing.T) {
	dir := initRepo(t)
	if !IsRepo(dir) {
		t.Fatal("IsRepo = false for a fresh repo")
	}
	if IsRepo(t.TempDir()) {
		t.Fatal("IsRepo = true for a plain directory")
	}
}

func TestCommitAndIsDirty(t *testing.T) {
	dir := initRepo(t)
	dirty, err := IsDirty(dir)
	if err != nil || dirty {
		t.Fatalf("fresh repo IsDirty = %v, %v", dirty, err)
	}
	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dirty, err = IsDirty(dir)
	if err != nil || !dirty {
		t.Fatalf("untracked file IsDirty = %v, %v", dirty, err)
	}
	if err := Commit(dir, "add a", "a.txt"); err != nil {
		t.Fatal(err)
	}
	dirty, err = IsDirty(dir)
	if err != nil || dirty {
		t.Fatalf("after commit IsDirty = %v, %v", dirty, err)
	}
	out, err := run(dir, "log", "--format=%s", "-1")
	if err != nil || out != "add a" {
		t.Fatalf("last commit subject = %q, %v", out, err)
	}

	// A deletion staged via the same helper.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := Commit(dir, "rm a", "a.txt"); err != nil {
		t.Fatal(err)
	}
	if dirty, _ := IsDirty(dir); dirty {
		t.Fatal("deletion commit left the tree dirty")
	}

	if err := Commit(dir, "nothing"); err == nil {
		t.Fatal("Commit with no paths must error")
	}
}

func TestCloneRemotePushPull(t *testing.T) {
	// A local bare repo stands in for the remote.
	bare := t.TempDir()
	if _, err := run(bare, "init", "--bare"); err != nil {
		t.Fatal(err)
	}

	a := t.TempDir()
	if err := Clone(bare, filepath.Join(a, "vault")); err != nil {
		t.Fatal(err)
	}
	aDir := filepath.Join(a, "vault")
	configureCommitter(t, aDir)
	hasRemote, err := HasRemote(aDir)
	if err != nil || !hasRemote {
		t.Fatalf("clone HasRemote = %v, %v", hasRemote, err)
	}
	if hasRemote, _ := HasRemote(initRepo(t)); hasRemote {
		t.Fatal("fresh init HasRemote = true")
	}

	if err := os.WriteFile(filepath.Join(aDir, "f.txt"), []byte("v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Commit(aDir, "v1", "f.txt"); err != nil {
		t.Fatal(err)
	}
	if err := Push(aDir); err != nil {
		t.Fatal(err)
	}

	b := filepath.Join(t.TempDir(), "vault")
	if err := Clone(bare, b); err != nil {
		t.Fatal(err)
	}
	configureCommitter(t, b)
	data, err := os.ReadFile(filepath.Join(b, "f.txt"))
	if err != nil || string(data) != "v1\n" {
		t.Fatalf("clone contents = %q, %v", data, err)
	}

	// A pushes v2; B pulls it.
	if err := os.WriteFile(filepath.Join(aDir, "f.txt"), []byte("v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Commit(aDir, "v2", "f.txt"); err != nil {
		t.Fatal(err)
	}
	if err := Push(aDir); err != nil {
		t.Fatal(err)
	}
	if err := Pull(b); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(b, "f.txt"))
	if err != nil || string(data) != "v2\n" {
		t.Fatalf("pulled contents = %q, %v", data, err)
	}
}

func TestErrorsSurfaceGitStderr(t *testing.T) {
	err := Clone(filepath.Join(t.TempDir(), "nonexistent"), filepath.Join(t.TempDir(), "dest"))
	if err == nil {
		t.Fatal("clone of a nonexistent source succeeded")
	}
	if !strings.Contains(err.Error(), "coffin: git clone:") {
		t.Fatalf("error lost its context: %v", err)
	}
}

func TestMain(m *testing.M) {
	if _, err := exec.LookPath("git"); err != nil {
		// No git on this machine; the whole package is untestable.
		os.Exit(0)
	}
	os.Exit(m.Run())
}
