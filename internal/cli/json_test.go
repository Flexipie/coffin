package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flexipie/coffin/internal/vault"
)

func TestLsJSON(t *testing.T) {
	e := newTestEnv(t)
	v := setupDevFixture(t, e)
	if err := v.PutPassword("github", vault.PasswordData{Password: "x"}); err != nil {
		t.Fatal(err)
	}

	stdout, _ := e.mustRun(t, nil, "", "ls", "--json")
	var entries []struct {
		Vault     string `json:"vault"`
		Type      string `json:"type"`
		Name      string `json:"name"`
		UpdatedAt string `json:"updated_at"`
	}
	if err := json.Unmarshal([]byte(stdout), &entries); err != nil {
		t.Fatalf("ls --json is not JSON: %v\n%s", err, stdout)
	}
	if len(entries) != 3 {
		t.Fatalf("ls --json = %d entries, want 3", len(entries))
	}
	if entries[0].Type != "env" || entries[0].Name != "myapp/base" || entries[0].Vault != "personal" {
		t.Fatalf("first entry = %+v", entries[0])
	}
	if entries[2].Type != "password" || entries[2].Name != "github" {
		t.Fatalf("last entry = %+v", entries[2])
	}
	if entries[0].UpdatedAt == "" {
		t.Fatal("updated_at missing")
	}

	// Filtered-to-nothing still emits a JSON array, not prose.
	stdout, _ = e.mustRun(t, nil, "", "ls", "--json", "--project", "ghost")
	if strings.TrimSpace(stdout) != "[]" {
		t.Fatalf("empty ls --json = %q, want []", stdout)
	}
}

func TestGetJSON(t *testing.T) {
	e := newTestEnv(t)
	v := setupDevFixture(t, e)
	if err := v.PutPassword("github", vault.PasswordData{
		Username: "octocat", Password: "hunter2", URL: "https://github.com",
	}); err != nil {
		t.Fatal(err)
	}
	e.mustRun(t, []string{devMaster}, "", "unlock")

	// --json without --show must refuse: it prints secrets.
	if _, _, err := e.run(t, nil, "", "get", "github", "--json"); err == nil ||
		!strings.Contains(err.Error(), "--show") {
		t.Fatalf("get --json without --show = %v", err)
	}
	if _, _, err := e.run(t, nil, "", "get", "github", "--json", "--show", "--field", "password"); err == nil ||
		!strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("get --json --field = %v", err)
	}

	stdout, _ := e.mustRun(t, nil, "", "get", "github", "--show", "--json")
	var pw struct {
		Name     string `json:"name"`
		Username string `json:"username"`
		Password string `json:"password"`
		URL      string `json:"url"`
	}
	if err := json.Unmarshal([]byte(stdout), &pw); err != nil {
		t.Fatalf("password --json: %v\n%s", err, stdout)
	}
	if pw.Name != "github" || pw.Username != "octocat" || pw.Password != "hunter2" {
		t.Fatalf("password --json = %+v", pw)
	}

	stdout, _ = e.mustRun(t, nil, "", "get", "myapp/staging", "--show", "--json")
	var env map[string]string
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("env --json: %v\n%s", err, stdout)
	}
	if env["OVERRIDE_ME"] != "staging" || env["STAGING_ONLY"] != "s1" || len(env) != 2 {
		t.Fatalf("env --json = %v", env)
	}
}

func TestDiffJSON(t *testing.T) {
	e := newTestEnv(t)
	setupDevFixture(t, e)
	dir := enterProjectDir(t, devProjectFile)
	e.mustRun(t, []string{devMaster}, "", "unlock")
	e.mustRun(t, nil, "", "render")

	stdout, _, err := e.run(t, nil, "", "diff", "--json")
	if err != nil {
		t.Fatalf("in-sync diff --json errored: %v", err)
	}
	var report struct {
		InSync    bool     `json:"in_sync"`
		Matching  int      `json:"matching"`
		VaultOnly []string `json:"vault_only"`
		FileOnly  []string `json:"file_only"`
		Changed   []struct {
			Key        string `json:"key"`
			VaultValue string `json:"vault_value"`
			LocalValue string `json:"local_value"`
		} `json:"changed"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("diff --json: %v\n%s", err, stdout)
	}
	if !report.InSync || report.Matching != 4 || report.VaultOnly == nil || report.FileOnly == nil {
		t.Fatalf("in-sync report = %+v", report)
	}

	drifted := "DB_URL=postgres://localhost/base\nBASE_ONLY=b1\nOVERRIDE_ME=tampered\nEXTRA=local\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(drifted), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err = e.run(t, nil, "", "diff", "--json")
	if ExitCode(err) != 1 {
		t.Fatalf("drift diff --json ExitCode = %d (%v)", ExitCode(err), err)
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("drift diff --json: %v\n%s", err, stdout)
	}
	if report.InSync || len(report.VaultOnly) != 1 || report.VaultOnly[0] != "STAGING_ONLY" ||
		len(report.FileOnly) != 1 || report.FileOnly[0] != "EXTRA" ||
		len(report.Changed) != 1 || report.Changed[0].Key != "OVERRIDE_ME" {
		t.Fatalf("drift report = %+v", report)
	}
	if report.Changed[0].VaultValue != "" {
		t.Fatal("diff --json leaked values without --values")
	}

	stdout, _, err = e.run(t, nil, "", "diff", "--json", "--values")
	if ExitCode(err) != 1 {
		t.Fatalf("diff --json --values ExitCode = %d", ExitCode(err))
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	if report.Changed[0].VaultValue != "staging" || report.Changed[0].LocalValue != "tampered" {
		t.Fatalf("--values report = %+v", report.Changed)
	}
}
