package project

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flexipie/coffin/internal/vault"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const validProject = `format_version = 1

[project]
vault = "team"
group = "myapp"
default_env = "dev"
`

func TestFindInCwd(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, FileName), validProject)
	pf, err := Find(dir)
	if err != nil {
		t.Fatal(err)
	}
	if pf.Vault != "team" || pf.Group != "myapp" || pf.DefaultEnv != "dev" {
		t.Fatalf("unexpected file: %+v", pf)
	}
	if pf.Dir != dir {
		t.Fatalf("Dir = %q, want %q", pf.Dir, dir)
	}
}

func TestFindWalksUp(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, FileName), validProject)
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	pf, err := Find(deep)
	if err != nil {
		t.Fatal(err)
	}
	if pf.Dir != root {
		t.Fatalf("Dir = %q, want %q", pf.Dir, root)
	}
}

func TestFindNotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := Find(dir)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error does not wrap ErrNotFound: %v", err)
	}
	if !strings.Contains(err.Error(), "coffin link") {
		t.Fatalf("error should hint at coffin link: %v", err)
	}
}

func TestFindHintsWhenInsideVault(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "coffin.toml"), "format_version = 1\n")
	_, err := Find(dir)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "looks like a coffin vault") {
		t.Fatalf("error should mention the vault manifest: %v", err)
	}
}

func TestLoadValidation(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantErr string
	}{
		{"missing group", "format_version = 1\n\n[project]\nvault = \"team\"\n", "missing project.group"},
		{"invalid group", "format_version = 1\n\n[project]\ngroup = \"My App!\"\n", "invalid group"},
		{"multi-segment default_env", "format_version = 1\n\n[project]\ngroup = \"myapp\"\ndefault_env = \"a/b\"\n", "single segment"},
		{"reserved default_env", "format_version = 1\n\n[project]\ngroup = \"myapp\"\ndefault_env = \"key\"\n", "reserved"},
		{"unknown version", "format_version = 99\n\n[project]\ngroup = \"myapp\"\n", "newer"},
		{"missing version", "[project]\ngroup = \"myapp\"\n", "format_version"},
		{"malformed toml", "format_version = 1\n[project\n", "parse"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), FileName)
			writeFile(t, path, tc.content)
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadOmittedVaultAndDefaultEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	writeFile(t, path, "format_version = 1\n\n[project]\ngroup = \"myapp/api\"\n")
	pf, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if pf.Vault != "" || pf.DefaultEnv != "" || pf.Group != "myapp/api" {
		t.Fatalf("unexpected file: %+v", pf)
	}
}

func vars(pairs ...string) vault.EnvData {
	var d vault.EnvData
	for i := 0; i+1 < len(pairs); i += 2 {
		d.Vars = append(d.Vars, vault.EnvVar{Key: pairs[i], Value: pairs[i+1]})
	}
	return d
}

func TestMerge(t *testing.T) {
	cases := []struct {
		name          string
		base, overlay vault.EnvData
		want          vault.EnvData
	}{
		{
			"override in place preserves base order",
			vars("A", "1", "B", "2", "C", "3"),
			vars("B", "9"),
			vars("A", "1", "B", "9", "C", "3"),
		},
		{
			"overlay-only keys append in overlay order",
			vars("A", "1"),
			vars("C", "3", "B", "2"),
			vars("A", "1", "C", "3", "B", "2"),
		},
		{
			"empty base",
			vars(),
			vars("A", "1"),
			vars("A", "1"),
		},
		{
			"empty overlay",
			vars("A", "1"),
			vars(),
			vars("A", "1"),
		},
		{
			"duplicate key within one side last wins",
			vars("A", "1", "A", "2"),
			vars("B", "3", "B", "4"),
			vars("A", "2", "B", "4"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Merge(tc.base, tc.overlay)
			if len(got.Vars) != len(tc.want.Vars) {
				t.Fatalf("got %v, want %v", got.Vars, tc.want.Vars)
			}
			for i := range got.Vars {
				if got.Vars[i] != tc.want.Vars[i] {
					t.Fatalf("var %d: got %v, want %v", i, got.Vars, tc.want.Vars)
				}
			}
		})
	}
}
