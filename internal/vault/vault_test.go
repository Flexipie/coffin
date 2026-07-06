package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/Flexipie/coffin/internal/crypto"
)

// nulEscape is the six-character TOML escape (backslash, u, four
// zeros) that BurntSushi decodes to a literal NUL inside a basic
// string, the smuggling route the NUL-rejection fixes close off.
const nulEscape = "\x5cu0000"

func newTestVault(t *testing.T) (*Vault, *age.X25519Identity) {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	v, err := Create(filepath.Join(t.TempDir(), "vault"), "personal", "personal",
		Recipient{Name: "tester", PublicKey: id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	return v, id
}

// noIdent is an ident func for paths that must stay encrypt-only.
func noIdent(t *testing.T) func() (age.Identity, error) {
	return func() (age.Identity, error) {
		t.Fatal("ident() called on a path that must not need unlock")
		return nil, nil
	}
}

func TestManifestRoundTrip(t *testing.T) {
	v, _ := newTestVault(t)
	got, err := Open(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Manifest.FormatVersion != 1 ||
		got.Manifest.Vault.ID != v.Manifest.Vault.ID ||
		got.Manifest.Vault.Name != "personal" ||
		got.Manifest.Vault.Kind != "personal" ||
		len(got.Manifest.Recipients) != 1 ||
		got.Manifest.Recipients[0].PublicKey != v.Manifest.Recipients[0].PublicKey {
		t.Fatalf("manifest round trip mismatch: %+v", got.Manifest)
	}
	if len(got.Manifest.Vault.ID) != 32 {
		t.Fatalf("vault id = %q, want 16 bytes of lowercase hex", got.Manifest.Vault.ID)
	}
	if _, err := got.AgeRecipients(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateRefusesExisting(t *testing.T) {
	v, id := newTestVault(t)
	_, err := Create(v.Root, "again", "personal",
		Recipient{Name: "tester", PublicKey: id.Recipient().String()})
	if !errors.Is(err, ErrExists) {
		t.Fatalf("Create over existing vault = %v, want ErrExists", err)
	}
}

func TestPasswordRoundTrip(t *testing.T) {
	v, id := newTestVault(t)
	want := PasswordData{
		Username: "octocat",
		Password: "hunter2",
		URL:      "https://github.com",
		Notes:    "work account",
		TOTPSeed: "JBSWY3DP",
	}
	if err := v.PutPassword("GitHub", want); err != nil {
		t.Fatal(err)
	}
	// Normalization means the mixed-case name reads back too.
	got, err := v.GetPassword("github", id)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip mismatch: got %+v want %+v", got, want)
	}

	info, err := os.Stat(v.passwordPath("github"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("entry file mode = %o, want 0600", perm)
	}

	exists, err := v.PasswordExists("github")
	if err != nil || !exists {
		t.Fatalf("PasswordExists = %v, %v", exists, err)
	}

	if _, err := v.GetPassword("missing", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetPassword(missing) = %v, want ErrNotFound", err)
	}
	if err := v.RemovePassword("github"); err != nil {
		t.Fatal(err)
	}
	if err := v.RemovePassword("github"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second RemovePassword = %v, want ErrNotFound", err)
	}
}

func TestPasswordFreshKeyPerWrite(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.PutPassword("x", PasswordData{Password: "one"}); err != nil {
		t.Fatal(err)
	}
	first, err := readEntryFile(v.passwordPath("x"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.PutPassword("x", PasswordData{Password: "two"}); err != nil {
		t.Fatal(err)
	}
	second, err := readEntryFile(v.passwordPath("x"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Key.Wrapped == second.Key.Wrapped {
		t.Fatal("rewrite reused the wrapped data key; every write must generate a fresh one")
	}
}

func TestEnvRoundTripAndKeyReuse(t *testing.T) {
	v, id := newTestVault(t)
	want := EnvData{Vars: []EnvVar{
		{Key: "Z_LAST", Value: "26"},
		{Key: "A_FIRST", Value: "1"},
		{Key: "M_MID", Value: "13"},
		{Key: "EMPTY", Value: ""},
	}}
	// New group: must be encrypt-only.
	if err := v.PutEnv("myapp/api", "staging", want, noIdent(t)); err != nil {
		t.Fatal(err)
	}
	got, err := v.GetEnv("myapp/api", "staging", id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Vars) != len(want.Vars) {
		t.Fatalf("got %d vars, want %d", len(got.Vars), len(want.Vars))
	}
	for i := range want.Vars {
		if got.Vars[i] != want.Vars[i] {
			t.Fatalf("var %d = %+v, want %+v (order must be preserved)", i, got.Vars[i], want.Vars[i])
		}
	}

	// Existing group: ident must be consulted, key.toml key reused.
	identCalled := false
	err = v.PutEnv("myapp/api", "prod", EnvData{Vars: []EnvVar{{Key: "K", Value: "v"}}},
		func() (age.Identity, error) { identCalled = true; return id, nil })
	if err != nil {
		t.Fatal(err)
	}
	if !identCalled {
		t.Fatal("PutEnv on an existing group did not call ident()")
	}
	if _, err := v.GetEnv("myapp/api", "prod", id); err != nil {
		t.Fatal(err)
	}

	exists, err := v.EnvGroupExists("myapp/api")
	if err != nil || !exists {
		t.Fatalf("EnvGroupExists = %v, %v", exists, err)
	}
	if _, err := v.GetEnv("myapp/api", "dev", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetEnv(missing overlay) = %v, want ErrNotFound", err)
	}
	if _, err := v.GetEnv("nosuch", "dev", id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetEnv(missing group) = %v, want ErrNotFound", err)
	}
}

func TestRemoveEnvLastOverlayCleanup(t *testing.T) {
	v, id := newTestVault(t)
	put := func(env string) {
		t.Helper()
		err := v.PutEnv("myapp/api", env, EnvData{Vars: []EnvVar{{Key: "K", Value: env}}},
			func() (age.Identity, error) { return id, nil })
		if err != nil {
			t.Fatal(err)
		}
	}
	put("staging")
	put("prod")

	if err := v.RemoveEnv("myapp/api", "staging"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(v.envKeyPath("myapp/api")); err != nil {
		t.Fatalf("key.toml should survive while overlays remain: %v", err)
	}

	if err := v.RemoveEnv("myapp/api", "prod"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(v.envKeyPath("myapp/api")); !os.IsNotExist(err) {
		t.Fatalf("key.toml should be removed with the last overlay: %v", err)
	}
	if _, err := os.Stat(filepath.Join(v.Root, "env")); !os.IsNotExist(err) {
		t.Fatalf("empty env dirs should be pruned: %v", err)
	}
	if err := v.RemoveEnv("myapp/api", "prod"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RemoveEnv on gone overlay = %v, want ErrNotFound", err)
	}
}

// TestTamperMatrix encodes FORMAT.md's file-shuffling resistance: every
// tamper is ErrDecrypt, except a version bump which is the one distinct
// pre-crypto error.
func TestTamperMatrix(t *testing.T) {
	v, id := newTestVault(t)
	if err := v.PutEnv("myapp", "staging", EnvData{Vars: []EnvVar{{Key: "A", Value: "1"}}}, noIdent(t)); err != nil {
		t.Fatal(err)
	}
	err := v.PutEnv("myapp", "prod", EnvData{Vars: []EnvVar{{Key: "A", Value: "2"}}},
		func() (age.Identity, error) { return id, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := v.PutPassword("github", PasswordData{Password: "hunter2"}); err != nil {
		t.Fatal(err)
	}

	t.Run("cross-entry rename", func(t *testing.T) {
		// staging.toml's bytes served as prod.toml: same group key,
		// different canonical path, must fail.
		staging, err := os.ReadFile(v.envPath("myapp", "staging"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(v.envPath("myapp", "prod"), staging, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := v.GetEnv("myapp", "prod", id); !errors.Is(err, crypto.ErrDecrypt) {
			t.Fatalf("renamed overlay opened: %v, want ErrDecrypt", err)
		}
	})

	t.Run("edited updated_at", func(t *testing.T) {
		path := v.passwordPath("github")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		f, err := readEntryFile(path)
		if err != nil {
			t.Fatal(err)
		}
		oldTS := f.UpdatedAt.Format(time.RFC3339)
		newTS := f.UpdatedAt.Add(time.Hour).Format(time.RFC3339)
		tampered := strings.Replace(string(raw), oldTS, newTS, 1)
		if tampered == string(raw) {
			t.Fatal("test bug: timestamp not found in file")
		}
		if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := v.GetPassword("github", id); !errors.Is(err, crypto.ErrDecrypt) {
			t.Fatalf("entry with edited updated_at opened: %v, want ErrDecrypt", err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("cross-vault transplant", func(t *testing.T) {
		other, _ := newTestVault(t)
		// Same recipient so the key unwraps; only vault.id differs.
		other.Manifest.Recipients = v.Manifest.Recipients
		if err := other.saveManifest(); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(v.passwordPath("github"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(other.Root, "passwords"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(other.passwordPath("github"), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := other.GetPassword("github", id); !errors.Is(err, crypto.ErrDecrypt) {
			t.Fatalf("transplanted entry opened in another vault: %v, want ErrDecrypt", err)
		}
	})

	t.Run("NUL in type header", func(t *testing.T) {
		// The unicode escape smuggles a literal NUL into the decoded
		// type; it must surface as ErrDecrypt, never reach the AAD
		// builder (which panics on NUL by contract).
		path := v.passwordPath("github")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		tampered := strings.Replace(string(raw), `type = "password"`, `type = "password`+nulEscape+`x"`, 1)
		if tampered == string(raw) {
			t.Fatal("test bug: type header not found in file")
		}
		if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := v.GetPassword("github", id); !errors.Is(err, crypto.ErrDecrypt) {
			t.Fatalf("entry with NUL in type header = %v, want ErrDecrypt", err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("format_version bump", func(t *testing.T) {
		path := v.passwordPath("github")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		bumped := strings.Replace(string(raw), "format_version = 1", "format_version = 2", 1)
		if err := os.WriteFile(path, []byte(bumped), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = v.GetPassword("github", id)
		var uv *UnknownVersionError
		if !errors.As(err, &uv) {
			t.Fatalf("version bump = %v, want UnknownVersionError", err)
		}
		if uv.Version != 2 {
			t.Fatalf("UnknownVersionError.Version = %d, want 2", uv.Version)
		}
		if errors.Is(err, crypto.ErrDecrypt) {
			t.Fatal("version mismatch must never be a decrypt error")
		}
	})
}

func TestOpenRejectsBadVaultID(t *testing.T) {
	v, _ := newTestVault(t)
	path := filepath.Join(v.Root, manifestName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The last entry decodes to 31 hex chars plus a literal NUL via
	// the TOML unicode escape, the shape that would panic in the AAD
	// builder if it got through.
	for _, bad := range []string{
		"",
		"abc",
		strings.Repeat("A", 32),
		strings.Repeat("a", 31) + nulEscape,
	} {
		tampered := strings.Replace(string(raw), v.Manifest.Vault.ID, bad, 1)
		if tampered == string(raw) {
			t.Fatal("test bug: vault id not found in manifest")
		}
		if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(v.Root); err == nil || !strings.Contains(err.Error(), "corrupt") {
			t.Fatalf("Open with vault id %q = %v, want corrupt-manifest error", bad, err)
		}
	}
}

func TestList(t *testing.T) {
	v, id := newTestVault(t)
	fixed := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	v.Now = func() time.Time { return fixed }
	if err := v.PutPassword("github", PasswordData{Password: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := v.PutEnv("myapp/api", "staging", EnvData{Vars: []EnvVar{{Key: "A", Value: "1"}}}, noIdent(t)); err != nil {
		t.Fatal(err)
	}
	err := v.PutEnv("myapp/api", "prod", EnvData{Vars: []EnvVar{{Key: "A", Value: "2"}}},
		func() (age.Identity, error) { return id, nil })
	if err != nil {
		t.Fatal(err)
	}

	entries, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	want := []EntryRef{
		{VaultName: "personal", VaultRoot: v.Root, Type: TypeEnv, Path: "env/myapp/api/prod", Name: "myapp/api/prod", UpdatedAt: fixed},
		{VaultName: "personal", VaultRoot: v.Root, Type: TypeEnv, Path: "env/myapp/api/staging", Name: "myapp/api/staging", UpdatedAt: fixed},
		{VaultName: "personal", VaultRoot: v.Root, Type: TypePassword, Path: "passwords/github", Name: "github", UpdatedAt: fixed},
	}
	if len(entries) != len(want) {
		t.Fatalf("List returned %d entries, want %d (key.toml must be skipped): %+v", len(entries), len(want), entries)
	}
	for i := range want {
		got := entries[i]
		if got.Path != want[i].Path || got.Name != want[i].Name || got.Type != want[i].Type ||
			got.VaultName != want[i].VaultName || !got.UpdatedAt.Equal(want[i].UpdatedAt) {
			t.Fatalf("entry %d = %+v, want %+v", i, got, want[i])
		}
	}
}

func TestListSkipsOrphanEnvOverlay(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.PutEnv("myapp", "staging", EnvData{Vars: []EnvVar{{Key: "A", Value: "1"}}}, noIdent(t)); err != nil {
		t.Fatal(err)
	}
	// A hand-crafted overlay directly under env/ has no group; no
	// coffin writes this shape, and List must not surface it (a
	// slash-less env name would break group/env splitting downstream).
	orphan := "format_version = 1\ntype = \"env\"\nname = \"orphan\"\nupdated_at = 2026-07-06T12:00:00Z\n"
	if err := os.WriteFile(filepath.Join(v.Root, "env", "orphan.toml"), []byte(orphan), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name == "orphan" {
			t.Fatalf("List surfaced the groupless overlay: %+v", e)
		}
	}
	if len(entries) != 1 {
		t.Fatalf("List returned %d entries, want 1: %+v", len(entries), entries)
	}
}
