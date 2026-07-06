package vault

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// The golden vault under testdata/golden-vault is a committed
// mini-vault sealed to the pinned test identity. It pins two things:
// the read path (files written by this exact code, and by every past
// version, must keep decrypting) and the header byte shape (any drift
// in serialization shows up as a diff here). Regenerate with:
//
//	COFFIN_REGEN_GOLDEN=1 go test ./internal/vault -run TestGoldenVault
const (
	goldenRoot    = "testdata/golden-vault"
	goldenVaultID = "9f3a1c0d2b4e5f60718293a4b5c6d7e8"
)

var (
	goldenTime     = time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC)
	goldenPassword = PasswordData{
		Username: "octocat",
		Password: "hunter2",
		URL:      "https://github.com",
	}
	goldenEnv = EnvData{Vars: []EnvVar{
		{Key: "DB_URL", Value: "postgres://localhost/dev"},
		{Key: "API_KEY", Value: "sekrit"},
	}}
)

func goldenIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	raw, err := os.ReadFile("testdata/golden_identity.txt")
	if err != nil {
		t.Fatal(err)
	}
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestGoldenVault(t *testing.T) {
	id := goldenIdentity(t)
	if os.Getenv("COFFIN_REGEN_GOLDEN") != "" {
		regenGolden(t, id)
	}

	v, err := Open(goldenRoot)
	if err != nil {
		t.Fatal(err)
	}
	if v.Manifest.Vault.ID != goldenVaultID {
		t.Fatalf("golden vault id = %q, want %q", v.Manifest.Vault.ID, goldenVaultID)
	}

	pw, err := v.GetPassword("github", id)
	if err != nil {
		t.Fatalf("golden password no longer decrypts: %v", err)
	}
	if pw != goldenPassword {
		t.Fatalf("golden password = %+v, want %+v", pw, goldenPassword)
	}

	env, err := v.GetEnv("myapp/api", "staging", id)
	if err != nil {
		t.Fatalf("golden env no longer decrypts: %v", err)
	}
	if len(env.Vars) != 2 || env.Vars[0] != goldenEnv.Vars[0] || env.Vars[1] != goldenEnv.Vars[1] {
		t.Fatalf("golden env = %+v, want %+v", env, goldenEnv)
	}

	// Header byte-shape pin: the serialized form is part of the format
	// contract (the timestamp doubles as AAD input).
	raw, err := os.ReadFile(filepath.Join(goldenRoot, "passwords", "github.toml"))
	if err != nil {
		t.Fatal(err)
	}
	entry := string(raw)
	wantHeader := "format_version = 1\n" +
		"type = \"password\"\n" +
		"name = \"github\"\n" +
		"updated_at = 2026-07-06T00:00:00Z\n" +
		"\n[key]\nwrapped = \"\"\"\n-----BEGIN AGE ENCRYPTED FILE-----\n"
	if !strings.HasPrefix(entry, wantHeader) {
		t.Fatalf("golden entry header shape drifted:\n%s", entry[:min(len(entry), len(wantHeader)+40)])
	}
	for _, re := range []string{
		`(?s)-----END AGE ENCRYPTED FILE-----\n"""\n`,
		`(?m)^\[payload\]$`,
		`(?m)^nonce = "[A-Za-z0-9+/]+={0,2}"$`,
		`(?m)^ciphertext = "[A-Za-z0-9+/]+={0,2}"$`,
	} {
		if !regexp.MustCompile(re).MatchString(entry) {
			t.Fatalf("golden entry does not match %q:\n%s", re, entry)
		}
	}

	keyRaw, err := os.ReadFile(filepath.Join(goldenRoot, "env", "myapp", "api", "key.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(keyRaw), "format_version = 1\ntype = \"env-key\"\n\n[key]\nwrapped = \"\"\"\n") {
		t.Fatalf("golden key.toml shape drifted:\n%s", keyRaw)
	}

	overlayRaw, err := os.ReadFile(filepath.Join(goldenRoot, "env", "myapp", "api", "staging.toml"))
	if err != nil {
		t.Fatal(err)
	}
	wantOverlay := "format_version = 1\n" +
		"type = \"env\"\n" +
		"name = \"staging\"\n" +
		"updated_at = 2026-07-06T00:00:00Z\n" +
		"\n[payload]\n"
	if !strings.HasPrefix(string(overlayRaw), wantOverlay) {
		t.Fatalf("golden overlay shape drifted:\n%s", overlayRaw)
	}

	entries, err := v.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("golden vault List = %d entries, want 2: %+v", len(entries), entries)
	}
}

func regenGolden(t *testing.T, id *age.X25519Identity) {
	t.Helper()
	if err := os.RemoveAll(goldenRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(goldenRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	v := &Vault{
		Root: goldenRoot,
		Manifest: Manifest{
			FormatVersion: FormatVersion,
			Vault: VaultInfo{
				ID:        goldenVaultID,
				Name:      "golden",
				Kind:      "personal",
				CreatedAt: goldenTime,
			},
			Recipients: []Recipient{{
				Name:      "golden",
				PublicKey: id.Recipient().String(),
				AddedAt:   goldenTime,
			}},
		},
		Now: func() time.Time { return goldenTime },
	}
	if err := v.saveManifest(); err != nil {
		t.Fatal(err)
	}
	if err := v.PutPassword("github", goldenPassword); err != nil {
		t.Fatal(err)
	}
	if err := v.PutEnv("myapp/api", "staging", goldenEnv, noIdent(t)); err != nil {
		t.Fatal(err)
	}
	t.Log("regenerated golden vault")
}
