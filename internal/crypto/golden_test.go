package crypto

import (
	"encoding/base64"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// TestGoldenEntry guards against format drift: a pinned on-disk entry
// (generated once, committed under testdata/) must keep decrypting
// with the AAD recomputed from its pinned header fields. The exact
// TOML serialization pin moves to internal/vault in Phase 2, which
// reuses this fixture; here we verify the cryptographic contract.
func TestGoldenEntry(t *testing.T) {
	raw, err := os.ReadFile("testdata/golden_entry.toml")
	if err != nil {
		t.Fatal(err)
	}
	entry := string(raw)
	secret, err := os.ReadFile("testdata/golden_identity.txt")
	if err != nil {
		t.Fatal(err)
	}

	// Pinned header fields. These must match the fixture byte for
	// byte; if the fixture is regenerated with different values this
	// test is the tripwire.
	const (
		vaultID = "9f3a1c0d2b4e5f60718293a4b5c6d7e8"
		path    = "passwords/github"
		typ     = "password"
	)
	updatedAt := time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC)
	wantPlaintext := `{"username":"octocat","password":"hunter2","url":"https://github.com","notes":"","totp_seed":""}`

	for _, pin := range []string{
		"format_version = 1",
		`type = "password"`,
		`name = "github"`,
		"updated_at = 2026-07-06T00:00:00Z",
	} {
		if !strings.Contains(entry, pin) {
			t.Fatalf("fixture missing pinned header line %q", pin)
		}
	}

	wrapped := extractGolden(t, entry, `(?s)wrapped = """\n(.*?)"""`)
	nonce := b64Golden(t, extractGolden(t, entry, `nonce = "([^"]+)"`))
	ct := b64Golden(t, extractGolden(t, entry, `ciphertext = "([^"]+)"`))

	id, err := age.ParseX25519Identity(strings.TrimSpace(string(secret)))
	if err != nil {
		t.Fatal(err)
	}
	dataKey, err := UnwrapKey(wrapped, id)
	if err != nil {
		t.Fatalf("golden wrapped key no longer unwraps: %v", err)
	}
	got, err := Open(dataKey, nonce, ct, EntryAAD(vaultID, typ, path, updatedAt))
	if err != nil {
		t.Fatalf("golden payload no longer opens: %v", err)
	}
	if string(got) != wantPlaintext {
		t.Fatalf("golden plaintext = %q, want %q", got, wantPlaintext)
	}
}

func extractGolden(t *testing.T, s, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("fixture does not match %q", pattern)
	}
	return m[1]
}

func b64Golden(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("fixture base64: %v", err)
	}
	return b
}
