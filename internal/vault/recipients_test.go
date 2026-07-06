package vault

import (
	"errors"
	"os"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/Flexipie/coffin/internal/crypto"
)

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// seedVault builds the fixture both recipient-op tests share: one
// password, one group under myapp, one group elsewhere.
func seedVault(t *testing.T) (*Vault, *age.X25519Identity) {
	t.Helper()
	v, alice := newTestVault(t)
	if err := v.PutPassword("github", PasswordData{Password: "hunter2"}); err != nil {
		t.Fatal(err)
	}
	if err := v.PutEnv("myapp/api", "staging", EnvData{Vars: []EnvVar{{Key: "A", Value: "1"}}}, noIdent(t)); err != nil {
		t.Fatal(err)
	}
	if err := v.PutEnv("otherapp", "prod", EnvData{Vars: []EnvVar{{Key: "B", Value: "2"}}}, noIdent(t)); err != nil {
		t.Fatal(err)
	}
	return v, alice
}

func TestAddRecipientFull(t *testing.T) {
	v, alice := seedVault(t)
	bob := newIdentity(t)

	before, err := os.ReadFile(v.passwordPath("github"))
	if err != nil {
		t.Fatal(err)
	}

	touched, err := v.AddRecipient(Recipient{Name: "bob", PublicKey: bob.Recipient().String()}, alice)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"passwords/github.toml":  true,
		"env/myapp/api/key.toml": true,
		"env/otherapp/key.toml":  true,
		manifestName:             true,
	}
	if len(touched) != len(want) {
		t.Fatalf("touched = %v, want the 4 files", touched)
	}
	for _, p := range touched {
		if !want[p] {
			t.Fatalf("unexpected touched path %q", p)
		}
	}

	// Bob reads everything; payloads were rewrapped, not re-encrypted.
	for _, id := range []age.Identity{alice, bob} {
		if pw, err := v.GetPassword("github", id); err != nil || pw.Password != "hunter2" {
			t.Fatalf("GetPassword after add = %+v, %v", pw, err)
		}
		if _, err := v.GetEnv("myapp/api", "staging", id); err != nil {
			t.Fatal(err)
		}
		if _, err := v.GetEnv("otherapp", "prod", id); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadFile(v.passwordPath("github"))
	if err != nil {
		t.Fatal(err)
	}
	sectionOf := func(raw []byte) string {
		s := string(raw)
		return s[strings.Index(s, "[payload]"):]
	}
	if sectionOf(before) != sectionOf(after) {
		t.Fatal("add recipient rewrote the payload; it must only rewrap the key")
	}

	// A vault reopened from disk sees the new recipient.
	got, err := Open(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Manifest.Recipients) != 2 || !got.Manifest.Recipients[1].Full() {
		t.Fatalf("reloaded recipients = %+v", got.Manifest.Recipients)
	}
}

func TestAddRecipientScoped(t *testing.T) {
	v, alice := seedVault(t)
	carol := newIdentity(t)

	touched, err := v.AddRecipient(Recipient{
		Name:      "carol",
		PublicKey: carol.Recipient().String(),
		Projects:  []string{"MyApp"}, // normalization applies to prefixes too
	}, alice)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range touched {
		if p == "passwords/github.toml" || p == "env/otherapp/key.toml" {
			t.Fatalf("scoped add rewrapped out-of-scope file %q", p)
		}
	}

	// Carol reads only her project.
	if _, err := v.GetEnv("myapp/api", "staging", carol); err != nil {
		t.Fatalf("scoped recipient cannot read in-scope group: %v", err)
	}
	if _, err := v.GetPassword("github", carol); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("scoped recipient read a password: %v", err)
	}
	if _, err := v.GetEnv("otherapp", "prod", carol); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("scoped recipient read an out-of-scope group: %v", err)
	}

	// Future writes honor the scope in both directions.
	if err := v.PutPassword("new-secret", PasswordData{Password: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.GetPassword("new-secret", carol); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("scoped recipient read a new password: %v", err)
	}
	if err := v.PutEnv("myapp/worker", "dev", EnvData{Vars: []EnvVar{{Key: "C", Value: "3"}}}, noIdent(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.GetEnv("myapp/worker", "dev", carol); err != nil {
		t.Fatalf("scoped recipient cannot read a new in-scope group: %v", err)
	}
	// Prefixes match whole segments: myapp does not cover myapp2.
	if err := v.PutEnv("myapp2", "dev", EnvData{Vars: []EnvVar{{Key: "D", Value: "4"}}}, noIdent(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.GetEnv("myapp2", "dev", carol); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("prefix myapp leaked into myapp2: %v", err)
	}
}

func TestAddRecipientValidation(t *testing.T) {
	v, alice := seedVault(t)
	bob := newIdentity(t)
	pub := bob.Recipient().String()

	if _, err := v.AddRecipient(Recipient{Name: "", PublicKey: pub}, alice); err == nil {
		t.Fatal("empty name accepted")
	}
	if _, err := v.AddRecipient(Recipient{Name: "bob", PublicKey: "not-a-key"}, alice); err == nil {
		t.Fatal("invalid public key accepted")
	}
	if _, err := v.AddRecipient(Recipient{Name: "tester", PublicKey: pub}, alice); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate name = %v, want ErrExists", err)
	}
	alicePub := v.Manifest.Recipients[0].PublicKey
	if _, err := v.AddRecipient(Recipient{Name: "bob", PublicKey: alicePub}, alice); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate public key = %v, want ErrExists", err)
	}
	if _, err := v.AddRecipient(Recipient{Name: "bob", PublicKey: pub, Projects: []string{}}, alice); err == nil {
		t.Fatal("empty projects list accepted")
	}
	if _, err := v.AddRecipient(Recipient{Name: "bob", PublicKey: pub, Projects: []string{"BAD SLUG!"}}, alice); err == nil {
		t.Fatal("invalid project prefix accepted")
	}
}

func TestRevokeScopedRotatesOnlyCoveredGroups(t *testing.T) {
	v, alice := seedVault(t)
	carol := newIdentity(t)
	if _, err := v.AddRecipient(Recipient{
		Name: "carol", PublicKey: carol.Recipient().String(), Projects: []string{"myapp"},
	}, alice); err != nil {
		t.Fatal(err)
	}

	pwBefore, err := os.ReadFile(v.passwordPath("github"))
	if err != nil {
		t.Fatal(err)
	}

	touched, rotated, err := v.RevokeRecipient("carol", alice)
	if err != nil {
		t.Fatal(err)
	}
	wantRotated := []string{"env/myapp/api/staging"}
	if len(rotated) != 1 || rotated[0] != wantRotated[0] {
		t.Fatalf("rotated = %v, want %v", rotated, wantRotated)
	}
	for _, p := range touched {
		if strings.HasPrefix(p, "passwords/") || strings.HasPrefix(p, "env/otherapp/") {
			t.Fatalf("scoped revoke touched out-of-scope file %q", p)
		}
	}
	pwAfter, err := os.ReadFile(v.passwordPath("github"))
	if err != nil {
		t.Fatal(err)
	}
	if string(pwBefore) != string(pwAfter) {
		t.Fatal("scoped revoke rewrote a password entry")
	}

	// Carol lost the rotated group; alice still reads it.
	if _, err := v.GetEnv("myapp/api", "staging", carol); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("revoked recipient still reads the rotated group: %v", err)
	}
	got, err := v.GetEnv("myapp/api", "staging", alice)
	if err != nil || len(got.Vars) != 1 || got.Vars[0].Value != "1" {
		t.Fatalf("remaining recipient lost the rotated group: %+v, %v", got, err)
	}
}

func TestRevokeFullRotatesEverything(t *testing.T) {
	v, alice := seedVault(t)
	bob := newIdentity(t)
	if _, err := v.AddRecipient(Recipient{Name: "bob", PublicKey: bob.Recipient().String()}, alice); err != nil {
		t.Fatal(err)
	}
	// Bob can read before the revoke; this is the access being cut.
	if _, err := v.GetPassword("github", bob); err != nil {
		t.Fatal(err)
	}

	_, rotated, err := v.RevokeRecipient("bob", alice)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"passwords/github":      true,
		"env/myapp/api/staging": true,
		"env/otherapp/prod":     true,
	}
	if len(rotated) != len(want) {
		t.Fatalf("rotated = %v, want all 3 entries", rotated)
	}
	for _, p := range rotated {
		if !want[p] {
			t.Fatalf("unexpected rotated path %q", p)
		}
	}

	if _, err := v.GetPassword("github", bob); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("revoked full recipient still reads a password: %v", err)
	}
	if _, err := v.GetEnv("myapp/api", "staging", bob); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("revoked full recipient still reads a group: %v", err)
	}
	if pw, err := v.GetPassword("github", alice); err != nil || pw.Password != "hunter2" {
		t.Fatalf("remaining recipient lost a rotated password: %+v, %v", pw, err)
	}
	if _, err := v.GetEnv("otherapp", "prod", alice); err != nil {
		t.Fatal(err)
	}

	// The manifest no longer lists bob.
	got, err := Open(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Manifest.Recipients) != 1 || got.Manifest.Recipients[0].Name != "tester" {
		t.Fatalf("reloaded recipients = %+v", got.Manifest.Recipients)
	}
}

func TestRevokeGuards(t *testing.T) {
	v, alice := seedVault(t)
	if _, _, err := v.RevokeRecipient("nobody", alice); err == nil {
		t.Fatal("revoking an unknown name succeeded")
	}
	if _, _, err := v.RevokeRecipient("tester", alice); err == nil ||
		!strings.Contains(err.Error(), "full recipient") {
		t.Fatalf("revoking the last full recipient = %v, want a guard error", err)
	}

	// With only a scoped recipient remaining the guard still fires.
	carol := newIdentity(t)
	if _, err := v.AddRecipient(Recipient{
		Name: "carol", PublicKey: carol.Recipient().String(), Projects: []string{"myapp"},
	}, alice); err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.RevokeRecipient("tester", alice); err == nil {
		t.Fatal("revoking the only full recipient succeeded despite a scoped one remaining")
	}
}
