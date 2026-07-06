package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Flexipie/coffin/internal/crypto"
	"github.com/Flexipie/coffin/internal/vault"
)

func setTempConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return filepath.Join(dir, "coffin")
}

// fastKDFParams keeps argon2id cheap in tests; production always uses
// crypto.NewKDFParams.
func fastKDFParams(t *testing.T) crypto.KDFParams {
	t.Helper()
	p, err := crypto.NewKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	p.Time = 1
	p.MemoryKiB = 8 * 1024
	return p
}

func TestDirRespectsXDG(t *testing.T) {
	want := setTempConfig(t)
	got, err := Dir()
	if err != nil || got != want {
		t.Fatalf("Dir() = %q, %v; want %q", got, err, want)
	}
}

func TestLoadDefaultsWhenMissing(t *testing.T) {
	setTempConfig(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Settings.SessionTTLMinutes != 15 || c.Settings.ClipboardClearSeconds != 30 || len(c.Vaults) != 0 {
		t.Fatalf("defaults = %+v", c)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := setTempConfig(t)
	c := Default()
	if err := c.AddVault("personal", "/tmp/vault", "personal"); err != nil {
		t.Fatal(err)
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("config dir mode = %o, want 0700", perm)
	}
	info, err = os.Stat(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config file mode = %o, want 0600", perm)
	}

	got, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	ref, ok := got.FindVault("personal")
	if !ok || ref.Path != "/tmp/vault" || ref.Kind != "personal" {
		t.Fatalf("FindVault = %+v, %v", ref, ok)
	}
	if _, ok := got.FindVault("nope"); ok {
		t.Fatal("FindVault found a vault that does not exist")
	}
}

func TestAddVaultRejectsDuplicate(t *testing.T) {
	c := Default()
	if err := c.AddVault("personal", "/a", "personal"); err != nil {
		t.Fatal(err)
	}
	if err := c.AddVault("personal", "/b", "personal"); err == nil {
		t.Fatal("duplicate vault name accepted")
	}
}

func TestLoadRejectsUnknownVersion(t *testing.T) {
	dir := setTempConfig(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("format_version = 9\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	var uv *vault.UnknownVersionError
	if !errors.As(err, &uv) || uv.Version != 9 {
		t.Fatalf("Load = %v, want UnknownVersionError{Version: 9}", err)
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	dir := setTempConfig(t)

	exists, err := IdentityExists()
	if err != nil || exists {
		t.Fatalf("IdentityExists on empty config = %v, %v", exists, err)
	}
	if _, err := LoadIdentity(); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("LoadIdentity with no file = %v, want ErrNoIdentity", err)
	}

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.SealIdentity(id, []byte("correct horse"), fastKDFParams(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIdentity(enc); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(dir, "identity.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("identity file mode = %o, want 0600", perm)
	}

	exists, err = IdentityExists()
	if err != nil || !exists {
		t.Fatalf("IdentityExists after save = %v, %v", exists, err)
	}

	loaded, err := LoadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	opened, err := crypto.OpenIdentity(loaded, []byte("correct horse"))
	if err != nil {
		t.Fatalf("round-tripped identity does not open: %v", err)
	}
	if opened.Recipient().String() != id.Recipient().String() {
		t.Fatal("round-tripped identity has a different public key")
	}
	if _, err := crypto.OpenIdentity(loaded, []byte("wrong password")); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("wrong password = %v, want ErrDecrypt", err)
	}
}

func TestLoadIdentityRejectsNULPublicKey(t *testing.T) {
	dir := setTempConfig(t)

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.SealIdentity(id, []byte("correct horse"), fastKDFParams(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveIdentity(enc); err != nil {
		t.Fatal(err)
	}

	// The TOML unicode escape (backslash, u, four zeros) decodes to a
	// literal NUL in public_key, which feeds IdentityAAD; tampering
	// must be ErrDecrypt, not a panic.
	path := filepath.Join(dir, "identity.toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), enc.PublicKey, "age1\x5cu0000evil", 1)
	if tampered == string(raw) {
		t.Fatal("test bug: public key not found in identity.toml")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("identity with NUL in public_key = %v, want ErrDecrypt", err)
	}
}
