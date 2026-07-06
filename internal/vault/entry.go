package vault

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/Flexipie/coffin/internal/crypto"
)

// entryFile is the decoded form of any entry-shaped file: password
// entries carry all fields, env overlays have no [key], key.toml has
// no name/updated_at/[payload].
type entryFile struct {
	FormatVersion int            `toml:"format_version"`
	Type          string         `toml:"type"`
	Name          string         `toml:"name"`
	UpdatedAt     time.Time      `toml:"updated_at"`
	Key           keySection     `toml:"key"`
	Payload       payloadSection `toml:"payload"`
}

type keySection struct {
	Wrapped string `toml:"wrapped"`
}

type payloadSection struct {
	Nonce      string `toml:"nonce"`
	Ciphertext string `toml:"ciphertext"`
}

// readEntryFile loads and decodes an entry file, running the
// format_version pre-check before the full decode.
func readEntryFile(path string) (entryFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return entryFile{}, ErrNotFound
		}
		return entryFile{}, err
	}
	if err := CheckVersion(path, data); err != nil {
		return entryFile{}, err
	}
	var f entryFile
	if err := toml.Unmarshal(data, &f); err != nil {
		return entryFile{}, fmt.Errorf("coffin: parse %s: %w", path, err)
	}
	return f, nil
}

// openEntryPayload decrypts an entry payload with the AAD recomputed
// from the file's actual canonical path and its header fields, never
// from anything stored (FORMAT.md, "AAD (load-bearing)"). Malformed
// base64 counts as tampering and surfaces as ErrDecrypt like every
// other decrypt failure.
func openEntryPayload(f entryFile, vaultID, canonical string, dataKey []byte) ([]byte, error) {
	// The type header feeds the AAD, which must be NUL-free. A strict
	// whitelist covers that and costs nothing: any legit file carries
	// one of these values, and a cross-type open would fail AAD anyway.
	if f.Type != TypePassword && f.Type != TypeEnv {
		return nil, crypto.ErrDecrypt
	}
	nonce, err := base64.StdEncoding.DecodeString(f.Payload.Nonce)
	if err != nil {
		return nil, crypto.ErrDecrypt
	}
	ct, err := base64.StdEncoding.DecodeString(f.Payload.Ciphertext)
	if err != nil {
		return nil, crypto.ErrDecrypt
	}
	return crypto.Open(dataKey, nonce, ct, crypto.EntryAAD(vaultID, f.Type, canonical, f.UpdatedAt))
}

// The render helpers write entry files by hand instead of through a
// TOML encoder: every value is byte-safe by construction (slugs,
// RFC 3339 UTC timestamps, base64, age armor), and a fixed layout
// means the on-disk shape can never drift under a library upgrade.

func renderPasswordEntry(name string, updatedAt time.Time, wrapped string, nonce, ciphertext []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "format_version = %d\n", FormatVersion)
	fmt.Fprintf(&b, "type = %q\n", TypePassword)
	fmt.Fprintf(&b, "name = %q\n", name)
	fmt.Fprintf(&b, "updated_at = %s\n\n", updatedAt.Format(time.RFC3339))
	renderKeySection(&b, wrapped)
	b.WriteString("\n")
	renderPayloadSection(&b, nonce, ciphertext)
	return []byte(b.String())
}

func renderEnvEntry(name string, updatedAt time.Time, nonce, ciphertext []byte) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "format_version = %d\n", FormatVersion)
	fmt.Fprintf(&b, "type = %q\n", TypeEnv)
	fmt.Fprintf(&b, "name = %q\n", name)
	fmt.Fprintf(&b, "updated_at = %s\n\n", updatedAt.Format(time.RFC3339))
	renderPayloadSection(&b, nonce, ciphertext)
	return []byte(b.String())
}

func renderEnvKey(wrapped string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "format_version = %d\n", FormatVersion)
	fmt.Fprintf(&b, "type = %q\n\n", TypeEnvKey)
	renderKeySection(&b, wrapped)
	return []byte(b.String())
}

func renderKeySection(b *strings.Builder, wrapped string) {
	if !strings.HasSuffix(wrapped, "\n") {
		wrapped += "\n"
	}
	b.WriteString("[key]\n")
	fmt.Fprintf(b, "wrapped = \"\"\"\n%s\"\"\"\n", wrapped)
}

func renderPayloadSection(b *strings.Builder, nonce, ciphertext []byte) {
	b.WriteString("[payload]\n")
	fmt.Fprintf(b, "nonce = %q\n", base64.StdEncoding.EncodeToString(nonce))
	fmt.Fprintf(b, "ciphertext = %q\n", base64.StdEncoding.EncodeToString(ciphertext))
}
