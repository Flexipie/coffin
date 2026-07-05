package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// testKDFParams returns deliberately tiny argon2 parameters so the
// suite stays fast. Production defaults are exercised only via
// NewKDFParams' own test.
func testKDFParams(t *testing.T) KDFParams {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	return KDFParams{Time: 1, MemoryKiB: 8 * 1024, Parallelism: 1, Salt: salt}
}

func mustIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustDataKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// assertErrDecrypt checks that err is exactly the generic decrypt
// failure, with no distinguishing message that could act as an oracle.
func assertErrDecrypt(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected ErrDecrypt, got nil")
	}
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
	if err.Error() != ErrDecrypt.Error() {
		t.Fatalf("error carries distinguishing message: %q", err.Error())
	}
}

var testAADTime = time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

func TestIdentityRoundTrip(t *testing.T) {
	id := mustIdentity(t)
	password := []byte("correct horse battery staple")

	enc, err := SealIdentity(id, password, testKDFParams(t))
	if err != nil {
		t.Fatal(err)
	}
	if enc.PublicKey != id.Recipient().String() {
		t.Fatalf("public key mismatch: %q vs %q", enc.PublicKey, id.Recipient().String())
	}

	got, err := OpenIdentity(enc, password)
	if err != nil {
		t.Fatal(err)
	}

	// The recovered identity must be able to unwrap a key wrapped to
	// the original's recipient.
	dataKey := mustDataKey(t)
	wrapped, err := WrapKey(dataKey, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := UnwrapKey(wrapped, got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unwrapped, dataKey) {
		t.Fatal("unwrapped key differs from original data key")
	}
}

func TestOpenIdentityWrongPassword(t *testing.T) {
	id := mustIdentity(t)
	password := []byte("correct horse battery staple")
	enc, err := SealIdentity(id, password, testKDFParams(t))
	if err != nil {
		t.Fatal(err)
	}

	oneOff := append([]byte(nil), password...)
	oneOff[0] ^= 0x01

	cases := []struct {
		name     string
		password []byte
	}{
		{"wrong", []byte("totally different")},
		{"empty", []byte{}},
		{"one byte off", oneOff},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OpenIdentity(enc, tc.password)
			assertErrDecrypt(t, err)
			if got != nil {
				t.Fatal("identity returned despite failure")
			}
		})
	}
}

func TestKDFParamsRoundTrip(t *testing.T) {
	id := mustIdentity(t)
	password := []byte("pw")

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	// Nonstandard parameters: opening must honor what is stored, not
	// any defaults.
	params := KDFParams{Time: 2, MemoryKiB: 16 * 1024, Parallelism: 2, Salt: salt}

	enc, err := SealIdentity(id, password, params)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenIdentity(enc, password); err != nil {
		t.Fatalf("open with stored params: %v", err)
	}

	// Tampering with any stored parameter must derive a different key.
	tampered := *enc
	tampered.Params.Time = params.Time + 1
	_, err = OpenIdentity(&tampered, password)
	assertErrDecrypt(t, err)
}

// TestOpenIdentityInvalidParams: argon2 panics on zero time or
// parallelism, so a tampered identity file with such params must be
// caught before key derivation and surface as the generic ErrDecrypt,
// never a crash or a distinguishable error.
func TestOpenIdentityInvalidParams(t *testing.T) {
	id := mustIdentity(t)
	password := []byte("pw")
	enc, err := SealIdentity(id, password, testKDFParams(t))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(*KDFParams)
	}{
		{"zero time", func(p *KDFParams) { p.Time = 0 }},
		{"zero parallelism", func(p *KDFParams) { p.Parallelism = 0 }},
		{"empty salt", func(p *KDFParams) { p.Salt = nil }},
		{"oversized memory", func(p *KDFParams) { p.MemoryKiB = 4*1024*1024 + 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := *enc
			tampered.Params.Salt = append([]byte(nil), enc.Params.Salt...)
			tc.mutate(&tampered.Params)
			_, err := OpenIdentity(&tampered, password)
			assertErrDecrypt(t, err)
		})
	}
}

func TestSealIdentityInvalidParams(t *testing.T) {
	id := mustIdentity(t)
	_, err := SealIdentity(id, []byte("pw"), KDFParams{})
	if err == nil {
		t.Fatal("expected error sealing with zero params")
	}
	// Write path, not a decrypt failure: the error must be descriptive,
	// not the generic oracle-safe ErrDecrypt.
	if errors.Is(err, ErrDecrypt) {
		t.Fatalf("seal path returned ErrDecrypt: %v", err)
	}
}

func TestNewKDFParamsDefaults(t *testing.T) {
	p, err := NewKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	if p.Time != 3 || p.MemoryKiB != 256*1024 || p.Parallelism != 4 {
		t.Fatalf("unexpected defaults: %+v", p)
	}
	if len(p.Salt) != 16 {
		t.Fatalf("salt length = %d, want 16", len(p.Salt))
	}
	q, err := NewKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(p.Salt, q.Salt) {
		t.Fatal("two NewKDFParams calls produced the same salt")
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	key := mustDataKey(t)
	aad := EntryAAD("aabb", "password", "passwords/github", testAADTime)

	sizes := []int{0, 1, 1024, 5 * 1024 * 1024}
	for _, n := range sizes {
		plaintext := make([]byte, n)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatal(err)
		}
		nonce, ct, err := Seal(key, plaintext, aad)
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		if len(nonce) != 24 {
			t.Fatalf("size %d: nonce length = %d, want 24", n, len(nonce))
		}
		got, err := Open(key, nonce, ct, aad)
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("size %d: round-trip mismatch", n)
		}
	}
}

func TestSealFreshNonce(t *testing.T) {
	key := mustDataKey(t)
	plaintext := []byte("same input twice")
	aad := EntryAAD("aabb", "password", "passwords/github", testAADTime)

	n1, c1, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	n2, c2, err := Seal(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(n1, n2) {
		t.Fatal("nonce reused across two Seal calls")
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("identical ciphertext for two Seal calls")
	}
}

func TestWrapKeyEmptyRecipients(t *testing.T) {
	if _, err := WrapKey(mustDataKey(t), nil); err == nil {
		t.Fatal("expected error wrapping to zero recipients")
	}
}

func TestUnwrapKeyNonRecipient(t *testing.T) {
	owner := mustIdentity(t)
	outsider := mustIdentity(t)
	wrapped, err := WrapKey(mustDataKey(t), []age.Recipient{owner.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = UnwrapKey(wrapped, outsider)
	assertErrDecrypt(t, err)
}

func TestTamperMatrix(t *testing.T) {
	id := mustIdentity(t)
	key := mustDataKey(t)
	aad := EntryAAD("aabb", "password", "passwords/github", testAADTime)
	nonce, ct, err := Seal(key, []byte("secret payload"), aad)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapKey(key, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("flip ciphertext byte", func(t *testing.T) {
		bad := append([]byte(nil), ct...)
		bad[len(bad)/2] ^= 0x01
		_, err := Open(key, nonce, bad, aad)
		assertErrDecrypt(t, err)
	})

	t.Run("flip nonce byte", func(t *testing.T) {
		bad := append([]byte(nil), nonce...)
		bad[0] ^= 0x01
		_, err := Open(key, bad, ct, aad)
		assertErrDecrypt(t, err)
	})

	t.Run("flip armor body char", func(t *testing.T) {
		lines := strings.Split(wrapped, "\n")
		// Pick a base64 body line (not the BEGIN/END markers) and swap
		// one character for a different valid base64 character.
		for i, line := range lines {
			if strings.HasPrefix(line, "-----") || line == "" {
				continue
			}
			c := byte('A')
			if line[0] == 'A' {
				c = 'B'
			}
			lines[i] = string(c) + line[1:]
			break
		}
		_, err := UnwrapKey(strings.Join(lines, "\n"), id)
		assertErrDecrypt(t, err)
	})

	t.Run("truncated armor", func(t *testing.T) {
		_, err := UnwrapKey(wrapped[:len(wrapped)/2], id)
		assertErrDecrypt(t, err)
	})
}

func TestAADMatrix(t *testing.T) {
	key := mustDataKey(t)
	const (
		vaultID = "9f3a1c0d2b4e5f60718293a4b5c6d7e8"
		typ     = "env"
		path    = "env/nice/api-server/prod"
	)
	aad := EntryAAD(vaultID, typ, path, testAADTime)
	nonce, ct, err := Seal(key, []byte("PORT=8080"), aad)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: the correct AAD opens.
	if _, err := Open(key, nonce, ct, aad); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		aad  []byte
	}{
		{"changed path", EntryAAD(vaultID, typ, "env/nice/api-server/staging", testAADTime)},
		{"changed type", EntryAAD(vaultID, "password", path, testAADTime)},
		{"changed updated_at", EntryAAD(vaultID, typ, path, testAADTime.Add(time.Second))},
		{"changed vault id", EntryAAD("00000000000000000000000000000000", typ, path, testAADTime)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Open(key, nonce, ct, tc.aad)
			assertErrDecrypt(t, err)
		})
	}
}

// TestCrossEntrySwap covers the attack plain AEAD without AAD would
// miss: two env overlays sealed under the SAME group data key must not
// be interchangeable on disk.
func TestCrossEntrySwap(t *testing.T) {
	groupKey := mustDataKey(t)
	const vaultID = "9f3a1c0d2b4e5f60718293a4b5c6d7e8"
	prodAAD := EntryAAD(vaultID, "env", "env/nice/api-server/prod", testAADTime)
	stagingAAD := EntryAAD(vaultID, "env", "env/nice/api-server/staging", testAADTime)

	prodNonce, prodCT, err := Seal(groupKey, []byte("DB=prod"), prodAAD)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("prod ciphertext under staging AAD", func(t *testing.T) {
		_, err := Open(groupKey, prodNonce, prodCT, stagingAAD)
		assertErrDecrypt(t, err)
	})

	t.Run("same path in another vault", func(t *testing.T) {
		otherVault := EntryAAD("112233445566778899aabbccddeeff00", "env", "env/nice/api-server/prod", testAADTime)
		_, err := Open(groupKey, prodNonce, prodCT, otherVault)
		assertErrDecrypt(t, err)
	})

	t.Run("identity blob under wrong public key", func(t *testing.T) {
		id := mustIdentity(t)
		other := mustIdentity(t)
		password := []byte("pw")
		enc, err := SealIdentity(id, password, testKDFParams(t))
		if err != nil {
			t.Fatal(err)
		}
		swapped := *enc
		swapped.PublicKey = other.Recipient().String()
		_, err = OpenIdentity(&swapped, password)
		assertErrDecrypt(t, err)
	})
}

func TestRewrapAddRecipient(t *testing.T) {
	a := mustIdentity(t)
	b := mustIdentity(t)
	dataKey := mustDataKey(t)
	aad := EntryAAD("aabb", "password", "passwords/github", testAADTime)
	nonce, ct, err := Seal(dataKey, []byte("hunter2"), aad)
	if err != nil {
		t.Fatal(err)
	}

	wrappedA, err := WrapKey(dataKey, []age.Recipient{a.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	wrappedAB, err := Rewrap(wrappedA, a, []age.Recipient{a.Recipient(), b.Recipient()})
	if err != nil {
		t.Fatal(err)
	}

	keyViaB, err := UnwrapKey(wrappedAB, b)
	if err != nil {
		t.Fatalf("new recipient cannot unwrap: %v", err)
	}
	keyViaA, err := UnwrapKey(wrappedAB, a)
	if err != nil {
		t.Fatalf("original recipient cannot unwrap: %v", err)
	}
	if !bytes.Equal(keyViaA, dataKey) || !bytes.Equal(keyViaB, dataKey) {
		t.Fatal("rewrap changed the data key bytes")
	}

	// Existing ciphertext still opens; no payload rewrite happened.
	if _, err := Open(keyViaB, nonce, ct, aad); err != nil {
		t.Fatalf("old ciphertext no longer opens: %v", err)
	}
}

func TestRotateOnRevoke(t *testing.T) {
	a := mustIdentity(t)
	b := mustIdentity(t)
	oldKey := mustDataKey(t)
	plaintext := []byte("DB=prod")
	oldAAD := EntryAAD("aabb", "env", "env/api/prod", testAADTime)

	oldWrapped, err := WrapKey(oldKey, []age.Recipient{a.Recipient(), b.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	oldNonce, oldCT, err := Seal(oldKey, plaintext, oldAAD)
	if err != nil {
		t.Fatal(err)
	}

	// Revoke B: rotate to {A}. updated_at changes with the rewrite.
	newAAD := EntryAAD("aabb", "env", "env/api/prod", testAADTime.Add(time.Hour))
	newWrapped, sealed, err := Rotate(
		[]Payload{{Plaintext: plaintext, AAD: newAAD}},
		[]age.Recipient{a.Recipient()},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != 1 {
		t.Fatalf("sealed count = %d, want 1", len(sealed))
	}

	// B is locked out of the new blob.
	_, err = UnwrapKey(newWrapped, b)
	assertErrDecrypt(t, err)

	// A unwraps the new key; it must differ from the old one.
	newKey, err := UnwrapKey(newWrapped, a)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(newKey, oldKey) {
		t.Fatal("rotate reused the old data key")
	}

	// The old key does not open the new ciphertext.
	_, err = Open(oldKey, sealed[0].Nonce, sealed[0].Ciphertext, newAAD)
	assertErrDecrypt(t, err)

	// A reads the new ciphertext.
	got, err := Open(newKey, sealed[0].Nonce, sealed[0].Ciphertext, newAAD)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("rotated payload mismatch")
	}

	// Git-history semantics (PRD 6.7): the old blob and old ciphertext
	// remain readable to A via the old key.
	oldKeyViaA, err := UnwrapKey(oldWrapped, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(oldKeyViaA, oldNonce, oldCT, oldAAD); err != nil {
		t.Fatalf("historical ciphertext no longer opens: %v", err)
	}
}

func TestRotateZeroRecipients(t *testing.T) {
	_, _, err := Rotate([]Payload{{Plaintext: []byte("x"), AAD: []byte("y")}}, nil)
	if err == nil {
		t.Fatal("expected error rotating to zero recipients")
	}
}

// TestAADNULRejected: a NUL inside a field would make the 0x00-joined
// AAD encoding ambiguous ("env" + "x\x00y" == "env\x00x" + "y"). Fields
// are internal and NUL-free by construction, so a NUL is a broken
// invariant and must panic rather than silently produce ambiguous AAD.
func TestAADNULRejected(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on NUL byte in AAD field")
		}
	}()
	EntryAAD("aabb", "env", "x\x00y", testAADTime)
}

// TestAADConstruction pins the exact AAD byte layout. Any change here
// is a format break and needs a new AAD context string.
func TestAADConstruction(t *testing.T) {
	got := EntryAAD("9f3a", "password", "passwords/github", testAADTime)
	want := "coffin.entry.v1\x009f3a\x00password\x00passwords/github\x002026-07-06T12:00:00Z"
	if string(got) != want {
		t.Fatalf("EntryAAD = %q, want %q", got, want)
	}

	// Sub-second and zone information must not leak into the AAD.
	loc := time.FixedZone("UTC+2", 2*60*60)
	messy := time.Date(2026, 7, 6, 14, 0, 0, 123456789, loc)
	if string(EntryAAD("9f3a", "password", "passwords/github", messy)) != want {
		t.Fatal("AAD not canonicalized to UTC second precision")
	}

	gotID := IdentityAAD("age1example")
	wantID := "coffin.identity.v1\x00age1example"
	if string(gotID) != wantID {
		t.Fatalf("IdentityAAD = %q, want %q", gotID, wantID)
	}
}
