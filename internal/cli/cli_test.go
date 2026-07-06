package cli

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/crypto"
)

// fakePrompter pops scripted answers; an empty queue behaves like a
// non-TTY (so "no prompt expected" tests fail loudly if one happens).
type fakePrompter struct {
	answers []string
	labels  []string
}

func (p *fakePrompter) next(label string) (string, error) {
	p.labels = append(p.labels, label)
	if len(p.answers) == 0 {
		return "", errNoTerminal
	}
	a := p.answers[0]
	p.answers = p.answers[1:]
	return a, nil
}

func (p *fakePrompter) Prompt(label string) (string, error)       { return p.next(label) }
func (p *fakePrompter) PromptHidden(label string) (string, error) { return p.next(label) }

type fakeClip struct {
	value string
	fail  bool
}

func (f *fakeClip) Copy(text string) error {
	if f.fail {
		return errors.New("fake clipboard failure")
	}
	f.value = text
	return nil
}

func (f *fakeClip) Read() (string, error) {
	if f.fail {
		return "", errors.New("fake clipboard failure")
	}
	return f.value, nil
}

type fakeStore struct {
	value   string
	present bool
}

func (s *fakeStore) Get() (string, bool, error) { return s.value, s.present, nil }
func (s *fakeStore) Set(v string) error         { s.value, s.present = v, true; return nil }
func (s *fakeStore) Delete() error              { s.value, s.present = "", false; return nil }

// testEnv is one user's machine: keychain, clipboard, and config home
// survive across commands, prompts are scripted per command. Tests can
// hold several (the two-user team flow); run() switches
// XDG_CONFIG_HOME to the acting user before every command.
type testEnv struct {
	store     *fakeStore
	clip      *fakeClip
	configDir string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	e := &testEnv{store: &fakeStore{}, clip: &fakeClip{}, configDir: t.TempDir()}
	t.Setenv("XDG_CONFIG_HOME", e.configDir)
	return e
}

// harmlessExe is what the spawned clipboard clearer execs in tests.
func harmlessExe(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("true")
	if err != nil {
		t.Skipf("no `true` binary: %v", err)
	}
	return path
}

func (e *testEnv) run(t *testing.T, prompts []string, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", e.configDir)
	exe := harmlessExe(t)
	p := &fakePrompter{answers: prompts}
	d := &deps{
		store:    e.store,
		clip:     e.clip,
		prompt:   p,
		execPath: func() (string, error) { return exe, nil },
		now:      time.Now,
	}
	root := newRootCmd(d)
	root.SetArgs(args)
	var out, errB bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errB)
	root.SetIn(strings.NewReader(stdin))
	err = root.Execute()
	if len(p.answers) != 0 {
		t.Fatalf("command %v left unused prompt answers: %v", args, p.answers)
	}
	return out.String(), errB.String(), err
}

func (e *testEnv) mustRun(t *testing.T, prompts []string, stdin string, args ...string) (string, string) {
	t.Helper()
	stdout, stderr, err := e.run(t, prompts, stdin, args...)
	if err != nil {
		t.Fatalf("coffin %v failed: %v\nstderr: %s", args, err, stderr)
	}
	return stdout, stderr
}

func mustGenerateIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// writeRegistry registers an existing vault in config.toml, for tests
// that skip the full init flow.
func writeRegistry(t *testing.T, name, path string) {
	t.Helper()
	cfg := config.Default()
	if err := cfg.AddVault(name, path, "personal"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratePassword(t *testing.T) {
	for _, length := range []int{8, 24, 64} {
		pw, err := generatePassword(length, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != length {
			t.Fatalf("len = %d, want %d", len(pw), length)
		}
		for _, class := range []string{charsLower, charsUpper, charsDigit, charsSymbol} {
			if !strings.ContainsAny(pw, class) {
				t.Fatalf("password %q missing a character from class %q", pw, class)
			}
		}
	}

	pw, err := generatePassword(24, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(pw, charsSymbol) {
		t.Fatalf("no-symbols password %q contains a symbol", pw)
	}
	for _, class := range []string{charsLower, charsUpper, charsDigit} {
		if !strings.ContainsAny(pw, class) {
			t.Fatalf("password %q missing a character from class %q", pw, class)
		}
	}

	if _, err := generatePassword(7, true); err == nil {
		t.Fatal("length 7 accepted")
	}
	if _, err := generatePassword(257, true); err == nil {
		t.Fatal("length 257 accepted")
	}
}

func TestParseDotenv(t *testing.T) {
	input := strings.Join([]string{
		"# a comment",
		"",
		"DB_URL=postgres://localhost/dev",
		"export API_KEY=sekrit",
		"  SPACED = padded value ",
		"EMPTY=",
		"EQ=a=b=c",
	}, "\n")
	vars, err := parseDotenv(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	want := [][2]string{
		{"DB_URL", "postgres://localhost/dev"},
		{"API_KEY", "sekrit"},
		{"SPACED", " padded value"},
		{"EMPTY", ""},
		{"EQ", "a=b=c"},
	}
	if len(vars) != len(want) {
		t.Fatalf("got %d vars, want %d: %+v", len(vars), len(want), vars)
	}
	for i, w := range want {
		if vars[i].Key != w[0] || vars[i].Value != w[1] {
			t.Fatalf("var %d = %+v, want %v", i, vars[i], w)
		}
	}

	_, err = parseDotenv(strings.NewReader("GOOD=1\nnot a var\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("bad line error = %v, want line number 2", err)
	}

	for _, bad := range []string{"MY KEY=1", "1BAD=x", "DASH-KEY=x"} {
		_, err = parseDotenv(strings.NewReader(bad + "\n"))
		if err == nil || !strings.Contains(err.Error(), "line 1") {
			t.Fatalf("parseDotenv(%q) = %v, want invalid-key error with line 1", bad, err)
		}
	}
}

func TestGenShowAndClipboard(t *testing.T) {
	e := newTestEnv(t)
	stdout, _ := e.mustRun(t, nil, "", "gen", "--show", "--len", "32")
	pw := strings.TrimSpace(stdout)
	if len(pw) != 32 {
		t.Fatalf("gen --show printed %q", stdout)
	}
	if e.clip.value != "" {
		t.Fatal("gen --show must not touch the clipboard")
	}

	_, stderr := e.mustRun(t, nil, "", "gen")
	if e.clip.value == "" || len(e.clip.value) != generatedPasswordLen {
		t.Fatalf("gen did not copy a %d-char password: %q", generatedPasswordLen, e.clip.value)
	}
	if !strings.Contains(stderr, "Clears in 30s.") {
		t.Fatalf("gen stderr = %q, want auto-clear notice", stderr)
	}
}

func TestFormatTTL(t *testing.T) {
	for _, tt := range []struct {
		d    time.Duration
		want string
	}{
		{15 * time.Minute, "15m"},
		{2 * time.Hour, "2h"},
		{90 * time.Second, "1m30s"},
	} {
		if got := formatTTL(tt.d); got != tt.want {
			t.Errorf("formatTTL(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}
