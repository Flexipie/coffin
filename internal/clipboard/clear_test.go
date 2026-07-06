package clipboard

import (
	"errors"
	"testing"
)

type fakeClipboard struct {
	value string
	fail  bool
}

func (f *fakeClipboard) Copy(text string) error {
	if f.fail {
		return errors.New("fake clipboard failure")
	}
	f.value = text
	return nil
}

func (f *fakeClipboard) Read() (string, error) {
	if f.fail {
		return "", errors.New("fake clipboard failure")
	}
	return f.value, nil
}

func TestClearIfMatches(t *testing.T) {
	c := &fakeClipboard{value: "hunter2"}
	if err := ClearIfMatches(c, HashValue("hunter2")); err != nil {
		t.Fatal(err)
	}
	if c.value != "" {
		t.Fatalf("matching clipboard not cleared: %q", c.value)
	}
}

func TestClearIfMatchesLeavesLaterCopy(t *testing.T) {
	c := &fakeClipboard{value: "something the user copied later"}
	if err := ClearIfMatches(c, HashValue("hunter2")); err != nil {
		t.Fatal(err)
	}
	if c.value != "something the user copied later" {
		t.Fatal("clipboard with a different value was clobbered")
	}
}

func TestClearIfMatchesReadError(t *testing.T) {
	c := &fakeClipboard{fail: true}
	if err := ClearIfMatches(c, HashValue("x")); err == nil {
		t.Fatal("read error swallowed")
	}
}
