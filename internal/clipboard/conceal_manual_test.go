//go:build darwin && cgo

package clipboard

import (
	"os"
	"strings"
	"testing"
)

// TestConcealedCopyManual drives the real macOS pasteboard, so it only
// runs when explicitly asked for (it clobbers whatever the user has
// copied). Verify with:
//
//	COFFIN_CLIPBOARD_TEST=1 go test ./internal/clipboard/ -run Concealed -v
func TestConcealedCopyManual(t *testing.T) {
	if os.Getenv("COFFIN_CLIPBOARD_TEST") == "" {
		t.Skip("set COFFIN_CLIPBOARD_TEST=1 to exercise the real pasteboard")
	}
	const value = "coffin-conceal-test"
	if err := copyConcealed(value); err != nil {
		t.Fatal(err)
	}
	got, err := System().Read()
	if err != nil {
		t.Fatal(err)
	}
	if got != value {
		t.Fatalf("read back %q, want %q", got, value)
	}
	if types := pasteboardTypes(); !strings.Contains(types, "org.nspasteboard.ConcealedType") {
		t.Fatalf("pasteboard types missing the concealed marker: %s", types)
	}
	// Leave the pasteboard clean.
	if err := System().Copy(""); err != nil {
		t.Fatal(err)
	}
}
