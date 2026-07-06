package cli

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
)

const (
	genMinLen = 8
	genMaxLen = 256

	charsLower = "abcdefghijklmnopqrstuvwxyz"
	charsUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsDigit = "0123456789"
	// Shell-safe symbols: nothing that needs quoting in a typical
	// double-quoted shell string (no backtick, $, quotes, backslash).
	charsSymbol = "!@#$%^&*()-_=+[]{}:,.?~"
)

func newGenCmd(d *deps) *cobra.Command {
	var length int
	var noSymbols, show bool
	cmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate a random password (copied by default)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			password, err := generatePassword(length, !noSymbols)
			if err != nil {
				return err
			}
			if show {
				fmt.Fprintln(cmd.OutOrStdout(), password)
				return nil
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			return d.copyWithClear(cmd.ErrOrStderr(), cfg, password, "Copied generated password.")
		},
	}
	cmd.Flags().IntVar(&length, "len", generatedPasswordLen, "password length")
	cmd.Flags().BoolVar(&noSymbols, "no-symbols", false, "letters and digits only")
	cmd.Flags().BoolVar(&show, "show", false, "print to stdout instead of copying")
	return cmd
}

// generatePassword draws every character uniformly from the full
// charset via crypto/rand and requires at least one character from
// each active class, regenerating the whole password on a miss so the
// distribution stays unbiased (no post-hoc patching).
func generatePassword(length int, symbols bool) (string, error) {
	if length < genMinLen || length > genMaxLen {
		return "", fmt.Errorf("coffin: password length must be between %d and %d", genMinLen, genMaxLen)
	}
	classes := []string{charsLower, charsUpper, charsDigit}
	if symbols {
		classes = append(classes, charsSymbol)
	}
	charset := strings.Join(classes, "")
	max := big.NewInt(int64(len(charset)))
	buf := make([]byte, length)
	// P(miss) is tiny at length >= 8; the loop is a formality, but cap
	// it so a coffin bug cannot spin forever.
	for attempt := 0; attempt < 1000; attempt++ {
		for i := range buf {
			n, err := rand.Int(rand.Reader, max)
			if err != nil {
				return "", err
			}
			buf[i] = charset[n.Int64()]
		}
		ok := true
		for _, class := range classes {
			if !strings.ContainsAny(string(buf), class) {
				ok = false
				break
			}
		}
		if ok {
			return string(buf), nil
		}
	}
	return "", fmt.Errorf("coffin: password generation failed to satisfy character classes")
}
