package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/Flexipie/coffin/internal/vault"
)

// parseDotenv reads KEY=VALUE lines: blanks and # comments are
// skipped, a leading "export " is stripped, the first = splits, and
// values are kept verbatim (no quote processing).
func parseDotenv(r io.Reader) ([]vault.EnvVar, error) {
	var vars []vault.EnvVar
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		i := strings.IndexByte(line, '=')
		if i < 0 {
			return nil, fmt.Errorf("coffin: line %d: expected KEY=VALUE, got %q", lineNo, line)
		}
		key := strings.TrimSpace(line[:i])
		if key == "" {
			return nil, fmt.Errorf("coffin: line %d: empty key", lineNo)
		}
		if !validEnvKey(key) {
			return nil, fmt.Errorf("coffin: line %d: invalid key %q", lineNo, key)
		}
		vars = append(vars, vault.EnvVar{Key: key, Value: line[i+1:]})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return vars, nil
}

// validEnvKey reports whether key is a valid environment variable
// name: [A-Za-z_][A-Za-z0-9_]*.
func validEnvKey(key string) bool {
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
		case c >= '0' && c <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return len(key) > 0
}

// readEnvVars collects variables from --from-file or stdin. On an
// interactive terminal it explains how to finish; from a pipe it just
// reads.
func readEnvVars(cmd *cobra.Command, fromFile string) ([]vault.EnvVar, error) {
	var r io.Reader
	if fromFile != "" {
		f, err := os.Open(fromFile)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	} else {
		if f, ok := cmd.InOrStdin().(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			fmt.Fprintln(cmd.ErrOrStderr(), "Paste KEY=VALUE lines, ^D to finish:")
		}
		r = cmd.InOrStdin()
	}
	vars, err := parseDotenv(r)
	if err != nil {
		return nil, err
	}
	if len(vars) == 0 {
		return nil, fmt.Errorf("coffin: no variables provided")
	}
	return vars, nil
}
