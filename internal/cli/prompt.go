package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// prompter is how commands talk to the user. Labels go to stderr so
// stdout stays pipeable.
type prompter interface {
	// Prompt asks with echoed input.
	Prompt(label string) (string, error)
	// PromptHidden asks with echo disabled (passwords, TOTP seeds).
	PromptHidden(label string) (string, error)
}

var errNoTerminal = errors.New(`coffin: cannot prompt: not a terminal (run "coffin unlock" first)`)

// terminalPrompter reads from the controlling terminal. When stdin is
// not a TTY (e.g. "coffin add --type env" fed by a pipe) it falls back
// to /dev/tty so the password prompt still works; with neither
// available it fails with a pointer at "coffin unlock".
type terminalPrompter struct{}

// source returns the terminal to read from and a cleanup func.
func (terminalPrompter) source() (*os.File, func(), error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return os.Stdin, func() {}, nil
	}
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return nil, nil, errNoTerminal
	}
	return tty, func() { tty.Close() }, nil
}

func (p *terminalPrompter) Prompt(label string) (string, error) {
	f, done, err := p.source()
	if err != nil {
		return "", err
	}
	defer done()
	fmt.Fprint(os.Stderr, label)
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (p *terminalPrompter) PromptHidden(label string) (string, error) {
	f, done, err := p.source()
	if err != nil {
		return "", err
	}
	defer done()
	fmt.Fprint(os.Stderr, label)
	b, err := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// promptWithDefault shows the current value and keeps it on empty
// input (the edit-flow convention).
func promptWithDefault(p prompter, label, current string) (string, error) {
	if current != "" {
		label = fmt.Sprintf("%s [%s]", label, current)
	}
	answer, err := p.Prompt(label + ": ")
	if err != nil {
		return "", err
	}
	if answer == "" {
		return current, nil
	}
	return answer, nil
}
