package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/Flexipie/coffin/internal/config"
)

func newRunCmd(d *deps) *cobra.Command {
	var envName, vaultName string
	cmd := &cobra.Command{
		Use:   "run [-e <env>] [--] <command> [args...]",
		Short: "Run a command with the project's env vars injected",
		Long: "Run a command with the project's effective env vars (base overlaid\n" +
			"by the chosen environment) injected into its process. Nothing is\n" +
			"written to disk. The project is discovered via .coffin.toml.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return silenceExitCode(cmd, runRun(cmd, d, envName, vaultName, args))
		},
	}
	// Stop flag parsing at the first positional so the child command's
	// own flags pass through untouched, with or without "--".
	cmd.Flags().SetInterspersed(false)
	cmd.Flags().StringVarP(&envName, "env", "e", "", "overlay to use (default: default_env from .coffin.toml)")
	cmd.Flags().StringVar(&vaultName, "vault", "", "vault holding the project group")
	return cmd
}

func runRun(cmd *cobra.Command, d *deps, envName, vaultName string, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	pf, v, env, err := projectContext(cfg, vaultName, envName)
	if err != nil {
		return err
	}
	id, _, err := acquireIdentity(d, cfg, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	data, err := loadEffectiveEnv(v, pf.Group, env, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Running with %d vars from %s (%s, vault %s).\n",
		len(data.Vars), pf.Group, env, v.Manifest.Vault.Name)

	child := exec.Command(args[0], args[1:]...)
	child.Env = composeEnv(os.Environ(), data.Vars)
	child.Stdin = cmd.InOrStdin()
	child.Stdout = cmd.OutOrStdout()
	child.Stderr = cmd.ErrOrStderr()
	if err := child.Start(); err != nil {
		return fmt.Errorf("coffin: %s: %w", args[0], err)
	}

	// Forward termination signals so "kill <coffin>" reaches the child;
	// Ctrl-C already reaches it via the foreground process group.
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigc:
				child.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()
	err = child.Wait()
	signal.Stop(sigc)
	close(done)
	if err == nil {
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code := ee.ExitCode()
		if code < 0 {
			// Killed by a signal: shell convention 128+sig.
			if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				code = 128 + int(ws.Signal())
			} else {
				code = 1
			}
		}
		// The child already reported its own failure on stderr.
		return &exitCodeError{code: code}
	}
	return fmt.Errorf("coffin: %s: %w", args[0], err)
}
