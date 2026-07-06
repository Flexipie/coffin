package cli

import (
	"fmt"
	"io"

	"filippo.io/age"

	"github.com/Flexipie/coffin/internal/config"
	"github.com/Flexipie/coffin/internal/crypto"
	"github.com/Flexipie/coffin/internal/session"
)

func sessionManager(d *deps, cfg *config.Config) *session.Manager {
	return session.NewManager(d.store, cfg.SessionTTL(), d.now)
}

// acquireResult reports how acquireIdentity got the identity.
type acquireResult struct {
	// FromSession means a valid cached session was hit (no prompt).
	FromSession bool
	// Stored means the session is in the keychain after this call,
	// either because it already was or because Put succeeded.
	Stored bool
}

// acquireIdentity is the one unlock path: cached session if valid,
// otherwise a master-password prompt. A wrong password surfaces as
// crypto.ErrDecrypt verbatim (no oracle); a keychain failure after a
// successful unlock is only a warning, because the session is an
// optimization, but the result records it so unlock can be honest.
func acquireIdentity(d *deps, cfg *config.Config, errW io.Writer) (*age.X25519Identity, acquireResult, error) {
	enc, err := config.LoadIdentity()
	if err != nil {
		return nil, acquireResult{}, err
	}
	mgr := sessionManager(d, cfg)
	if id, ok := mgr.Get(enc.PublicKey); ok {
		return id, acquireResult{FromSession: true, Stored: true}, nil
	}
	password, err := d.prompt.PromptHidden("Master password: ")
	if err != nil {
		return nil, acquireResult{}, err
	}
	id, err := crypto.OpenIdentity(enc, []byte(password))
	if err != nil {
		return nil, acquireResult{}, err
	}
	res := acquireResult{Stored: true}
	if err := mgr.Put(id); err != nil {
		fmt.Fprintf(errW, "warning: could not store the session in the keychain: %v\n", err)
		res.Stored = false
	}
	return id, res, nil
}
