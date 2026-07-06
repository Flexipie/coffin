package vault

// PasswordData is the decrypted payload of a password entry
// (FORMAT.md, "Plaintext inner schemas").
type PasswordData struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Notes    string `json:"notes"`
	TOTPSeed string `json:"totp_seed"`
}

// EnvVar is one KEY=VALUE pair. EnvData keeps them in an ordered slice
// so round-tripping preserves the user's ordering.
type EnvVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// EnvData is the decrypted payload of an env overlay.
type EnvData struct {
	Vars []EnvVar `json:"vars"`
}
