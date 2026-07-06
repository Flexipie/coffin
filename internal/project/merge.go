package project

import "github.com/Flexipie/coffin/internal/vault"

// Merge applies overlay on top of base (FORMAT.md, "Effective
// environment"): base ordering is preserved, overridden values are
// replaced in place, overlay-only keys are appended in overlay order.
// Within one input a duplicated key's last occurrence wins.
func Merge(base, overlay vault.EnvData) vault.EnvData {
	var out []vault.EnvVar
	index := make(map[string]int)
	add := func(v vault.EnvVar) {
		if i, ok := index[v.Key]; ok {
			out[i].Value = v.Value
			return
		}
		index[v.Key] = len(out)
		out = append(out, v)
	}
	for _, v := range base.Vars {
		add(v)
	}
	for _, v := range overlay.Vars {
		add(v)
	}
	return vault.EnvData{Vars: out}
}
