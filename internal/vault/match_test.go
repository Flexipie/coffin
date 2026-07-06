package vault

import "testing"

func refs(names ...string) []EntryRef {
	out := make([]EntryRef, len(names))
	for i, n := range names {
		typ, prefix := TypePassword, "passwords/"
		if len(n) > 4 && n[:4] == "env/" {
			typ, prefix, n = TypeEnv, "env/", n[4:]
		}
		out[i] = EntryRef{Type: typ, Name: n, Path: prefix + n}
	}
	return out
}

func matchNames(t *testing.T, query string, entries []EntryRef) []string {
	t.Helper()
	m := Match(query, entries)
	names := make([]string, len(m))
	for i, e := range m {
		names[i] = e.Name
	}
	return names
}

func TestMatch(t *testing.T) {
	entries := refs(
		"github",
		"github-work",
		"gitlab",
		"env/myapp/api/staging",
		"env/myapp/api/prod",
		"hub",
	)

	tests := []struct {
		query string
		want  []string
	}{
		// Exact beats prefix: "github" must not also return github-work.
		{"github", []string{"github"}},
		{"GitHub", []string{"github"}},
		// Exact last segment beats substring.
		{"staging", []string{"myapp/api/staging"}},
		{"hub", []string{"hub"}}, // exact beats the substring matches in github*
		// Prefix tier: both git* prefixes tie, shorter name first.
		{"git", []string{"github", "gitlab", "github-work"}},
		// Substring tier.
		{"thub", []string{"github", "github-work"}},
		// Subsequence tier.
		{"ghw", []string{"github-work"}},
		// Path matching works too.
		{"env/myapp/api/prod", []string{"myapp/api/prod"}},
		{"nomatch-xyz-q", nil},
		{"", nil},
	}
	for _, tt := range tests {
		got := matchNames(t, tt.query, entries)
		if len(got) != len(tt.want) {
			t.Errorf("Match(%q) = %v, want %v", tt.query, got, tt.want)
			continue
		}
		for i := range tt.want {
			if got[i] != tt.want[i] {
				t.Errorf("Match(%q) = %v, want %v", tt.query, got, tt.want)
				break
			}
		}
	}
}
