package vault

import "testing"

func TestNormalizeSlug(t *testing.T) {
	tests := []struct {
		in   string
		want string // "" means an error is expected
	}{
		{"github", "github"},
		{"GitHub", "github"},
		{"  github  ", "github"},
		{"my-app_2.prod", "my-app_2.prod"},
		{"myapp/api/staging", "myapp/api/staging"},
		{"MyApp/API", "myapp/api"},
		{"", ""},
		{"/", ""},
		{"a//b", ""},
		{"/leading", ""},
		{"trailing/", ""},
		{"-starts-with-dash", ""},
		{".starts-with-dot", ""},
		{"has space", ""},
		{"has\\backslash", ""},
		{"café", ""}, // non-ASCII rejected (makes NFC vacuous)
		{"emoji\U0001f600", ""},
		{"con", ""},
		{"CON", ""},
		{"con.txt", ""}, // Windows reserves extensions of device names too
		{"com7", ""},
		{"lpt1", ""},
		{"myapp/aux/dev", ""},  // reserved anywhere in the path
		{"console", "console"}, // prefix of a reserved name is fine
		{"com0", "com0"},       // only com1-9 are reserved
	}
	for _, tt := range tests {
		got, err := NormalizeSlug(tt.in)
		if tt.want == "" {
			if err == nil {
				t.Errorf("NormalizeSlug(%q) = %q, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeSlug(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeSlug(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
