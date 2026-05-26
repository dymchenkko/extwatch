package vsconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAutoUpdate(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want AutoUpdate
	}{
		{"absent", `{"editor.fontSize": 12}`, AutoUpdateDefaultOn},
		{"empty", ``, AutoUpdateDefaultOn},
		{"explicit true", `{"extensions.autoUpdate": true}`, AutoUpdateOn},
		{"explicit false", `{"extensions.autoUpdate": false}`, AutoUpdateOff},
		{"only enabled", `{"extensions.autoUpdate": "onlyEnabledExtensions"}`, AutoUpdateOnlyEnabled},
		// JSONC: line comment, block comment, and a trailing comma.
		{"jsonc", "{\n  // a comment\n  \"a\": 1, /* b */\n  \"extensions.autoUpdate\": false,\n}", AutoUpdateOff},
		// A "//" inside a string value must not be treated as a comment.
		{"slash in string", `{"x": "http://e.com", "extensions.autoUpdate": true}`, AutoUpdateOn},
	}
	for _, c := range cases {
		got, err := parseAutoUpdate([]byte(c.in))
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestDisableAutoUpdate(t *testing.T) {
	t.Run("inserts when absent and preserves comments", func(t *testing.T) {
		src := "{\n    // keep me\n    \"editor.fontSize\": 12,\n}\n"
		path := writeTemp(t, src)
		backup, err := DisableAutoUpdate(path)
		if err != nil {
			t.Fatal(err)
		}
		if backup == "" {
			t.Error("expected a backup path for an existing file")
		}
		assertDisabled(t, path)
		if !contains(readFile(t, path), "// keep me") {
			t.Error("comment was not preserved")
		}
	})

	t.Run("replaces an existing true value", func(t *testing.T) {
		path := writeTemp(t, "{\n    \"extensions.autoUpdate\": true\n}\n")
		if _, err := DisableAutoUpdate(path); err != nil {
			t.Fatal(err)
		}
		assertDisabled(t, path)
		if contains(readFile(t, path), "true") {
			t.Error("old true value still present")
		}
	})

	t.Run("creates a missing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "User", "settings.json")
		backup, err := DisableAutoUpdate(path)
		if err != nil {
			t.Fatal(err)
		}
		if backup != "" {
			t.Errorf("did not expect a backup for a new file, got %q", backup)
		}
		assertDisabled(t, path)
	})
}

func assertDisabled(t *testing.T, path string) {
	t.Helper()
	state, err := ReadAutoUpdate(path)
	if err != nil {
		t.Fatalf("re-read: %v", err)
	}
	if state != AutoUpdateOff {
		t.Errorf("state = %v, want disabled\n--- file ---\n%s", state, readFile(t, path))
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
