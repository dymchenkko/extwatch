// Package vsconfig inspects and edits the user-level settings.json of VS Code
// and its forks (Insiders, VSCodium, Cursor, Windsurf). Its sole concern is the
// "extensions.autoUpdate" setting: extwatch can only vet an update *before* it
// lands if VS Code isn't silently installing updates itself, so we need to read
// — and, with consent, disable — auto-update.
//
// settings.json is JSONC (JSON with // and /* */ comments and trailing commas),
// which encoding/json cannot parse, so we strip those before reading. Writes are
// surgical (a single value replacement or one inserted line) to preserve the
// user's existing comments and formatting, and always after a backup.
package vsconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Profile is one discovered VS Code-family editor with a settings.json on disk.
type Profile struct {
	Editor string // human-readable name, e.g. "VS Code", "Cursor"
	Path   string // absolute path to its user settings.json
}

// AutoUpdate is the state of the extensions.autoUpdate setting.
type AutoUpdate int

const (
	// AutoUpdateDefaultOn means the key is absent; VS Code's built-in default is
	// to auto-update, so this is effectively "on".
	AutoUpdateDefaultOn AutoUpdate = iota
	AutoUpdateOn                    // explicit true
	AutoUpdateOnlyEnabled           // "onlyEnabledExtensions" (still auto-installs)
	AutoUpdateOff                   // explicit false — what we want
)

// Enabled reports whether VS Code will auto-install extension updates in this
// state. Only an explicit false stops it.
func (a AutoUpdate) Enabled() bool { return a != AutoUpdateOff }

func (a AutoUpdate) String() string {
	switch a {
	case AutoUpdateDefaultOn:
		return "enabled (default — setting not present)"
	case AutoUpdateOn:
		return "enabled"
	case AutoUpdateOnlyEnabled:
		return "onlyEnabledExtensions"
	case AutoUpdateOff:
		return "disabled"
	default:
		return "unknown"
	}
}

// autoUpdateKey is the literal (dotted, flat) settings key VS Code uses.
const autoUpdateKey = "extensions.autoUpdate"

// knownEditors maps each editor's settings-dir folder name to its display name.
// The folder lives under the per-OS user-config root (see settingsRoot).
var knownEditors = []struct{ folder, name string }{
	{"Code", "VS Code"},
	{"Code - Insiders", "VS Code Insiders"},
	{"VSCodium", "VSCodium"},
	{"Cursor", "Cursor"},
	{"Windsurf", "Windsurf"},
}

// settingsRoot returns the per-OS directory under which each editor keeps its
// "<Editor>/User/settings.json", or "" if it can't be determined.
func settingsRoot() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support")
	case "windows":
		if appData := os.Getenv("APPDATA"); appData != "" {
			return appData
		}
		return filepath.Join(home, "AppData", "Roaming")
	default: // linux and other unixes
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return xdg
		}
		return filepath.Join(home, ".config")
	}
}

// DiscoverProfiles returns every known editor whose settings.json exists.
func DiscoverProfiles() []Profile {
	root := settingsRoot()
	if root == "" {
		return nil
	}
	var profiles []Profile
	for _, e := range knownEditors {
		path := filepath.Join(root, e.folder, "User", "settings.json")
		if _, err := os.Stat(path); err == nil {
			profiles = append(profiles, Profile{Editor: e.name, Path: path})
		}
	}
	return profiles
}

// ReadAutoUpdate parses settings.json and reports the auto-update state. A
// missing or empty file reads as AutoUpdateDefaultOn (VS Code's default).
func ReadAutoUpdate(path string) (AutoUpdate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if isNotExist(err) {
			return AutoUpdateDefaultOn, nil
		}
		return AutoUpdateDefaultOn, fmt.Errorf("read %s: %w", path, err)
	}
	return parseAutoUpdate(raw)
}

func parseAutoUpdate(raw []byte) (AutoUpdate, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return AutoUpdateDefaultOn, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(stripJSONC(raw), &m); err != nil {
		return AutoUpdateDefaultOn, fmt.Errorf("parse settings: %w", err)
	}
	val, ok := m[autoUpdateKey]
	if !ok {
		return AutoUpdateDefaultOn, nil
	}
	switch strings.TrimSpace(string(val)) {
	case "true":
		return AutoUpdateOn, nil
	case "false":
		return AutoUpdateOff, nil
	}
	// Non-boolean: the only documented string value is "onlyEnabledExtensions".
	var s string
	if err := json.Unmarshal(val, &s); err == nil && s == "onlyEnabledExtensions" {
		return AutoUpdateOnlyEnabled, nil
	}
	// Anything else unexpected: treat as enabled, the safer assumption.
	return AutoUpdateOn, nil
}

// DisableAutoUpdate sets extensions.autoUpdate=false in settings.json, returning
// the path of the backup it wrote first (empty if there was no prior file to back
// up). Existing comments and formatting are preserved.
func DisableAutoUpdate(path string) (backup string, err error) {
	raw, err := os.ReadFile(path)
	switch {
	case isNotExist(err) || (err == nil && len(bytes.TrimSpace(raw)) == 0):
		// No (usable) file yet: create a minimal one. Nothing to back up.
		if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil {
			return "", fmt.Errorf("create settings dir: %w", mkErr)
		}
		content := "{\n    \"" + autoUpdateKey + "\": false\n}\n"
		return "", os.WriteFile(path, []byte(content), 0o644)
	case err != nil:
		return "", fmt.Errorf("read %s: %w", path, err)
	}

	state, err := parseAutoUpdate(raw)
	if err != nil {
		return "", err
	}

	updated, err := setAutoUpdateFalse(raw, state)
	if err != nil {
		return "", err
	}

	backup = fmt.Sprintf("%s.extwatch.%d.bak", path, time.Now().Unix())
	if err := os.WriteFile(backup, raw, 0o644); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}
	if err := os.WriteFile(path, updated, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return backup, nil
}

// auValueRe matches the key and its scalar value (bool or string) so we can swap
// just the value in place.
var auValueRe = regexp.MustCompile(`("extensions\.autoUpdate"\s*:\s*)(true|false|"[^"]*")`)

// setAutoUpdateFalse returns raw with the auto-update value forced to false. If
// the key is already present (per the parsed state) it replaces the value;
// otherwise it inserts a new entry right after the opening brace, which is always
// valid since a non-empty object follows.
func setAutoUpdateFalse(raw []byte, state AutoUpdate) ([]byte, error) {
	if state != AutoUpdateDefaultOn {
		if !auValueRe.Match(raw) {
			return nil, fmt.Errorf("could not locate %q value to edit; please set it to false manually", autoUpdateKey)
		}
		return auValueRe.ReplaceAll(raw, []byte("${1}false")), nil
	}

	i := bytes.IndexByte(raw, '{')
	if i < 0 {
		return nil, fmt.Errorf("settings file is not a JSON object")
	}
	insertion := "\n" + detectIndent(raw) + "\"" + autoUpdateKey + "\": false,"
	out := make([]byte, 0, len(raw)+len(insertion))
	out = append(out, raw[:i+1]...)
	out = append(out, insertion...)
	out = append(out, raw[i+1:]...)
	return out, nil
}

// detectIndent infers the file's indentation from its first indented key,
// defaulting to four spaces.
func detectIndent(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || !strings.HasPrefix(trimmed, "\"") {
			continue
		}
		if indent := line[:len(line)-len(trimmed)]; indent != "" {
			return indent
		}
	}
	return "    "
}

func isNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// stripJSONC removes // line comments, /* */ block comments, and trailing commas
// from JSONC input, leaving strict JSON. It tracks string literals so that
// comment markers or commas inside strings are left untouched.
func stripJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inString := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				out = append(out, b[i+1])
				i++
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n') // keep line structure
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++ // consume the closing '*'; the loop's i++ consumes the '/'
		default:
			out = append(out, c)
		}
	}
	return removeTrailingCommas(out)
}

// removeTrailingCommas deletes any comma that is followed (ignoring whitespace)
// by a closing } or ], again respecting string literals.
func removeTrailingCommas(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inString := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				out = append(out, b[i+1])
				i++
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue // drop this trailing comma
			}
		}
		out = append(out, c)
	}
	return out
}
