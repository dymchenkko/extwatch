package fetcher

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dymchenkko/extwatch/internal/extension"
)

// makeVSIX builds a minimal in-memory .vsix (zip) with the given entries
// (path -> content) and returns the raw bytes.
func makeVSIX(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := strings.NewReader(content).WriteTo(f); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestDownloadVSIX_happy(t *testing.T) {
	vsix := makeVSIX(t, map[string]string{
		"extension/package.json":  `{"name":"test-ext"}`,
		"extension/dist/index.js": `eval("bad")`,
		"extension/README.md":     "ignored",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(vsix)
	}))
	defer srv.Close()

	c := New()
	js, manifest, err := c.DownloadVSIX(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if manifest != `{"name":"test-ext"}` {
		t.Errorf("manifest = %q, want {\"name\":\"test-ext\"}", manifest)
	}
	if _, ok := js["extension/dist/index.js"]; !ok {
		t.Errorf("expected extension/dist/index.js in js map, got keys %v", keys(js))
	}
	if _, ok := js["extension/README.md"]; ok {
		t.Errorf("README.md should not appear in js map")
	}
}

func TestDownloadVSIX_sizeLimit(t *testing.T) {
	// Serve a body that exceeds the limit passed to fetchBytes.
	const smallLimit = 64
	big := bytes.Repeat([]byte("x"), smallLimit+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(big)
	}))
	defer srv.Close()

	c := New()
	_, err := c.fetchBytes(context.Background(), srv.URL, smallLimit)
	if err == nil {
		t.Fatal("expected size-limit error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds size limit") {
		t.Errorf("error %q does not mention size limit", err)
	}
}

func TestDownloadVSIX_badStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := New()
	_, _, err := c.DownloadVSIX(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected error for 404 response, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error %q does not mention 404", err)
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestPreviousVersionUniversal(t *testing.T) {
	// Marketplace orders newest-first.
	versions := []VersionInfo{
		{Version: "3.0.0", VSIXURL: "u3"},
		{Version: "2.0.0", VSIXURL: "u2"},
		{Version: "1.0.0", VSIXURL: "u1"},
	}
	ext := extension.Extension{SemVer: "2.0.0"}
	prev, ok := PreviousVersion(versions, ext)
	if !ok || prev.Version != "1.0.0" {
		t.Fatalf("got %+v ok=%v, want 1.0.0", prev, ok)
	}

	// Oldest installed version => no previous.
	if _, ok := PreviousVersion(versions, extension.Extension{SemVer: "1.0.0"}); ok {
		t.Errorf("expected no previous for oldest version")
	}

	// Local version not on marketplace => newest is used as baseline.
	prev, ok = PreviousVersion(versions, extension.Extension{SemVer: "9.9.9"})
	if !ok || prev.Version != "3.0.0" {
		t.Errorf("got %+v ok=%v, want 3.0.0 baseline", prev, ok)
	}
}

func TestPreviousVersionPlatform(t *testing.T) {
	// Multiple platforms per version, as platform-specific extensions ship.
	versions := []VersionInfo{
		{Version: "0.18.0", Platform: "win32-x64", VSIXURL: "win-new"},
		{Version: "0.18.0", Platform: "darwin-arm64", VSIXURL: "mac-new"},
		{Version: "0.17.0", Platform: "win32-x64", VSIXURL: "win-old"},
		{Version: "0.17.0", Platform: "darwin-arm64", VSIXURL: "mac-old"},
	}
	ext := extension.Extension{SemVer: "0.18.0", Version: "0.18.0-darwin-arm64"}
	prev, ok := PreviousVersion(versions, ext)
	if !ok || prev.Version != "0.17.0" || prev.VSIXURL != "mac-old" {
		t.Fatalf("got %+v ok=%v, want 0.17.0 mac-old", prev, ok)
	}
}
