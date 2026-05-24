package fetcher

import (
	"testing"

	"github.com/dymchenkko/extwatch/internal/extension"
)

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
