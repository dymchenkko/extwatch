// Package extension defines the core domain model: the identity of an installed
// VS Code extension, parsed from its on-disk directory name. It has no
// dependencies on the other packages, so watcher, fetcher, and analyzer can all
// share the same Extension type without an import cycle.
package extension

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Extension is the parsed identity of a single installed extension, derived
// purely from its on-disk directory name. VS Code stores each extension in a
// directory named "<publisher>.<name>-<version>", e.g.
// "eamodio.gitlens-17.12.2". Some names and versions contain hyphens of their
// own (e.g. "ms-azuretools.vscode-docker-2.0.0" or platform-tagged
// "docker.docker-0.18.0-darwin-arm64"), which is why parsing is non-trivial.
type Extension struct {
	Publisher string // e.g. "eamodio"
	Name      string // e.g. "gitlens"
	Version   string // full version tag, may include a platform suffix
	SemVer    string // just the X.Y.Z core, stripped of any platform suffix
	Dir       string // absolute path to the extension's directory on disk
}

// ID returns the marketplace-style identifier "publisher.name", which is what
// the marketplace query API expects as a lookup key.
func (e Extension) ID() string {
	return e.Publisher + "." + e.Name
}

// String gives a compact human-readable label used in log/report output.
func (e Extension) String() string {
	return fmt.Sprintf("%s.%s@%s", e.Publisher, e.Name, e.Version)
}

// PlatformSuffix extracts a "darwin-arm64"-style platform tag from the version
// string, or "" if the extension is platform-agnostic. VS Code encodes the
// platform after the semver core, e.g. "0.18.0-darwin-arm64".
func (e Extension) PlatformSuffix() string {
	if len(e.Version) <= len(e.SemVer) {
		return ""
	}
	return strings.TrimPrefix(e.Version[len(e.SemVer):], "-")
}

// dirNamePattern splits an extension directory name into publisher, name and
// version. The trick is the version: we anchor it to the first segment that
// looks like a semantic version (X.Y.Z...). Everything before that is the
// (possibly hyphenated) name, everything from it on is the (possibly
// platform-suffixed) version.
//
//	^([^.]+)\.   publisher: everything up to the first dot
//	(.+?)-       name: shortest run up to the hyphen before the version
//	(\d+\.\d+\.\d+.*)$  version: starts at the first X.Y.Z we see
//
// The non-greedy name (.+?) combined with the digit-anchored version is what
// makes "vscode-docker-2.0.0" resolve to name="vscode-docker", ver="2.0.0"
// rather than name="vscode", ver="docker-2.0.0".
var dirNamePattern = regexp.MustCompile(`^([^.]+)\.(.+?)-(\d+\.\d+\.\d+.*)$`)

// semverPrefix pulls the leading X.Y.Z out of a version tag, discarding any
// trailing "-darwin-arm64"-style platform suffix.
var semverPrefix = regexp.MustCompile(`^\d+\.\d+\.\d+`)

// ParseDir turns an absolute extension directory path into an Extension. It
// returns ok=false (rather than an error) for paths that don't match the naming
// convention, because the watcher routinely sees unrelated paths (".obsolete",
// "extensions.json", temp files) that we simply skip.
func ParseDir(dir string) (Extension, bool) {
	base := filepath.Base(dir)
	// VS Code installs/updates atomically: it extracts into a staging dir named
	// "<id>-<version>.-<hash>.vsctmp" and then renames it to the final
	// "<id>-<version>". These staging dirs look like real extensions but are
	// transient — gone by the time our debounce fires — and the rename emits its
	// own Create event for the real directory. So we ignore .vsctmp outright.
	if strings.HasSuffix(base, ".vsctmp") {
		return Extension{}, false
	}
	m := dirNamePattern.FindStringSubmatch(base)
	if m == nil {
		return Extension{}, false
	}
	ext := Extension{
		Publisher: m[1],
		Name:      m[2],
		Version:   m[3],
		SemVer:    semverPrefix.FindString(m[3]),
		Dir:       dir,
	}
	return ext, true
}
