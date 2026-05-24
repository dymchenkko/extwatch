// Package fetcher gathers the code to be analysed: it queries the VS Code
// marketplace for an extension's version history, downloads and unpacks the
// previous version's .vsix, and extracts .js source from both the local install
// and the downloaded package.
package fetcher

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dymchenkko/extwatch/internal/extension"
)

// The local (current) version is already unzipped on disk by VS Code, so we
// read it directly; only the *previous* version needs downloading.

const (
	marketplaceQueryURL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"

	// vsixAssetType is the file entry in a marketplace version that points at
	// the actual .vsix package download.
	vsixAssetType = "Microsoft.VisualStudio.Services.VSIXPackage"

	// maxJSFileBytes caps how much we read from any single .js file. Extension
	// bundles can be tens of MB; this keeps memory bounded while still covering
	// realistic source files. (A limitation noted in the README.)
	maxJSFileBytes = 8 << 20 // 8 MiB

	// queryFlags asks the marketplace to include version history and the file
	// asset list (which carries the .vsix download URL). 51 == IncludeVersions |
	// IncludeFiles | IncludeCategoryAndTags | IncludeVersionProperties.
	queryFlags = 51
)

// Client wraps an HTTP client configured for the marketplace API.
type Client struct {
	http *http.Client
}

// New returns a Client with sane timeouts. A single shared client reuses
// connections across lookups.
func New() *Client {
	return &Client{
		http: &http.Client{Timeout: 60 * time.Second},
	}
}

// VersionInfo is one published version of an extension, narrowed to the fields
// we care about.
type VersionInfo struct {
	Version  string // e.g. "2026.5.210618"
	Platform string // targetPlatform, e.g. "darwin-arm64"; empty == universal
	VSIXURL  string // direct download URL for the .vsix, may be empty
}

// queryResponse mirrors the (large) marketplace JSON response, declaring only
// the fields we read. Unlisted fields are ignored by encoding/json.
type queryResponse struct {
	Results []struct {
		Extensions []struct {
			Versions []struct {
				Version        string `json:"version"`
				TargetPlatform string `json:"targetPlatform"`
				Files          []struct {
					AssetType string `json:"assetType"`
					Source    string `json:"source"`
				} `json:"files"`
			} `json:"versions"`
		} `json:"extensions"`
	} `json:"results"`
}

// Versions returns every published version of an extension, newest first,
// exactly as the marketplace orders them.
func (c *Client) Versions(ctx context.Context, id string) ([]VersionInfo, error) {
	// The query body filters by extension id (filterType 7 == "ExtensionName").
	body := map[string]any{
		"filters": []map[string]any{{
			"criteria": []map[string]any{
				{"filterType": 7, "value": id},
			},
			"pageNumber": 1,
			"pageSize":   1,
		}},
		"flags": queryFlags,
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, marketplaceQueryURL, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The api-version in Accept is mandatory; the marketplace 404s without it.
	req.Header.Set("Accept", "application/json;api-version=3.0-preview.1")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query marketplace: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("marketplace returned %s", resp.Status)
	}

	var qr queryResponse
	if err := json.NewDecoder(resp.Body).Decode(&qr); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if len(qr.Results) == 0 || len(qr.Results[0].Extensions) == 0 {
		return nil, fmt.Errorf("extension %q not found on marketplace", id)
	}

	raw := qr.Results[0].Extensions[0].Versions
	out := make([]VersionInfo, 0, len(raw))
	for _, v := range raw {
		vi := VersionInfo{Version: v.Version, Platform: v.TargetPlatform}
		for _, f := range v.Files {
			if f.AssetType == vsixAssetType {
				vi.VSIXURL = f.Source
				break
			}
		}
		out = append(out, vi)
	}
	return out, nil
}

// PreviousVersion picks the version to diff the local install against. The
// marketplace lists versions newest-first and may carry one entry per platform,
// so we first narrow to versions that match the local platform (or universal
// ones), then locate the local version and return the next-older entry.
//
// Heuristic when the local version isn't on the marketplace (dev builds,
// yanked releases): fall back to the newest published version as the baseline,
// since that's the most recent known-good code to compare against.
func PreviousVersion(versions []VersionInfo, ext extension.Extension) (VersionInfo, bool) {
	want := ext.PlatformSuffix() // "" for universal extensions

	// Keep only versions whose platform matches ours or that are universal.
	var candidates []VersionInfo
	for _, v := range versions {
		if v.Platform == "" || v.Platform == want {
			candidates = append(candidates, v)
		}
	}
	if len(candidates) == 0 {
		candidates = versions // platform filter wiped everything; don't give up
	}

	// Find the locally installed version within the candidate list.
	for i, v := range candidates {
		if v.Version == ext.SemVer {
			if i+1 < len(candidates) {
				return candidates[i+1], true // the next-older version
			}
			return VersionInfo{}, false // local is the oldest known; nothing prior
		}
	}

	// Local version not found upstream: use the newest published version as a
	// baseline, unless that *is* the local version (shouldn't happen here).
	if len(candidates) > 0 && candidates[0].Version != ext.SemVer {
		return candidates[0], true
	}
	return VersionInfo{}, false
}

// vsixManifestPath is where the extension's package.json lives inside a .vsix
// (everything is packed under an "extension/" directory).
const vsixManifestPath = "extension/package.json"

// DownloadVSIX downloads the .vsix at url, unzips it in memory, and returns the
// map of relative-path -> .js source plus the package.json manifest content
// (empty if absent).
func (c *Client) DownloadVSIX(ctx context.Context, url string) (js map[string]string, manifest string, err error) {
	if url == "" {
		return nil, "", fmt.Errorf("no .vsix download URL available")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", fmt.Errorf("build download request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("download vsix: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("vsix download returned %s", resp.Status)
	}

	// archive/zip needs random access (io.ReaderAt + size), which a streaming
	// HTTP body doesn't provide. Buffer the whole .vsix into memory first; for
	// extension packages (single-digit MB) this is fine.
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read vsix body: %w", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, "", fmt.Errorf("open vsix as zip: %w", err)
	}

	js = make(map[string]string)
	for _, f := range zr.File {
		switch {
		case f.Name == vsixManifestPath:
			if content, err := readZipFile(f); err == nil {
				manifest = content
			}
		case isJSFile(f.Name):
			content, err := readZipFile(f)
			if err != nil {
				continue // one unreadable entry shouldn't sink the analysis
			}
			js[f.Name] = content
		}
	}
	return js, manifest, nil
}

// readZipFile reads a single entry from a zip, bounded by maxJSFileBytes.
func readZipFile(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxJSFileBytes))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ExtractLocal walks the already-unzipped local extension directory and returns
// the map of relative-path -> .js source plus the top-level package.json content
// (empty if absent). Paths are relative to the extension dir.
func ExtractLocal(ext extension.Extension) (js map[string]string, manifest string, err error) {
	js = make(map[string]string)
	walkErr := filepath.WalkDir(ext.Dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isJSFile(path) {
			return nil
		}
		rel, relErr := filepath.Rel(ext.Dir, path)
		if relErr != nil {
			rel = path
		}
		f, openErr := os.Open(path)
		if openErr != nil {
			return nil // skip unreadable file rather than abort the walk
		}
		defer f.Close()
		data, readErr := io.ReadAll(io.LimitReader(f, maxJSFileBytes))
		if readErr != nil {
			return nil
		}
		js[rel] = string(data)
		return nil
	})
	if walkErr != nil {
		return nil, "", fmt.Errorf("walk local extension dir: %w", walkErr)
	}

	// The manifest sits at the extension root, not under "extension/" locally.
	if data, readErr := os.ReadFile(filepath.Join(ext.Dir, "package.json")); readErr == nil {
		manifest = string(data)
	}
	return js, manifest, nil
}

// isJSFile reports whether a path looks like a JavaScript source file. We treat
// .js and .cjs/.mjs alike since extensions ship all three.
func isJSFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".js", ".cjs", ".mjs":
		return true
	default:
		return false
	}
}
