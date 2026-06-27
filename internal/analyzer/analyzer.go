// Package analyzer performs the security inspection: it scans extracted .js for
// a fixed catalogue of dangerous patterns, then diffs the new version against
// the previous one so we report code that was *introduced* by the update rather
// than long-standing (already-accepted) behaviour.
package analyzer

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dymchenkko/extwatch/internal/astscanner"
	"github.com/dymchenkko/extwatch/internal/extension"
)

// Severity ranks how alarming a pattern is. Higher value == more dangerous.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
)

// String renders a severity for report output.
func (s Severity) String() string {
	switch s {
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// weight gives each severity a numeric value for the aggregate risk score.
func (s Severity) weight() int {
	switch s {
	case SeverityHigh:
		return 10
	case SeverityMedium:
		return 3
	default:
		return 1
	}
}

// Pattern is one detected rule: its name, severity, and a human-readable
// description. The regex fields from the previous implementation have been
// removed — detection is now performed by the AST scanner.
type Pattern struct {
	Name     string
	Severity Severity
	Desc     string
}

// astPatternDesc maps AST scanner pattern names to human-readable descriptions
// for the report output.
var astPatternDesc = map[string]string{
	"exec(":               "Calls exec() to run a shell command",
	"execSync(":           "Calls execSync() to run a shell command synchronously",
	"spawn(":              "Spawns a child process",
	"spawnSync(":          "Spawns a child process synchronously",
	"eval(":               "Evaluates a string as code",
	"new Function(":       "Builds a function from a string (eval-equivalent)",
	"runInNewContext(":    "Executes code in a new vm context (eval-equivalent)",
	"runInThisContext(":   "Executes code in the current vm context (eval-equivalent)",
	"setTimeout(string)":  "Evaluates a string argument via setTimeout (eval-equivalent)",
	"setInterval(string)": "Evaluates a string argument via setInterval (eval-equivalent)",
	"process.env":         "Reads process environment variables",
	".ssh":                "References the user's SSH directory",
	".aws":                "References the user's AWS credentials directory",
	".npmrc":              "References the user's npm auth token file",
	".kube":               "References the user's Kubernetes credentials directory",
	".docker":             "References the user's Docker credentials",
	"fetch(":              "Makes an outbound HTTP request via fetch()",
	"https.request(":      "Makes an outbound HTTPS request via Node's https module",
	"http.request(":       "Makes an outbound HTTP request via Node's http module",
	"createConnection(":   "Opens a raw TCP socket via Node's net module",
	"WebSocket":           "Opens a WebSocket connection",
	"XMLHttpRequest":      "Makes an HTTP request via XMLHttpRequest",
	"createTerminal(":     "Creates a hidden VS Code terminal to run shell commands",
}

// Finding is a single pattern match located in a specific file.
type Finding struct {
	Pattern Pattern
	Module  string // resolved require() module, e.g. "child_process"; "" for globals
	Arg     string // first string-literal argument, "" if not applicable
	File    string // relative path within the extension
	Line    int    // 1-based line number of the match
	Snippet string // trimmed/truncated line containing the match (for display)

	// fullLine is the trimmed but untruncated line text, used by the diff to
	// decide whether this exact line existed in the previous version. Unexported
	// because it's an analysis detail, not part of the report.
	fullLine string
}

// Result is the outcome of comparing a new extension version against the
// previous one.
type Result struct {
	Extension       extension.Extension
	PreviousVersion string    // "" when there was no baseline to compare against
	HasBaseline     bool      // false on first install / failed download
	Introduced      []Finding // patterns present in new version but not the old
}

// snippetMax truncates very long lines (minified bundles are often one giant
// line) so the report stays readable.
const snippetMax = 160

// maxDiffLineLen is the boundary between "readable" source and a minified
// mega-line. At or below it we diff the exact line text (precise: catches a new
// malicious call site even when the pattern itself is old). Above it, line-level
// diffing is meaningless — one changed bundle line would flag everything — so we
// fall back to AST-signature diffing (see findingSet / introduced).
const maxDiffLineLen = 300

// Analyze scans the new version's JS for dangerous patterns and keeps only what
// the update introduced. A match counts as introduced when:
//
//  1. it lives in a file that did not exist in the previous version, OR
//  2. (readable line) its exact line text is absent from the previous version, OR
//  3. (minified line) its (pattern, module, arg) signature is absent from the
//     same file in the previous version.
//
// Rule 3 handles minified bundles where everything is on one giant line.
// Because variable names are mangled by bundlers (cp → a, b, c between versions),
// we cannot compare line text. Instead we compare what the AST scanner resolved:
// the pattern name ("exec("), the module it came from ("child_process"), and the
// first string argument ("whoami"). Two calls with identical signatures in the
// same file are considered the same call; a new distinct signature is flagged.
//
// Pass oldJS == nil when there is no baseline (first install, or the previous
// .vsix couldn't be fetched); then every match is introduced and HasBaseline is
// false.
func Analyze(ext extension.Extension, prevVersion string, newJS, oldJS map[string]string, newManifest, oldManifest string) Result {
	res := Result{
		Extension:       ext,
		PreviousVersion: prevVersion,
		HasBaseline:     oldJS != nil,
	}

	oldFiles := fileSet(oldJS)    // normalised paths present in the old version
	oldLines := lineSet(oldJS)    // every trimmed source line in the old version
	oldSigs  := findingSet(oldJS) // per-file AST signatures for minified fallback

	for _, f := range scanCorpus(newJS) {
		if introduced(f, oldFiles, oldLines, oldSigs) {
			res.Introduced = append(res.Introduced, f)
		}
	}

	// The package.json manifest is diffed separately (it's structured, not JS):
	// flag install scripts and eager activation that the update newly added.
	res.Introduced = append(res.Introduced, analyzeManifest(newManifest, oldManifest)...)

	// Stable, useful ordering: most dangerous first, then by file/line.
	sort.SliceStable(res.Introduced, func(i, j int) bool {
		a, b := res.Introduced[i], res.Introduced[j]
		if a.Pattern.Severity != b.Pattern.Severity {
			return a.Pattern.Severity > b.Pattern.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return res
}

// introduced decides whether a finding from the new version is something the
// update added, given the previous version's files, lines, and signatures. See
// Analyze's doc comment for the three-way rule.
func introduced(f Finding, oldFiles map[string]bool, oldLines map[string]bool, oldSigs map[string]map[string]bool) bool {
	if !oldFiles[normPath(f.File)] {
		return true // the whole file is new in this version
	}
	if len(f.fullLine) <= maxDiffLineLen {
		return !oldLines[f.fullLine] // readable line: exact-line diff
	}
	// Minified mega-line: compare by (pattern, module, arg) within the same file.
	key := f.Pattern.Name + "\x00" + f.Module + "\x00" + f.Arg
	return !oldSigs[normPath(f.File)][key]
}

// manifest holds the package.json fields relevant to security: lifecycle
// scripts that run automatically, and the events that trigger the extension.
type manifest struct {
	Scripts          map[string]string `json:"scripts"`
	ActivationEvents []string          `json:"activationEvents"`
}

// lifecycleScripts are npm script hooks that execute automatically (no user
// action) when a package is installed or prepared — a classic supply-chain
// execution vector. Note: for a packaged .vsix these don't run at install time;
// they matter most when an extension is installed from source or pulled in as a
// dependency. Mapped to a severity.
var lifecycleScripts = map[string]Severity{
	"preinstall":     SeverityHigh,
	"install":        SeverityHigh,
	"postinstall":    SeverityHigh,
	"prepare":        SeverityMedium,
	"prepublish":     SeverityMedium,
	"prepublishOnly": SeverityMedium,
}

// eagerActivation are activationEvents that make a VS Code extension run code
// automatically: "*" eagerly on every startup, onStartupFinished shortly after
// launch. Stealthy malware prefers these so its code runs with no user action.
var eagerActivation = map[string]Severity{
	"*":                 SeverityMedium,
	"onStartupFinished": SeverityLow,
}

// analyzeManifest diffs two package.json contents and returns findings for
// install scripts and eager-activation events that the new version added or
// changed. Like the JS diff, it reports only what the update introduced; with
// no baseline (oldManifest == "") everything present is reported.
func analyzeManifest(newManifest, oldManifest string) []Finding {
	newM, ok := parseManifest(newManifest)
	if !ok {
		return nil
	}
	oldM, _ := parseManifest(oldManifest)

	var out []Finding

	for name, cmd := range newM.Scripts {
		sev, watched := lifecycleScripts[name]
		if !watched {
			continue
		}
		if old, exists := oldM.Scripts[name]; exists && old == cmd {
			continue // unchanged from previous version
		}
		out = append(out, Finding{
			Pattern: Pattern{
				Name:     name + " script",
				Severity: sev,
				Desc:     "npm lifecycle script — runs automatically on install",
			},
			File:    "package.json",
			Snippet: truncate(name+": "+strings.TrimSpace(cmd), snippetMax),
		})
	}

	oldEvents := sliceSet(oldM.ActivationEvents)
	for _, ev := range newM.ActivationEvents {
		sev, watched := eagerActivation[ev]
		if !watched || oldEvents[ev] {
			continue
		}
		out = append(out, Finding{
			Pattern: Pattern{
				Name:     "activation: " + ev,
				Severity: sev,
				Desc:     "extension runs code automatically on startup",
			},
			File:    "package.json",
			Snippet: "activationEvents: " + ev,
		})
	}
	return out
}

// parseManifest decodes package.json text, tolerating empty/invalid input.
func parseManifest(s string) (manifest, bool) {
	var m manifest
	if strings.TrimSpace(s) == "" {
		return m, false
	}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return m, false
	}
	return m, true
}

// sliceSet turns a string slice into a set for membership tests.
func sliceSet(xs []string) map[string]bool {
	set := make(map[string]bool, len(xs))
	for _, x := range xs {
		set[x] = true
	}
	return set
}

// findingSet builds a per-file set of AST finding signatures for the minified
// diff fallback. The outer key is the normalised file path; the inner key is
// pattern + "\x00" + module + "\x00" + arg — the same triple used by
// introduced() to decide whether a minified-line finding is new.
func findingSet(corpus map[string]string) map[string]map[string]bool {
	sigs := make(map[string]map[string]bool)
	for file, content := range corpus {
		fp := normPath(file)
		if sigs[fp] == nil {
			sigs[fp] = make(map[string]bool)
		}
		for _, af := range astscanner.ScanFile(file, content) {
			sigs[fp][af.Pattern+"\x00"+af.Module+"\x00"+af.Arg] = true
		}
	}
	return sigs
}

// fileSet returns the set of normalised file paths in a corpus.
func fileSet(corpus map[string]string) map[string]bool {
	set := make(map[string]bool, len(corpus))
	for path := range corpus {
		set[normPath(path)] = true
	}
	return set
}

// lineSet returns the set of every trimmed, non-empty source line in a corpus.
// Used for exact-line diffing against the new version.
func lineSet(corpus map[string]string) map[string]bool {
	set := make(map[string]bool)
	for _, content := range corpus {
		for _, line := range strings.Split(content, "\n") {
			if t := strings.TrimSpace(line); t != "" {
				set[t] = true
			}
		}
	}
	return set
}

// normPath puts local-dir and .vsix paths in the same namespace so file
// identity is comparable. VS Code unpacks a .vsix's "extension/" subtree into
// the install dir, so a vsix entry "extension/dist/x.js" and the local
// "dist/x.js" are the same file once the prefix is stripped.
func normPath(p string) string {
	return strings.TrimPrefix(filepath.ToSlash(p), "extension/")
}

// scanCorpus runs the AST scanner over every file in the corpus and converts
// the results into analyzer Findings.
func scanCorpus(corpus map[string]string) []Finding {
	var findings []Finding
	for file, content := range corpus {
		for _, af := range astscanner.ScanFile(file, content) {
			desc := astPatternDesc[af.Pattern]
			if desc == "" {
				desc = af.Pattern
			}
			full := af.Snippet
			findings = append(findings, Finding{
				Pattern: Pattern{
					Name:     af.Pattern,
					Severity: Severity(af.Severity),
					Desc:     desc,
				},
				Module:   af.Module,
				Arg:      af.Arg,
				File:     file,
				Line:     af.Line,
				Snippet:  truncate(full, snippetMax),
				fullLine: full,
			})
		}
	}
	return findings
}

// truncate caps a string at n bytes, appending an ellipsis if it was cut.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// MaxSeverity returns the highest severity among introduced findings, or
// SeverityLow if there are none (callers should also check len(Introduced)).
func (r Result) MaxSeverity() Severity {
	max := SeverityLow
	for _, f := range r.Introduced {
		if f.Pattern.Severity > max {
			max = f.Pattern.Severity
		}
	}
	return max
}

// HasHigh reports whether any introduced finding is HIGH severity — the trigger
// for a desktop notification.
func (r Result) HasHigh() bool {
	for _, f := range r.Introduced {
		if f.Pattern.Severity == SeverityHigh {
			return true
		}
	}
	return false
}

// RiskScore is a coarse aggregate: the summed severity weights of distinct
// introduced patterns (counting each pattern once, not per match). It's a
// rough "how much new attack surface" number for the report header.
func (r Result) RiskScore() int {
	seen := make(map[string]bool)
	score := 0
	for _, f := range r.Introduced {
		if seen[f.Pattern.Name] {
			continue
		}
		seen[f.Pattern.Name] = true
		score += f.Pattern.Severity.weight()
	}
	return score
}
