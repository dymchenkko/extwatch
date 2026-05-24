// Package analyzer performs the security inspection: it scans extracted .js for
// a fixed catalogue of dangerous patterns, then diffs the new version against
// the previous one so we report code that was *introduced* by the update rather
// than long-standing (already-accepted) behaviour.
package analyzer

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

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

// Pattern is one rule: a compiled regexp, what it means, and how bad it is.
type Pattern struct {
	Name     string
	Severity Severity
	Desc     string
	re       *regexp.Regexp

	// reqRe, if set, gates the pattern: a match only counts in a file where
	// reqRe also matches. We use it to require an actual `child_process` import
	// before treating exec()/spawn() as shelling out — otherwise innocent
	// `regex.exec(...)` calls (a RegExp method) in minified libraries like d3
	// produce a flood of false positives.
	reqRe *regexp.Regexp
}

// patterns is the detection catalogue. Each entry maps a regexp to a severity,
// optionally gated by a "requires" expression (see Pattern.reqRe). Notes on a
// couple of regexp choices:
//   - `\bexec\s*\(` deliberately does NOT match `execSync(` (after "exec" comes
//     "Sync", not "("), so exec and execSync stay distinct findings.
//   - the URL regexp uses \x60 to mean a literal backtick, which can't appear
//     inside a Go raw-string literal.
var patterns = buildPatterns([]patternSpec{
	// --- HIGH: code execution / shelling out -------------------------------
	// exec/execSync/spawn require a child_process import in the same file, so
	// RegExp.prototype.exec() and unrelated spawn() helpers don't false-positive.
	{"child_process", "Imports Node's child_process module (run OS commands)", `child_process`, SeverityHigh, ""},
	{"exec(", "Calls exec() to run a shell command", `\bexec\s*\(`, SeverityHigh, `child_process`},
	{"execSync(", "Calls execSync() to run a shell command synchronously", `\bexecSync\s*\(`, SeverityHigh, `child_process`},
	{"spawn(", "Spawns a child process", `\bspawn\s*\(`, SeverityHigh, `child_process`},
	// --- HIGH: dynamic code evaluation -------------------------------------
	{"eval(", "Evaluates a string as code", `\beval\s*\(`, SeverityHigh, ""},
	{"new Function(", "Builds a function from a string (eval-equivalent)", `new\s+Function\s*\(`, SeverityHigh, ""},
	// --- HIGH: credential / sensitive path access --------------------------
	{".ssh", "References the user's SSH directory", `\.ssh\b`, SeverityHigh, ""},
	{".aws", "References the user's AWS credentials directory", `\.aws\b`, SeverityHigh, ""},
	{"USERPROFILE", "Reads the Windows USERPROFILE path", `USERPROFILE`, SeverityHigh, ""},
	// --- MEDIUM: environment + network -------------------------------------
	{"process.env", "Reads process environment variables", `process\.env`, SeverityMedium, ""},
	{"fetch(", "Makes an outbound HTTP request via fetch()", `\bfetch\s*\(`, SeverityMedium, ""},
	{"WebSocket", "Opens a WebSocket connection", `WebSocket`, SeverityMedium, ""},
	{"outbound URL", "Hard-coded outbound URL", `https?://[^\s"'\x60)\]]+`, SeverityMedium, ""},
	// --- LOW ----------------------------------------------------------------
	{"clipboard", "Accesses the system clipboard", `(?i)clipboard`, SeverityLow, ""},
})

// patternSpec is the source form of a rule before compilation. requires is an
// optional regexp that must also be present in a file for the rule to fire.
type patternSpec struct {
	name, desc, expr string
	sev              Severity
	requires         string
}

// buildPatterns compiles the rule table once at package init. regexp.MustCompile
// is acceptable here because the expressions are constant: a bad regexp is a
// programmer bug, surfaced immediately at startup rather than at runtime.
func buildPatterns(specs []patternSpec) []Pattern {
	out := make([]Pattern, 0, len(specs))
	for _, s := range specs {
		p := Pattern{
			Name:     s.name,
			Severity: s.sev,
			Desc:     s.desc,
			re:       regexp.MustCompile(s.expr),
		}
		if s.requires != "" {
			p.reqRe = regexp.MustCompile(s.requires)
		}
		out = append(out, p)
	}
	return out
}

// Finding is a single pattern match located in a specific file.
type Finding struct {
	Pattern Pattern
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

// maxMatchesPerPatternFile bounds how many example matches we keep for a single
// pattern in a single file, so a minified blob with thousands of "process.env"
// hits doesn't drown the report.
const maxMatchesPerPatternFile = 3

// snippetMax truncates very long lines (minified bundles are often one giant
// line) so the report stays readable.
const snippetMax = 160

// maxDiffLineLen is the boundary between "readable" source and a minified
// mega-line. At or below it we diff the exact line text (precise: catches a new
// malicious call site even when the pattern itself is old). Above it, line-level
// diffing is meaningless — one changed bundle line would flag everything — so we
// fall back to coarse pattern-presence for that match.
const maxDiffLineLen = 300

// Analyze scans the new version's JS for dangerous patterns and keeps only what
// the update introduced. A match counts as introduced when:
//
//  1. it lives in a file that did not exist in the previous version, OR
//  2. (readable line) its exact line text is absent from the previous version, OR
//  3. (minified line) its pattern was absent from the previous version entirely.
//
// This catches a malicious *new use* of a pattern the extension already used
// (e.g. a fresh spawn('/bin/sh') alongside a legitimate spawn(server)), which a
// coarse "is the pattern anywhere in old?" check would miss.
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

	oldFiles := fileSet(oldJS)       // normalised paths present in the old version
	oldLines := lineSet(oldJS)       // every trimmed source line in the old version
	oldHas := patternPresence(oldJS) // pattern names anywhere in old (minified fallback)

	for _, f := range scanCorpus(newJS) {
		if introduced(f, oldFiles, oldLines, oldHas) {
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
// update added, given the previous version's files, lines, and patterns. See
// Analyze's doc comment for the three-way rule.
func introduced(f Finding, oldFiles, oldLines, oldHas map[string]bool) bool {
	if !oldFiles[normPath(f.File)] {
		return true // the whole file is new in this version
	}
	if len(f.fullLine) <= maxDiffLineLen {
		return !oldLines[f.fullLine] // readable line: exact-line diff
	}
	return !oldHas[f.Pattern.Name] // minified mega-line: coarse fallback
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

// patternPresence returns the set of pattern names that match anywhere in the
// given corpus. Returns an empty (non-nil) set for nil input.
func patternPresence(corpus map[string]string) map[string]bool {
	present := make(map[string]bool)
	for _, content := range corpus {
		for _, p := range patterns {
			if !present[p.Name] && p.re.MatchString(content) {
				present[p.Name] = true
			}
		}
	}
	return present
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

// scanCorpus finds every pattern match across all files, capturing line numbers
// and snippets, bounded by maxMatchesPerPatternFile per pattern/file.
func scanCorpus(corpus map[string]string) []Finding {
	var findings []Finding
	for file, content := range corpus {
		offsets := lineOffsets(content)
		for _, p := range patterns {
			// Gated patterns (e.g. exec/spawn) only count when their required
			// context (a child_process import) is present in the same file.
			if p.reqRe != nil && !p.reqRe.MatchString(content) {
				continue
			}
			locs := p.re.FindAllStringIndex(content, -1)
			for n, loc := range locs {
				if n >= maxMatchesPerPatternFile {
					break
				}
				line := lineForOffset(offsets, loc[0])
				full := lineText(content, offsets, line)
				findings = append(findings, Finding{
					Pattern:  p,
					File:     file,
					Line:     line,
					Snippet:  truncate(full, snippetMax),
					fullLine: full,
				})
			}
		}
	}
	return findings
}

// lineOffsets returns the byte offset at which each line starts. offsets[0] is
// always 0; offsets[i] is the index just after the i-th '\n'. With this we can
// binary-search a match offset to its line number in O(log n).
func lineOffsets(content string) []int {
	offsets := []int{0}
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}

// lineForOffset maps a byte offset to a 1-based line number via binary search.
func lineForOffset(offsets []int, off int) int {
	// sort.Search finds the first line start strictly greater than off; the
	// line containing off is the one before it.
	i := sort.Search(len(offsets), func(i int) bool { return offsets[i] > off })
	if i == 0 {
		return 1
	}
	return i
}

// lineText returns the trimmed (untruncated) text of a 1-based line.
func lineText(content string, offsets []int, line int) string {
	start := offsets[line-1]
	end := len(content)
	if line < len(offsets) {
		end = offsets[line] - 1 // drop the trailing '\n'
	}
	return strings.TrimSpace(content[start:end])
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
