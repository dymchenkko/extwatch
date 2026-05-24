// Package notifier turns an analyzer.Result into output. The policy:
//   - any HIGH-severity introduced finding -> desktop notification + full report
//   - MEDIUM or LOW only                   -> terminal report, no notification
//   - nothing introduced                   -> stay silent
//
// Keeping this decision in one place means the caller just hands off a result.
package notifier

import (
	"fmt"
	"os"
	"strings"

	"github.com/dymchenkko/extwatch/internal/analyzer"
	"github.com/gen2brain/beeep"
)

// Report applies the notification policy to an analysis result.
func Report(res analyzer.Result) {
	if len(res.Introduced) == 0 {
		return // nothing suspicious; stay quiet
	}

	printReport(res)

	if res.HasHigh() {
		notifyHigh(res)
	}
}

// printReport writes a structured, human-readable report to stdout. Findings
// are already sorted most-dangerous-first by analyzer.Analyze.
func printReport(res analyzer.Result) {
	ext := res.Extension
	var b strings.Builder

	fmt.Fprintf(&b, "\n┌─ extwatch report: %s\n", ext)
	if res.HasBaseline {
		fmt.Fprintf(&b, "│  comparing against previous version %s\n", res.PreviousVersion)
		fmt.Fprintf(&b, "│  showing patterns introduced by this update\n")
	} else {
		// No previous version to diff against: this is a from-scratch scan.
		fmt.Fprintf(&b, "│  no marketplace baseline available — scanning full install\n")
	}
	fmt.Fprintf(&b, "│  risk score: %d   highest severity: %s   findings: %d\n",
		res.RiskScore(), res.MaxSeverity(), len(res.Introduced))
	fmt.Fprintf(&b, "│\n")

	for _, f := range res.Introduced {
		fmt.Fprintf(&b, "│  [%s] %s — %s\n", f.Pattern.Severity, f.Pattern.Name, f.Pattern.Desc)
		// Manifest findings (package.json) carry no line number; omit the ":0".
		if f.Line > 0 {
			fmt.Fprintf(&b, "│      %s:%d\n", f.File, f.Line)
		} else {
			fmt.Fprintf(&b, "│      %s\n", f.File)
		}
		if f.Snippet != "" {
			fmt.Fprintf(&b, "│        %s\n", f.Snippet)
		}
	}
	fmt.Fprintf(&b, "└─\n")

	fmt.Print(b.String())
}

// notifyHigh raises a desktop notification summarising the HIGH findings. A
// failed notification (no notifier daemon, headless box) is non-fatal — we've
// already printed the full report, so we just warn on stderr.
func notifyHigh(res analyzer.Result) {
	title := fmt.Sprintf("⚠ extwatch: HIGH risk in %s", res.Extension.ID())

	// Summarise the distinct HIGH pattern names for the notification body.
	var highNames []string
	seen := make(map[string]bool)
	for _, f := range res.Introduced {
		if f.Pattern.Severity == analyzer.SeverityHigh && !seen[f.Pattern.Name] {
			seen[f.Pattern.Name] = true
			highNames = append(highNames, f.Pattern.Name)
		}
	}
	body := fmt.Sprintf("v%s introduced: %s", res.Extension.Version, strings.Join(highNames, ", "))

	if err := beeep.Notify(title, body, ""); err != nil {
		fmt.Fprintf(os.Stderr, "extwatch: could not send desktop notification: %v\n", err)
	}
}
