// Package astscanner replaces the regex-based pattern matching in
// internal/analyzer with a proper JavaScript AST walk.
//
// The public surface is intentionally minimal: ScanFile is the only entry
// point. Once the test suite is green this package will be wired into
// analyzer.Analyze in place of the current scanCorpus function.
package astscanner

import (
	"sort"
	"strings"
	"unsafe"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// Severity mirrors analyzer.Severity so the two packages can be integrated
// without a circular import.
type Severity int

const (
	Low Severity = iota
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// Finding is one detected dangerous pattern in a single JS file.
type Finding struct {
	Pattern  string   // short name, e.g. "exec(", "process.env"
	Module   string   // resolved require() module, e.g. "child_process"; "" if global/unknown
	Arg      string   // first string-literal argument, "" if not a string or not applicable
	Severity Severity
	Line     int    // 1-based; 0 for findings with no meaningful line
	Snippet  string // trimmed source line containing the match
}

// ScanFile parses the JavaScript in content and returns every dangerous
// pattern it finds. filename is used only for error context; it does not
// affect which patterns are detected.
func ScanFile(filename, content string) []Finding {
	// Use one []byte allocation for both the parser and position calculation.
	// tdewolff returns Var.Data and LiteralExpr.Data as sub-slices of this
	// buffer, which lets sliceOffset compute byte positions without copying.
	contentBytes := []byte(content)

	ast, _ := js.Parse(parse.NewInputBytes(contentBytes), js.Options{})
	if ast == nil {
		return nil
	}

	offsets := lineOffsets(content)

	// Pass 1: build the require() binding map.
	b := newBindings()
	js.Walk(&bindingCollector{b: b}, ast)

	// Pass 2: detect dangerous patterns using those bindings.
	d := &detector{
		filename:     filename,
		content:      content,
		contentBytes: contentBytes,
		offsets:      offsets,
		bindings:     b,
	}
	js.Walk(d, ast)

	return d.findings
}

// ── binding map ───────────────────────────────────────────────────────────────

type bindings struct {
	// module: local variable → required module name.
	// Built from:  const cp = require('child_process')  →  "cp" → "child_process"
	module map[string]string

	// direct: destructured function name → required module name.
	// Built from:  const { exec } = require('child_process')  →  "exec" → "child_process"
	direct map[string]string
}

func newBindings() *bindings {
	return &bindings{
		module: make(map[string]string),
		direct: make(map[string]string),
	}
}

// ── pass 1: binding collector ─────────────────────────────────────────────────

type bindingCollector struct{ b *bindings }

func (bc *bindingCollector) Enter(n js.INode) js.IVisitor {
	decl, ok := n.(*js.VarDecl)
	if !ok {
		return bc
	}
	for _, item := range decl.List {
		bc.trackItem(item)
	}
	return bc
}

func (bc *bindingCollector) Exit(_ js.INode) {}

func (bc *bindingCollector) trackItem(item js.BindingElement) {
	if item.Default == nil || item.Binding == nil {
		return
	}
	mod, ok := asRequireModule(item.Default)
	if !ok {
		return
	}
	switch b := item.Binding.(type) {
	case *js.Var:
		// const cp = require('child_process')
		bc.b.module[string(b.Name())] = mod
	case *js.BindingObject:
		// const { exec, spawn } = require('child_process')
		for _, objItem := range b.List {
			if v, ok := objItem.Value.Binding.(*js.Var); ok {
				bc.b.direct[string(v.Name())] = mod
			}
		}
	}
}

// asRequireModule returns the module name if expr is `require('literal-string')`.
// Returns ("", false) for anything else, including require('a' + 'b').
func asRequireModule(expr js.IExpr) (string, bool) {
	call, ok := expr.(*js.CallExpr)
	if !ok {
		return "", false
	}
	callee, ok := call.X.(*js.Var)
	if !ok || string(callee.Data) != "require" {
		return "", false
	}
	if len(call.Args.List) == 0 {
		return "", false
	}
	lit, ok := call.Args.List[0].Value.(*js.LiteralExpr)
	if !ok || lit.TokenType != js.StringToken {
		return "", false
	}
	return strings.Trim(string(lit.Data), `"'`), true
}

// ── detection catalogue ───────────────────────────────────────────────────────

type moduleMethodSpec struct {
	module, method, pattern string
	sev                     Severity
}

// moduleMethodCatalogue maps (module, method) to a dangerous finding.
// The module is the value from the require() binding map; the method is the
// property name called on the bound variable.
var moduleMethodCatalogue = []moduleMethodSpec{
	// child_process — shell execution
	{"child_process", "exec",             "exec(",             High},
	{"child_process", "execSync",         "execSync(",         High},
	{"child_process", "spawn",            "spawn(",            High},
	{"child_process", "spawnSync",        "spawnSync(",        High},
	// vm — eval equivalents
	{"vm", "runInNewContext",  "runInNewContext(",  High},
	{"vm", "runInThisContext", "runInThisContext(", High},
	// network modules (not in the regex catalogue)
	{"https", "request",          "https.request(",    Medium},
	{"http",  "request",          "http.request(",     Medium},
	{"net",   "createConnection", "createConnection(", Medium},
	// VS Code API — hidden terminal = shell execution
	{"vscode", "createTerminal", "createTerminal(", High},
}

type globalSpec struct {
	name, pattern string
	sev           Severity
}

// globalCallCatalogue covers calls that are dangerous as bare global functions.
var globalCallCatalogue = []globalSpec{
	{"eval",  "eval(",  High},
	{"fetch", "fetch(", Medium},
}

type newSpec struct {
	name, pattern string
	sev           Severity
}

// newExprCatalogue covers dangerous `new X()` constructor calls.
var newExprCatalogue = []newSpec{
	{"Function",       "new Function(",  High},
	{"WebSocket",      "WebSocket",      Medium},
	{"XMLHttpRequest", "XMLHttpRequest", Medium},
}

type credPathSpec struct {
	fragment, pattern string
	sev               Severity
}

// credPathCatalogue lists sensitive path fragments checked in string literals.
var credPathCatalogue = []credPathSpec{
	{".ssh",    ".ssh",    High},
	{".aws",    ".aws",    High},
	{".npmrc",  ".npmrc",  High},
	{".kube",   ".kube",   High},
	{".docker", ".docker", High},
}

// ── pass 2: detector ──────────────────────────────────────────────────────────

type detector struct {
	filename     string
	content      string
	contentBytes []byte
	offsets      []int
	bindings     *bindings
	findings     []Finding
}

func (d *detector) Enter(n js.INode) js.IVisitor {
	switch node := n.(type) {
	case *js.CallExpr:
		d.checkCall(node)
	case *js.NewExpr:
		d.checkNew(node)
	case *js.DotExpr:
		d.checkMemberDot(node)
	case *js.IndexExpr:
		d.checkMemberIndex(node)
	case *js.LiteralExpr:
		d.checkStringLiteral(node)
	}
	return d
}

func (d *detector) Exit(_ js.INode) {}

func (d *detector) checkCall(node *js.CallExpr) {
	mod, method := d.resolveCallee(node.X)
	leaf := calleeLeafData(node.X)

	if mod != "" {
		for _, spec := range moduleMethodCatalogue {
			if spec.module == mod && spec.method == method {
				d.emit(spec.pattern, mod, d.firstArgStr(node.Args), spec.sev, leaf)
				return
			}
		}
		return
	}

	// Global / unresolved callee.
	switch method {
	case "eval":
		d.emit("eval(", "", d.firstArgStr(node.Args), High, leaf)
	case "fetch":
		d.emit("fetch(", "", d.firstArgStr(node.Args), Medium, leaf)
	case "setTimeout", "setInterval":
		// Only dangerous when the first argument is a string literal (eval equivalent).
		// A function argument is the normal, safe usage.
		if d.firstArgIsString(node.Args) {
			d.emit(method+"(string)", "", d.firstArgStr(node.Args), High, leaf)
		}
	}
}

func (d *detector) checkNew(node *js.NewExpr) {
	v, ok := node.X.(*js.Var)
	if !ok {
		return
	}
	name := string(v.Name())
	for _, spec := range newExprCatalogue {
		if spec.name == name {
			d.emit(spec.pattern, "", "", spec.sev, v.Data)
			return
		}
	}
}

// checkMemberDot detects process.env via dot notation.
func (d *detector) checkMemberDot(node *js.DotExpr) {
	root, ok := node.X.(*js.Var)
	if !ok {
		return
	}
	if string(root.Name()) == "process" && varName(node.Y) == "env" {
		d.emit("process.env", "", "", Medium, root.Data)
	}
}

// checkMemberIndex detects process['env'] via bracket notation —
// the case a regex with a literal dot cannot match.
func (d *detector) checkMemberIndex(node *js.IndexExpr) {
	root, ok := node.X.(*js.Var)
	if !ok {
		return
	}
	if string(root.Name()) != "process" {
		return
	}
	lit, ok := node.Y.(*js.LiteralExpr)
	if !ok || lit.TokenType != js.StringToken {
		return
	}
	if strings.Trim(string(lit.Data), `"'`) == "env" {
		d.emit("process.env", "", "", Medium, root.Data)
	}
}

func (d *detector) checkStringLiteral(node *js.LiteralExpr) {
	if node.TokenType != js.StringToken {
		return
	}
	val := strings.Trim(string(node.Data), `"'`)
	for _, spec := range credPathCatalogue {
		if strings.Contains(val, spec.fragment) {
			// val becomes the Arg so two different paths (.ssh/id_rsa vs .ssh/id_ed25519)
			// produce distinct diff signatures even in minified bundles.
			d.emit(spec.pattern, "", val, spec.sev, node.Data)
			return
		}
	}
}

// ── callee resolution ─────────────────────────────────────────────────────────

// resolveCallee walks a callee expression and returns (resolvedModule, methodName).
//
//	cp.exec(...)       where cp→child_process  →  ("child_process", "exec")
//	exec(...)          destructured             →  ("child_process", "exec")
//	eval(...)          global                   →  ("", "eval")
//	vscode.window.createTerminal(...)           →  ("vscode", "createTerminal")
func (d *detector) resolveCallee(expr js.IExpr) (module, method string) {
	switch e := expr.(type) {
	case *js.Var:
		name := string(e.Name())
		if mod, ok := d.bindings.direct[name]; ok {
			// Destructured: exec → child_process, so method name == local name.
			return mod, name
		}
		return "", name

	case *js.DotExpr:
		meth := varName(e.Y)
		// Recurse into the object first.
		objMod, _ := d.resolveCallee(e.X)
		if objMod != "" {
			// Object was already resolved to a module (handles chained access
			// like vscode.window.createTerminal where the middle step returns
			// the vscode module).
			return objMod, meth
		}
		// Object not resolved recursively — try the root variable directly.
		if root := rootVarName(e.X); root != "" {
			if mod, ok := d.bindings.module[root]; ok {
				return mod, meth
			}
		}
		return "", meth
	}
	return "", ""
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (d *detector) firstArgIsString(args js.Args) bool {
	if len(args.List) == 0 {
		return false
	}
	lit, ok := args.List[0].Value.(*js.LiteralExpr)
	return ok && lit.TokenType == js.StringToken
}

// firstArgStr returns the unquoted value of the first argument if it is a
// string literal, or "" otherwise. Used to build per-call diff signatures.
func (d *detector) firstArgStr(args js.Args) string {
	if len(args.List) == 0 {
		return ""
	}
	lit, ok := args.List[0].Value.(*js.LiteralExpr)
	if !ok || lit.TokenType != js.StringToken {
		return ""
	}
	return strings.Trim(string(lit.Data), `"'`)
}

// varName extracts the identifier or string value from a Var or LiteralExpr.
func varName(expr js.IExpr) string {
	switch e := expr.(type) {
	case *js.Var:
		return string(e.Name())
	case *js.LiteralExpr: // pointer — string/number literal in expressions
		return strings.Trim(string(e.Data), `"'`)
	case js.LiteralExpr: // value — property name in DotExpr.Y
		return strings.Trim(string(e.Data), `"'`)
	}
	return ""
}

// rootVarName follows a member-expression chain and returns the root variable name.
// For a.b.c it returns "a".
func rootVarName(expr js.IExpr) string {
	switch e := expr.(type) {
	case *js.Var:
		return string(e.Name())
	case *js.DotExpr:
		return rootVarName(e.X)
	case *js.IndexExpr:
		return rootVarName(e.X)
	}
	return ""
}

// calleeLeafData returns the raw bytes of the leaf identifier in a callee
// expression. For "cp.exec" this is the bytes of "exec"; for a bare "eval"
// it is the bytes of "eval". Used to compute the source position of a finding.
func calleeLeafData(expr js.IExpr) []byte {
	switch e := expr.(type) {
	case *js.Var:
		return e.Data
	case *js.DotExpr:
		if v, ok := e.Y.(*js.Var); ok {
			return v.Data
		}
		if lit, ok := e.Y.(js.LiteralExpr); ok { // property name stored as value
			return lit.Data
		}
		return calleeLeafData(e.X)
	}
	return nil
}

// emit records a Finding, computing the line number and snippet from the
// byte position of nodeData within the source.
func (d *detector) emit(pattern, module, arg string, sev Severity, nodeData []byte) {
	line, snippet := d.position(nodeData)
	d.findings = append(d.findings, Finding{
		Pattern:  pattern,
		Module:   module,
		Arg:      arg,
		Severity: sev,
		Line:     line,
		Snippet:  snippet,
	})
}

// position converts a node's source data slice to a 1-based line number and
// the trimmed text of that line.
//
// nodeData is a sub-slice of d.contentBytes (tdewolff returns slices into its
// input, not copies). The byte offset is recovered via unsafe pointer arithmetic,
// which is safe here because both slices share the same backing array for the
// lifetime of this scan.
func (d *detector) position(nodeData []byte) (line int, snippet string) {
	if len(nodeData) == 0 {
		return 1, ""
	}
	off := sliceOffset(d.contentBytes, nodeData)
	if off < 0 {
		return 1, ""
	}
	line = lineForOffset(d.offsets, off)
	snippet = lineText(d.content, d.offsets, line)
	return line, snippet
}

// sliceOffset returns the byte offset of sub within src.
// Both slices must share the same backing array — guaranteed here because
// we pass one []byte allocation to both parse.NewInputBytes and sliceOffset.
func sliceOffset(src, sub []byte) int {
	if len(src) == 0 || len(sub) == 0 {
		return -1
	}
	off := int(uintptr(unsafe.Pointer(&sub[0])) - uintptr(unsafe.Pointer(&src[0])))
	if off < 0 || off >= len(src) {
		return -1
	}
	return off
}

// lineOffsets returns the byte offset at which each line starts.
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
	i := sort.Search(len(offsets), func(i int) bool { return offsets[i] > off })
	if i == 0 {
		return 1
	}
	return i
}

// lineText returns the trimmed text of a 1-based line.
func lineText(content string, offsets []int, line int) string {
	if line < 1 || line-1 >= len(offsets) {
		return ""
	}
	start := offsets[line-1]
	end := len(content)
	if line < len(offsets) {
		end = offsets[line] - 1
	}
	return strings.TrimSpace(content[start:end])
}
