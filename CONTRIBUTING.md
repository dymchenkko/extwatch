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
  analyzer/        detection patterns, version diff, scoring
  notifier/        terminal report + desktop notification
```

Tests live next to the package they cover. New detection logic should come with
a test in `internal/analyzer/analyzer_test.go`.

## Ground rules

- Run `gofmt -w .`, `go vet ./...`, and `go test ./...` before opening a PR.
- Keep functions small and commented in the existing style (this is a learning
  codebase — clarity over cleverness).
- New detection patterns: add to the catalogue in `internal/analyzer/analyzer.go`
  with an honest severity, and add a test case showing it fires (and, ideally,
  that it doesn't false-positive on benign code).

## Good first issues

Concrete, self-contained things that would genuinely help:

- **Broaden credential patterns** — detect `.npmrc`, browser "Login Data" paths,
  and `keychain`/`Credentials` access (currently only `.ssh`/`.aws`/`process.env`).
- **More network sinks** — `https.get` / `http.request`, raw IP-address literals,
  and known exfil endpoints (Discord/Telegram webhooks, pastebin).
- **Obfuscation heuristic** — flag likely-encoded payloads: `Buffer.from(..., 'base64')`,
  `atob(`, and long `\x..`/hex string runs. (See the `obfuscated` profile in
  `simulate.sh` for what currently slips past.)
- **AST-based detection** — replace substring matching for one pattern (e.g.
  `child_process` usage) with a real JS parser to cut false positives further.
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
