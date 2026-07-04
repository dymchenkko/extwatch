# extwatch roadmap

## Glossary

**VSIX** — the package format used to distribute VS Code extensions. It is a
renamed ZIP archive. When VS Code installs or updates an extension it downloads
a `.vsix` file, unpacks it, and runs the code inside. extwatch fetches the
previous version's `.vsix` from the marketplace to build a baseline for
diffing.

**CJS (CommonJS)** — the original Node.js module format. Files use
`require()` to import other modules and `module.exports` to export values.
Most older VS Code extensions ship their bundled output as `.cjs` files (or
`.js` files that use `require()` internally).

**MJS (ES Modules)** — the modern JavaScript module format, standardised in
ES2015. Files use `import` / `export` syntax. Newer bundlers (esbuild, Rollup)
increasingly emit `.mjs` output. extwatch scans `.js`, `.cjs`, and `.mjs`
because all three are live JavaScript that the extension runtime executes.

---

## Current state (v0.1)

- Watches the VS Code extensions directory for installs and updates via
  filesystem events (debounced).
- Downloads the previous version's `.vsix` from the VS Code marketplace and
  diffs it against the newly installed version so only *introduced* patterns
  are reported.
- Scans `.js` / `.cjs` / `.mjs` files with an AST-based scanner that detects shell execution, eval-equivalent constructs, credential path access, and outbound network calls.
- Diffs `package.json` manifests separately to flag newly added npm lifecycle
  scripts and eager activation events.
- Outputs a terminal report; HIGH-severity findings also raise a desktop
  notification.
- Offers to disable VS Code's auto-update so new versions can be vetted before
  they run.

---

## Planned work

### 1. Scan beyond JavaScript

VS Code extensions can ship file types that carry equal or greater risk than
JavaScript but are currently ignored.

**1a. Alert when a binary file is introduced by an update**

We cannot read `.node`, `.wasm`, or compiled executables the way we read
JavaScript — they are binary formats, not source code. But we do not need to
read them. The dangerous question is not *what is inside the file* but *did
this update add a file we cannot inspect?*

The solution: when diffing old vs. new versions, check whether any binary file
appeared for the first time. If an update that previously shipped no `.node`
file suddenly includes one, that is suspicious regardless of what is inside it.
extwatch would report it as a HIGH finding: "this update introduced a native
binary that runs outside the JavaScript sandbox."

Binary types to track:
- `.node` — native Node.js addon compiled from C/C++; runs outside the JS sandbox
- `.wasm` — WebAssembly module
- Prebuilt executables — some extensions ship a compiled program alongside their JavaScript (for example, a language server or a formatter binary).

**1b. Shell script scanning**

Some extensions bundle `.sh`, `.bash`, `.zsh`, or `Makefile` helper scripts.
A line-oriented scanner (no full shell parser needed) would flag patterns like
`curl | bash`, credential harvesting (`~/.ssh`, `~/.aws`), and `base64 -d |
bash`.

**1c. Python script scanning**

Extensions that ship language servers or formatters sometimes bundle `.py`
files. A line-oriented scanner (reading the file line by line and matching
against a list of dangerous patterns) would flag:

- `subprocess` / `os.system` — Python's way of running a shell command, the
  equivalent of `exec()` in JavaScript
- `eval()` / `exec()` — execute an arbitrary string as Python code, same risk
  as JavaScript's `eval`
- `socket` — opens a raw network connection, which could be used to send data
  to an attacker's server
- Credential path reads — string literals containing paths like `~/.ssh`,
  `~/.aws`, or `~/.npmrc`, which suggest the script is looking for stored
  secrets on the user's machine

**1d. Unified scanner interface**

Phases 1b and 1c each introduce a new scanner (shell, Python) alongside the
existing JavaScript one. This phase is about making the three scanners work
together cleanly.

The idea: instead of each scanner being a one-off thing the analyzer calls
individually, they all follow the same contract — given a filename and its
contents, return a list of findings. The analyzer does not need to know which
languages exist; it just runs every scanner against every file and collects the
results. Adding a fourth language in the future would mean writing one new
scanner that follows the same contract, with no changes needed anywhere else.

---

### 2. Improve minified-bundle coverage

Most VS Code extensions ship their JavaScript **minified** — all whitespace
removed, variable names shortened to single letters, and everything collapsed
onto one giant line. This is done purely to reduce file size and is normal and
legitimate.

The current scanner looks for dangerous function names like `eval(` or `exec(`.
That works when the code is written plainly. But a malicious author can hide
those names so a simple text search misses them. Common tricks:

- **Character code encoding** — instead of writing `eval`, write
  `String.fromCharCode(101,118,97,108)`, which produces the string `"eval"` at
  runtime. The scanner sees no `eval` in the source.
- **Hex / unicode escapes** — `\x65\x76\x61\x6c` is another way to spell
  `"eval"` that looks like noise to a scanner.
- **Roundabout property access** — `[]["constructor"]` is an obscure but valid
  way to reach the `Function` constructor, which can execute arbitrary code the
  same way `eval` can.

The goal of this phase is to teach the scanner to recognise these disguises so
that deliberately obfuscated malicious code is as visible as plainly written
malicious code.

---

### 3. Block mode

Today extwatch is detection-only — it reports findings but never prevents an
extension from running. A future mode could quarantine a newly installed
extension directory (remove execute permissions or rename it) until the user
explicitly approves it. This would require careful handling of the VS Code
extension host lifecycle to avoid leaving the editor in a broken state.

---

### 4. Richer reporting

- Machine-readable JSON output (for CI or scripted pipelines).
- A summary log file that persists findings across runs.
- Per-extension allowlist so a known-safe pattern in a trusted extension does
  not produce repeated noise.
