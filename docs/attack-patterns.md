# Attack patterns extwatch detects

VS Code extensions run with the same permissions as you — they can read your files,
talk to the internet, and execute programs. A malicious extension can do all of this
silently, in the background, while you write code.

extwatch watches for five families of attack. Here is what each one means in plain terms.

---

## 1. Running commands on your computer

**What the attacker does:**
The extension quietly opens a terminal and runs shell commands — the same as if someone
sat down at your keyboard and started typing. They can download malware, delete files,
create backdoors, or install programs you never asked for.

**Real example:**
In 2022 the `node-ipc` npm package (used by millions of developers) used this technique
to destroy files on computers.

**What extwatch catches:**
Any use of Node's `child_process` module — `exec`, `execSync`, `spawn`, `spawnSync` —
and VS Code's own terminal API(`createTerminal`), which lets an extension run commands through a hidden terminal window.

---

## 2. Hiding malicious code inside a string

**What the attacker does:**
Instead of writing the dangerous code directly (which is easy to spot), the attacker
encodes it as text and runs it at the last moment. The code never appears in readable
form in the file — it only exists in memory when it executes. This is how malware hides
from security scanners.

**Real example:**
```
eval(atob('cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ2lkJyk='))
```
That encoded string decodes to `require('child_process').exec('id')` — a shell command disguised as gibberish.

**What extwatch catches:**
`eval()`, `new Function()`, Node's `vm` module (`runInNewContext`, `runInThisContext`), and `setTimeout` / `setInterval` when passed a string instead of a function (a lesser-known but identical trick).

---

## 3. Stealing your passwords and secret keys

**What the attacker does:**
Your computer stores credentials in well-known locations. An extension has full filesystem access, so it can read any of these files and send the contents to an attacker's server.

**Files extwatch watches for:**

| File / folder | What it contains |
|---|---|
| `~/.ssh/` | SSH private keys — used to log into servers |
| `~/.aws/` | AWS access keys — control over cloud infrastructure |
| `~/.npmrc` | npm auth tokens — lets the attacker publish packages as you |
| `~/.kube/config` | Kubernetes credentials — full control over your clusters |
| `~/.docker/config.json` | Docker registry tokens — access to private images |

extwatch also watches for `process.env` access — the standard way extensions read
environment variables, where API keys and database passwords are commonly stored.

---

## 4. Sending your data to an attacker's server

**What the attacker does:**
After collecting credentials or source code, the extension sends them out over the
internet. There are many ways to do this, and attackers deliberately use obscure ones
to avoid simple pattern matching.

**What extwatch catches:**

| Method | What it is |
|---|---|
| `fetch()` | The standard browser/Node HTTP call |
| `https.request()` / `http.request()` | Node's built-in HTTP modules |
| `net.createConnection()` | A raw TCP socket — no HTTP overhead, no URL in the code |
| `new WebSocket()` | A persistent two-way connection to a remote server |
| `new XMLHttpRequest()` | An older HTTP API available in VS Code webviews |

Catching all of these matters because an attacker who knows you watch for `fetch()`
will simply use `net.createConnection()` instead.

---

## 5. Running commands through a hidden VS Code terminal

**What the attacker does:**
You know how some VS Code extensions open a terminal at the bottom of the screen to
show you output — a linter, a build tool, a test runner? Extensions can do the same
thing, but with the terminal hidden and with whatever commands they want typed into it.
The result is identical to attack #1: arbitrary commands run on your machine. The
difference is *how* — instead of using Node.js directly, the attacker uses VS Code's
own built-in terminal feature, which is less commonly watched for.

**What extwatch catches:**
Any extension that creates a VS Code terminal (`createTerminal`), flagged at the
highest severity level — because there is almost no legitimate reason for an extension
to create a hidden terminal.

---

## What extwatch does not catch

No static scanner catches everything. There are three ways a clever attacker can
slip past extwatch:

- **The payload is fully hidden.** We watch for `eval()` — the instruction that says
  "run this secret message as code." We can see that the instruction exists, but if the
  message itself is encoded gibberish, we cannot read what it actually does. We flag the suspicious wrapper, but we can't tell you what the hidden code will execute.

- **The attacker spells the module name in pieces.** extwatch recognises dangerous
  modules like `child_process` by their name. If an attacker writes
  `'child' + '_process'` (two pieces joined together), the full name never appears
  in the code as a single word, so we don't recognise it. Think of it like writing
  "pass" and "word" in separate cells of a spreadsheet — a word search for "password"
  would miss it.

- **The attack only triggers under specific conditions.** An extension could look
  completely clean but include a hidden rule: "only steal files if today is after
  January 1st" or "only run the malicious code when the user opens a file named
  `secrets.json`." extwatch reads the code without running it, so it cannot see
  behaviour that only appears under certain conditions — the same way reading a recipe
  does not tell you what the food will taste like.

extwatch is a first line of defence, not a guarantee. Its goal is to make common
supply-chain attacks significantly harder to pull off silently.
