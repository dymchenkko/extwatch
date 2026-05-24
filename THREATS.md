# What extwatch watches for — in plain English

This guide explains, without any technical background, the kinds of bad behavior
extwatch looks for and why they matter. If you've ever wondered "how could a
code editor add-on possibly be dangerous?", this is for you.

---

## First, what is a VS Code extension?

VS Code is a popular program that people use to write software. Like a web
browser with add-ons, it lets you install **extensions** — small add-ons that
add features (themes, spell-checkers, language helpers, and so on).

Here's the catch: **an extension is a tiny program that runs on your computer
with the same access you have.** It can read your files, use your internet
connection, and run commands — just like you can. Most extensions are made by
honest people and do exactly what they advertise. But a malicious one (or a good
one that gets hijacked) has a lot of power.

> **The key risk isn't installing something obviously shady.** It's that an
> extension you already trust quietly turns bad in an **update**. You installed a
> helpful tool months ago; today's automatic update slips in something nasty.
> That's the exact situation extwatch is built to notice.

---

## A simple way to picture it

Think of an extension as a **contractor you hire to work in your house**.

- A good contractor does the job and leaves.
- A bad one might **copy your house keys**, **let a stranger in through the back
  door**, **rummage through your filing cabinet**, or **walk out with your
  documents** — all while you're busy in another room.

extwatch is like a **security camera on the front door**. It doesn't lock the
contractor out, but it notices when something changed and shows you exactly what
looks suspicious, so *you* can decide what to do.

---

## The kinds of bad behavior we look for

Here are the most common tricks seen in real-world attacks, in everyday terms.

### 1. The "sleeper agent" — looks innocent, fetches the weapon later
The extension itself looks completely clean. But once it's running, it quietly
**reaches out to a stranger's computer on the internet, downloads instructions,
and follows them.** Because the harmful part is downloaded later, it's invisible
when you install it.
*Why it's clever:* the bad stuff is never actually "in" the extension you
inspected — it arrives afterward.

### 2. The "key thief" — steals your passwords and access keys
Programmers' computers are full of digital keys: passwords, access tokens, and
login files for things like cloud accounts and code repositories. A malicious
extension hunts for these and **copies them**. With them, an attacker can log in
as you somewhere else.

### 3. The "remote control" — runs commands on your computer
This is the most powerful one. The extension **runs system commands**, the same
way you would by typing into your computer. That can mean installing more
malware, making changes permanent, or handing remote control to an attacker.

### 4. The "smuggler" — sends your data out
After collecting your keys or files, the malware has to **send them somewhere**.
It quietly ships your information off to a server the attacker controls — often
disguised to look like ordinary internet chatter.

### 5. The "master of disguise" — hides what it's doing
Sophisticated attackers **scramble their code** so it's unreadable, then
unscramble it only when it runs. This is specifically meant to fool security
tools (including this one). It's the equivalent of a burglar wearing a mask.

### 6. The "pickpocket switch" — swaps what you copy
Some malware watches your **clipboard** (the place text goes when you copy it).
A common scam: when you copy a cryptocurrency payment address, it silently
**swaps in the attacker's address**, so your money goes to them.

---

## How extwatch helps

Every time an extension is installed or updated, extwatch:

1. **Notices the change** automatically.
2. **Compares the new version to the previous trusted version** — so it focuses
   on what *changed*, not on things the extension always did. (This is important:
   lots of legitimate extensions do "powerful" things, so the question is whether
   an update *newly* added something suspicious.)
3. **Flags anything that matches the bad behaviors above**, rating it:
   - 🔴 **High** — alarming (key theft, remote control). You get a pop-up alert.
   - 🟡 **Medium** — worth a look (internet calls, reading settings).
   - ⚪ **Low** — minor (clipboard access).
4. **Stays silent when nothing suspicious changed**, so it doesn't cry wolf.

---

## What extwatch is *not*

Being honest about the limits matters:

- **It's a smoke detector, not a fire department.** It *alerts* you; it does not
  block the install or remove the extension. You decide what to do next.
- **It can be fooled.** The "master of disguise" trick (#5) can slip past it. A
  silent result means "nothing obvious was found," not a guarantee of safety.
- **It can occasionally over-warn.** Sometimes a perfectly innocent update trips
  a flag. A warning is an invitation to look closer, not proof of wrongdoing.
- **It only reads the code and settings files, not everything.** It inspects an
  extension's JavaScript and its `package.json` settings, but some attacks can
  hide in other parts of an extension that this early version doesn't yet read.

Think of it as a helpful **early-warning signal** — one more set of eyes on the
software quietly running on your machine.

---

## The one-line version

> Extensions are little programs with big access to your computer. extwatch keeps
> an eye on them and tells you when an update starts behaving like a thief — so a
> human can take a closer look before any damage is done.
