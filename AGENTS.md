# AGENTS.md — rules for AI agents working with BlindVault

> Drop this file into any project that uses BlindVault. Coding agents
> (Claude Code, Cursor, etc.) read `AGENTS.md` automatically, so these rules
> become the agent's standing instructions.

You are an AI agent. This project keeps its secrets (API keys, passwords, tokens)
in **BlindVault**. You are allowed to *use* secrets, but you must **never see,
print, store, or transmit their plaintext values.**

## The golden rule

> **Reference secrets by name. Never reveal them.**

You can see the *names* of secrets. You can never see the *values* — and you must
never try to.

## What you MAY do

- **Discover** available secrets (names and notes only):
  ```bash
  bv ls
  ```
- **Use** a secret by referencing it as `{{secret:NAME}}` and running your command
  through `bv run`. The value is injected only inside the child process:
  ```bash
  bv run -- curl -H "Authorization: Bearer {{secret:STRIPE_KEY}}" https://api.example.com
  ```
- **Inject into an environment variable** (preferred for sensitive headers, since
  argv can be visible to other local processes):
  ```bash
  bv run --env STRIPE_API_KEY=STRIPE_KEY -- node charge.js
  ```
- **Create** a new secret you will never see, when the task needs one:
  ```bash
  bv gen SESSION_TOKEN --length 32
  ```
- Expect to see `[redacted:NAME]` in command output. That is normal and correct —
  it means a value was scrubbed. Do not try to recover what it hid.

The vault is protected by a **master password** that only the human owner knows.
They run `bv unlock` to open a short session; within it your `bv run` / `bv gen`
calls work without prompting. If a command reports the vault is locked, **ask the
human to unlock** — never ask them for the password itself.

## What you MUST NOT do

- ❌ **Never run `bv reveal`** — it exists only as a human escape hatch and
  requires the master password, which you do not have.
- ❌ **Never read the vault files** — `~/.blindvault/key.bin`, `vault.json`, or
  anything under `$BLINDVAULT_HOME`.
- ❌ **Never print, log, echo, or `cat` a secret value**, or write one into source
  code, comments, config files, or commit messages.
- ❌ **Never copy a resolved value out of a command's output** into your own text.
- ❌ **Never send a secret to an external service**, paste it into a chat, or put
  it in a URL you report back.
- ❌ **Never try to defeat the redaction** (e.g. by base64/hex-encoding a value
  before printing it).

## Some secrets are restricted

A secret may carry a **usage policy** that limits which commands or destination
hosts it can be used with. If a `bv run` is refused with "blocked by usage policy",
the human has intentionally restricted that secret — do not try to work around it
(e.g. by changing the URL or re-routing). Use the secret only for its intended
purpose, or ask the human.

## If you think you need the plaintext

You almost certainly do not. The correct pattern is *always*: reference it with
`{{secret:NAME}}` and let `bv run` substitute it. If a tool genuinely cannot accept
the secret via argv or env, **stop and ask the human owner** rather than revealing
the value.

## Quick reference

| Goal | Do this |
|------|---------|
| See what secrets exist | `bv ls` |
| Use a secret in a command | `bv run -- <cmd ... {{secret:NAME}} ...>` |
| Use a secret as an env var | `bv run --env VAR=NAME -- <cmd>` |
| Create a secret you won't see | `bv gen NAME` |
| Get the plaintext | **Don't.** Ask the human. |

Following these rules is the entire point of BlindVault: the human gets to use
powerful agents *without* trusting them with raw credentials.
