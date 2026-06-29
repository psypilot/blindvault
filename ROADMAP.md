# BlindVault Roadmap & Contributor Guide

BlindVault is a **daily-use, open-source secrets vault for AI agents**: agents
*use* API keys, DB passwords, and tokens **without ever seeing the plaintext**.
This document is where we plan what's next — and where **you** can jump in.

New here? Read [`README.md`](README.md) for what it does, [`CONTRIBUTING.md`](CONTRIBUTING.md)
for setup and the code layout, and [`docs/DESIGN-resolver.md`](docs/DESIGN-resolver.md)
for the security model.

## ✅ Where we are today

Master-password vault (scrypt + Fernet envelope) · reference-based use + output
scrubbing · per-secret usage policies · `.env` import · desktop GUI · audit log ·
the **resolver** (credential-injecting proxy with an OS-enforced boundary on Linux
*and* Windows) · a **PostgreSQL connector** (SCRAM-SHA-256 / md5) · an honest threat
model with a self [red-team report](docs/SECURITY-redteam.md) · CI on Linux & Windows.

## 🔭 Planned work

Each item notes a rough **size** and the files you'd touch.

### Protocol connectors (`blindvault/broker/`)
- **SSH connector** — *large.* A `paramiko`-based jump proxy: the broker is an SSH
  server to the agent and an SSH client to the backend, re-authenticating with the
  real key/password. New optional `paramiko` dependency. Model it on `pgproxy.py`.
- **MySQL connector** — *medium.* MySQL handshake (`mysql_native_password` /
  `caching_sha2_password`), then byte-splice. Closely mirrors `pgproxy.py`.
- **Redis / generic TCP** — *small–medium.* Many backends just need
  AUTH-then-stream.

### The resolver (`blindvault/broker/`)
- **macOS service** — *medium.* `getpeereid` peer auth + a launchd plist (Linux &
  Windows are done; `peercred.py` already has the macOS branch).
- **Per-secret request approval / rate limits** — *medium.* Tighten the
  confused-deputy surface (see the threat model).
- **Encoded-leak detection in `bv run` scrubbing** — *small.* Best-effort base64/hex
  detection of a value (it's defense-in-depth, document the limits — see the red-team report).

### Onboarding & packaging
- **Importers** for HashiCorp Vault and Doppler — *medium* (`blindvault/agent/`).
- **A proper desktop installer** (Inno Setup / NSIS) with Start-Menu + uninstaller — *medium*.
- **PyPI publishing** — *small* (the workflow exists; needs the trusted-publisher setup).

### Desktop app (`blindvault/gui/`)
- **Policy editor in the GUI** — *medium.* View/edit a secret's allowed hosts/commands.
- **A "use with my agent" helper** — *small.* One-click copy of the AGENTS.md snippet / proxy URL.

## 🌱 Good first issues
- Add a `bv --help` example to the README for each subcommand.
- Add `bv export` (human-only, password-gated) to back up a vault.
- Improve `.env` parsing (multi-line values, `${VAR}` expansion) in `agent/envfile.py`.
- Add a `--json` output mode to `bv ls`.
- Write a connector for a backend you use (copy `pgproxy.py` as a template).

## 🤝 How to contribute
1. Open an issue (or comment on an existing one) to claim a piece — avoids duplicate work.
2. Fork, branch, build it **with a test** (`python -m unittest discover -s tests -v`).
3. Keep the security posture: never weaken the "agent can't read the value" boundary
   without a loud note in the threat model; don't roll your own crypto.
4. Open a PR describing the change and the reasoning.

Questions or a security report? See [`SECURITY.md`](SECURITY.md). Thanks for helping
keep secrets out of AI agents' hands. 🛡️
