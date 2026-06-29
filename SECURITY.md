# Security Policy

BlindVault is a security tool, so we take its own security seriously — and we try
to be honest about its limits.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Instead, report privately via one of:

- GitHub's [private vulnerability reporting](https://github.com/psypilot/blindvault/security/advisories/new), or
- email **kallinos.loizos@gmail.com** with the subject line `BlindVault security`.

Please include a description, reproduction steps, and the impact you foresee.
We aim to acknowledge reports within a few days and will credit you (if you wish)
once a fix ships.

## Scope and current guarantees

BlindVault stops AI agents from reading or exposing secrets: the vault is encrypted
with a key derived from your **master password** (never stored on disk), the agent
works with references rather than plaintext, command output is scrubbed, and
`reveal` always requires the master password the agent does not have.

Known, documented limitations (these are **not** considered vulnerabilities — see
the threat model in the [README](README.md#️-threat-model--please-read)):

- **Usage policies are defense-in-depth, not a sandbox.** `bv policy` blocks the
  common/careless/prompt-injected exfiltration, but host-matching is a heuristic
  argv scan (a decoy allowed URL + an agent-controlled program can still exfiltrate)
  and `--allow-command` matches by program name only. Airtight egress control needs
  the separate-OS-user resolver (roadmap).
- **`BLINDVAULT_PASSWORD` must never be in an agent's environment.** It is for CI
  only; an agent that can read it effectively has the master password. Use
  `bv unlock` sessions for unattended runs.
- During an **unlocked session**, the data key is cached in `session.json`
  (short TTL; on Windows protection relies on the `%USERPROFILE%\.blindvault` ACL,
  not POSIX perms). Another same-user process could read it.
- A **file-write attacker** cannot swap two secrets (names are bound inside the
  ciphertext) but can still roll the vault file back to undo a deletion/rotation.
  Plain `passwd` does not revoke an already-exposed data key — use `passwd --rekey`.
- Values injected into **argv** are briefly visible to same-user processes; prefer
  `--env` (but note a host policy forbids `--env` delivery).
- Redaction matches the **literal** value, so a program that encodes a secret
  before printing it can defeat scrubbing.

If you find a way to leak a secret **outside** these documented limitations — for
example, a value surviving `bv run` in plain output, decrypting the vault without
the master password, `reveal` succeeding without it, or ciphertext that decrypts
under the wrong key — that is a vulnerability and we want to hear about it.

## Supported versions

BlindVault is pre-1.0; security fixes land on `main` and the latest release.
