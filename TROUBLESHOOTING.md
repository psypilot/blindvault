# Troubleshooting

Find your symptom below — each has the cause and the fix. Still stuck? Open an
[issue](https://github.com/psypilot/blindvault/issues) with your OS, `bv --version`,
and the exact message.

<br>

---

<br>

## `bv` command not found

**Why:** `pip` installed the `bv` script into a folder that isn't on your `PATH`.

**Fix:** run it as a module instead —

```bash
python -m blindvault --version
```

— or add Python's scripts directory to `PATH` (`python -m site --user-base`, then add
its `Scripts` (Windows) / `bin` (macOS/Linux) subfolder).

<br>

---

<br>

## Windows: "Windows protected your PC" (SmartScreen)

**Why:** `BlindVault.exe` is an unsigned binary (code-signing certificates cost money).

**Fix:** click **More info → Run anyway**. If you'd rather not trust the prebuilt exe,
build it yourself: `powershell -ExecutionPolicy Bypass -File build_exe.ps1`.

<br>

---

<br>

## The desktop app opens but a dialog (Add / Generate) seems to do nothing

**Why:** almost always a **stale or legacy vault** at `~/.blindvault` (e.g. from a much
older version), which can confuse the app's state.

**Fix:** close the app, then **rename or delete** `~/.blindvault`
(`%USERPROFILE%\.blindvault` on Windows) and relaunch — you'll start fresh.
⚠️ Deleting it removes your stored secrets. If you have real secrets in there, rename
it to `~/.blindvault.bak` instead and re-add them. (Dialogs are also centered over the
main window now, so check it isn't simply behind another window.)

<br>

---

<br>

## "warning: this vault's key-derivation cost is weak"

**Why:** the vault was created with a low scrypt cost (e.g. via `BLINDVAULT_ALLOW_WEAK_KDF`,
which is meant only for tests/CI).

**Fix:** strengthen it in place —

```bash
bv passwd --rekey
```

<br>

---

<br>

## "Wrong master password."

**Why:** the password is case-sensitive and is **not recoverable** by design — there's
no reset.

**Fix:** re-enter it carefully. If it's truly lost, the encrypted secrets cannot be
recovered; re-create the vault with `bv init --force` (this wipes it) and re-add them.

<br>

---

<br>

## "No vault found. Run `blindvault init` first."

**Fix:** create it once — `bv init`. If you keep your vault elsewhere, point at it with
`BLINDVAULT_HOME=/path/to/dir`.

<br>

---

<br>

## `run` asks for the password every single time

**Why:** there's no active unlock session, so each command prompts.

**Fix:** open a session once — `bv unlock` — and `bv run` won't prompt again until it
expires (or you `bv lock`). For unattended/CI use, set `BLINDVAULT_PASSWORD` (never
expose it to an untrusted agent — see [SECURITY.md](SECURITY.md)).

<br>

---

<br>

## "This vault predates the master-password format."

**Why:** it's a pre-0.2.0 vault (a plaintext `key.bin`).

**Fix:** upgrade it without losing secrets — `bv migrate` — or start clean with
`bv init --force`.

<br>

---

<br>

## `pip install` fails

**Why:** usually an outdated `pip` or no prebuilt `cryptography` wheel for your Python.

**Fix:** upgrade pip first, then retry —

```bash
python -m pip install --upgrade pip
pip install git+https://github.com/psypilot/blindvault.git
```

Use a supported Python (3.9–3.12). On minimal Linux you may need build tools
(`build-essential`, `libffi-dev`) for `cryptography`.

<br>

---

<br>

## PostgreSQL connector: the client can't connect / "connection refused"

**Why:** the backend Postgres isn't reachable at `--pg-backend`, or the secret's policy
doesn't allow that host.

**Fix:** confirm Postgres is running and reachable (`--pg-backend host:5432`), then
allow it on the secret: `bv policy PGPASS --allow-host <backend-host>`. No Postgres yet?
Start a throwaway one with the Docker command in [INSTALL.md](INSTALL.md#optional-a-postgres-to-test-the-connector).

<br>

---

<br>

## "The Windows named-pipe broker needs pywin32."

**Fix:** install the optional extra — `pip install "blindvault[windows]"`.

<br>

---

<br>

## Antivirus flags `BlindVault.exe`

**Why:** unsigned PyInstaller one-file binaries are sometimes false-positived.

**Fix:** prefer the `pip` install, or build the exe yourself from source
(`build_exe.ps1`) so you control the binary.
