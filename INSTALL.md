# Installing BlindVault

Two ways to install. Pick one — **the core app needs nothing else** (no database, no
SSH). If anything goes wrong, jump to **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)**.

<br>

## Requirements

| You're using… | You need |
|---|---|
| The **desktop app** (`BlindVault.exe`) | Nothing — it's fully standalone (Windows). |
| The **command line** (`bv`) | **Python 3.9 or newer** (`python --version`). |

<br>

---

<br>

## Path A — Desktop app (Windows, no Python)

**Recommended — the installer:**

1. Open the [**latest release**](https://github.com/psypilot/blindvault/releases/latest).
2. Download **`BlindVault-Setup.exe`** and run it. It installs BlindVault per-user
   (no admin): a Start Menu shortcut, an uninstaller, and the **`bv` command on your
   PATH** so you can use the CLI in any terminal.
3. Launch **BlindVault** from the Start Menu. The first time, it asks you to
   **create a master password** — choose a strong one; it encrypts your vault and
   **cannot be recovered**.

**Prefer no install?** Download the standalone **`BlindVault.exe`** instead and just
double-click it. Nothing is installed (and `bv` is not added to PATH).

> **SmartScreen warning?** The binaries are unsigned, so Windows may say *"Windows
> protected your PC."* Click **More info → Run anyway**. (Or build everything yourself
> — `powershell -ExecutionPolicy Bypass -File installer\build-windows.ps1`.)

Your encrypted vault lives in `%USERPROFILE%\.blindvault`.

<br>

---

<br>

## Path B — Command line (any OS)

```bash
pip install git+https://github.com/psypilot/blindvault.git
```

Verify:

```bash
bv --version          # -> blindvault 0.9.0
```

> `bv` and `blindvault` are the same command. If your shell can't find `bv`, your
> Python scripts directory isn't on `PATH` — see
> [TROUBLESHOOTING.md](TROUBLESHOOTING.md#bv-command-not-found). You can always run it
> as `python -m blindvault …`.

First run:

```bash
bv init               # choose a master password (once)
bv set MY_KEY         # type the secret value (hidden)
bv ls                 # confirm it's there (names only)
```

<br>

---

<br>

## Optional add-ons (only if you need them)

### The Windows named-pipe broker

Needed only for `bv serve --pipe` (the OS-isolated resolver on Windows):

```bash
pip install "blindvault[windows]"     # adds pywin32
```

<br>

### Optional: a Postgres to test the connector

You only need this for the **PostgreSQL connector** (`bv serve --pg-listen`), and only
if you don't already run Postgres. BlindVault **does not** install a database — but you
can spin a throwaway one up in one line with Docker:

```bash
docker run --name blindvault-pg \
  -e POSTGRES_USER=blindvault \
  -e POSTGRES_PASSWORD=blindvault_dev_pw \
  -e POSTGRES_DB=blindvault \
  -p 5432:5432 -d postgres:16
```

Then point the connector at it — see the
[database connector example](examples/README.md#4-postgresql-with-no-password-in-the-app).
Remove it later with `docker rm -f blindvault-pg`.

<br>

---

<br>

## Updating

```bash
pip install --upgrade --force-reinstall git+https://github.com/psypilot/blindvault.git
```

For the desktop app, download the newer `BlindVault.exe` from
[Releases](https://github.com/psypilot/blindvault/releases/latest). Your vault is
unaffected by updates.

<br>

## Uninstalling

```bash
pip uninstall blindvault
```

Your vault lives in `~/.blindvault` (Windows: `%USERPROFILE%\.blindvault`). Delete that
folder to remove your secrets too. **This is irreversible.**

<br>

---

<br>

Stuck anywhere? **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** has a fix for each common
issue, one by one.
