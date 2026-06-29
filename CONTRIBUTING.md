# Contributing to BlindVault

Thanks for your interest! BlindVault aims to be a small, readable, trustworthy
security tool. Contributions of all sizes are welcome — bug reports, docs, tests,
and features.

## Getting started

```bash
git clone https://github.com/psypilot/blindvault.git
cd blindvault
pip install cryptography
python -m blindvault --help
```

Run the test suite (stdlib `unittest`, no extra dependencies):

```bash
python -m unittest discover -s tests -v
```

Build the desktop `.exe` (Windows):

```powershell
powershell -ExecutionPolicy Bypass -File build_exe.ps1
```

## Project layout

```
blindvault/
  cli.py            the command-line interface (dispatch for every subcommand)
  __main__.py       enables `python -m blindvault`
  core/             the vault itself
    config.py       where the vault lives (~/.blindvault, override w/ BLINDVAULT_HOME)
    crypto.py       scrypt KDF + Fernet envelope (AES-CBC + HMAC) — no home-rolled crypto
    store.py        atomic encrypted JSON store
    session.py      short-lived unlock session (cached data key + TTL)
    service.py      Vault: the one place secrets are encrypted/decrypted
  agent/            what an AI agent interacts with
    resolver.py     parse {{secret:NAME}} refs -> inject values -> scrub output
    policy.py       per-secret usage policies (allowed hosts/commands)
    envfile.py      .env import parser
  broker/           the resolver: "use a secret you never hold"
    server.py       credential-injecting proxy (HTTP + Unix-socket / TCP transports)
    peercred.py     Unix-socket UID peer auth (SO_PEERCRED / getpeereid)
    hardening.py    process self-protection (PR_SET_DUMPABLE, mlock, privilege drop)
    winpipe.py      Windows named-pipe transport + token-SID auth
    pgproxy.py      PostgreSQL connector (SCRAM-SHA-256 / md5)
  gui/
    window.py       the human-facing desktop app (tkinter)
tests/              unittest suite (run on Linux & Windows in CI)
docs/               design, deploy, and security/red-team docs
deploy/             systemd unit + Linux setup script
examples/           hands-on usage walkthroughs
```

## Guidelines

- **Keep it readable.** Favor clear code over clever code; this is a security tool
  people need to be able to audit.
- **Don't roll your own crypto.** All encryption goes through `cryptography`.
- **Runtime dependencies stay minimal.** The CLI needs only `cryptography`; the
  GUI uses only the standard library.
- **Add a test** for any behavior change. CI runs the suite on Python 3.9–3.12,
  Linux and Windows.
- **Never weaken the boundary.** Any change that could let an agent obtain a
  plaintext value through the normal CLI surface needs a very good reason and a
  loud note in the threat model.

## Pull requests

1. Fork and create a branch.
2. Make your change with a test.
3. Ensure `python -m unittest discover -s tests` passes.
4. Open a PR describing the change and the reasoning.

By contributing you agree your work is licensed under the project's MIT License.

## Maintainer notes

- **Releases**: pushing a `vX.Y.Z` tag triggers `.github/workflows/release.yml`,
  which builds `BlindVault.exe` in CI and attaches it to the GitHub release.
- **PyPI**: `.github/workflows/publish.yml` publishes via trusted publishing (no
  token). It is **manual** until the one-time PyPI setup is done: on PyPI add a
  pending publisher for project `blindvault`, owner `psypilot`, repo `blindvault`,
  workflow `publish.yml`, environment `pypi`. Then run it from the Actions tab, or
  change its trigger to `on: { release: { types: [published] } }` to auto-publish.
- **Social preview**: upload `assets/social-card.png` under
  repo **Settings → General → Social preview**.
