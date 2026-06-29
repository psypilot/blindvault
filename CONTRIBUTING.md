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
  config.py    where the vault lives (~/.blindvault, override w/ BLINDVAULT_HOME)
  crypto.py    Fernet (AES-CBC + HMAC) — no home-rolled crypto
  store.py     atomic encrypted JSON store
  resolver.py  the core: parse refs -> inject values -> scrub output
  service.py   Vault: the one place secrets are encrypted/decrypted
  cli.py       init / set / gen / ls / rm / run / reveal / gui
  gui.py       the human-facing desktop app (tkinter)
tests/         unittest suite
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
