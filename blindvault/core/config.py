"""Filesystem locations for the vault.

Everything lives under a single home directory so it is easy to back up, move,
or point at a throwaway directory in tests via ``BLINDVAULT_HOME``.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_HOME = "BLINDVAULT_HOME"
ENV_PASSWORD = "BLINDVAULT_PASSWORD"  # for CI/automation only — see SECURITY.md


def vault_home() -> Path:
    """Directory holding the encrypted store and any unlock session."""
    override = os.environ.get(ENV_HOME)
    return Path(override).expanduser() if override else Path.home() / ".blindvault"


def store_path() -> Path:
    return vault_home() / "vault.json"


def session_path() -> Path:
    return vault_home() / "session.json"


def legacy_key_path() -> Path:
    """The plaintext key file used by pre-0.2.0 (v1) vaults, kept only for
    one-time migration to the master-password format."""
    return vault_home() / "key.bin"
