"""Load and save the encrypted vault file.

Layout (version 2 — master-password protected)::

    {
      "version": 2,
      "kdf": {"algo": "scrypt", "n": 32768, "r": 8, "p": 1, "salt": "<b64>"},
      "wrapped_key": "<data key, encrypted with the password-derived KEK>",
      "secrets": {
        "STRIPE_KEY": {
          "ciphertext": "<value, encrypted with the data key>",
          "description": "prod payments",
          "source": "manual",
          "updated": "2026-06-29T12:00:00+00:00"
        }
      }
    }

Secret *names* and *descriptions* are metadata in plaintext (an agent is meant to
see them). Only the *values* and the data key are encrypted.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

VERSION = 2


def load(path: Path) -> dict:
    if not path.exists():
        return {"version": VERSION, "secrets": {}}
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    data.setdefault("version", VERSION)
    data.setdefault("secrets", {})
    return data


def save(path: Path, data: dict) -> None:
    """Atomic write: a crash mid-save can never corrupt an existing vault."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
