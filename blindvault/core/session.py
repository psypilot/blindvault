"""A short-lived unlock session.

So a human does not have to retype the master password for every ``bv run``, an
unlock caches the *data key* (not the password) in a file with a TTL and
owner-only permissions. The agent can use this session to *run* commands, but it
is never used by ``reveal`` — printing plaintext always requires the password
itself.

Honest limit: within a single OS user, any file the unlock writes is also
readable by that user's other processes (including an agent). The session keeps
the exposure window short; the real boundary (a resolver under a separate OS
user) is on the roadmap.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

from . import config

DEFAULT_TTL_MINUTES = 15


def save(data_key: bytes, ttl_minutes: int = DEFAULT_TTL_MINUTES) -> datetime:
    expires = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
    payload = {"data_key": data_key.decode("ascii"), "expires": expires.isoformat()}
    path = config.session_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Truncate-or-create with owner-only permissions.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return expires


def load() -> bytes | None:
    """Return the cached data key, or None if there is no valid session."""
    path = config.session_path()
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        expires = datetime.fromisoformat(payload["expires"])
    except (ValueError, KeyError, OSError):
        clear()
        return None
    if datetime.now(timezone.utc) >= expires:
        clear()
        return None
    return payload["data_key"].encode("ascii")


def clear() -> None:
    path = config.session_path()
    try:
        path.unlink()
    except FileNotFoundError:
        pass
