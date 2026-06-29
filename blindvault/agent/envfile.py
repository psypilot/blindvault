"""Minimal .env parser for ``bv import``.

Handles ``KEY=VALUE``, ``export KEY=VALUE``, ``#`` comments, blank lines, and
optional single/double quotes around the value. Deliberately simple — it is for
importing existing secrets, not a full dotenv runtime.
"""

from __future__ import annotations

import re

# Keys must be usable as ``{{secret:NAME}}`` references.
VALID_KEY = re.compile(r"^[A-Za-z0-9_./\-]+$")


def parse(text: str) -> list[tuple[str, str]]:
    """Return ordered (key, value) pairs. Invalid keys are skipped."""
    pairs: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not VALID_KEY.match(key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        pairs.append((key, value))
    return pairs
