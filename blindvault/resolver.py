"""The two boundaries that keep secrets away from the agent.

1. **Injection** — replace ``{{secret:NAME}}`` references in a command with the
   real value, so the agent authored the command without ever knowing the value.
2. **Redaction** — scrub any secret value out of the command's output, so a
   value that leaks into stdout/stderr never reaches the agent's eyes.
"""

from __future__ import annotations

import re
from typing import Callable, Iterable

# Names may contain letters, digits, and ._-/ (path-like namespaces allowed).
REFERENCE_RE = re.compile(r"\{\{\s*secret:([A-Za-z0-9_./\-]+)\s*\}\}")


def make_reference(name: str) -> str:
    """The placeholder an agent uses to refer to a secret: ``{{secret:NAME}}``."""
    return "{{secret:" + name + "}}"


def prompt_instruction(name: str) -> str:
    """A self-contained line to paste into an AI prompt, so even an agent seeing
    BlindVault for the first time knows how to use the secret without revealing it."""
    return (
        'Use the BlindVault secret "' + name + '": reference it in commands as '
        + make_reference(name) + " and run them via `bv run` - never reveal its value."
    )


def find_references(text: str) -> list[str]:
    """Ordered, de-duplicated secret names referenced in ``text``."""
    seen: list[str] = []
    for name in REFERENCE_RE.findall(text):
        if name not in seen:
            seen.append(name)
    return seen


def references_in_args(args: Iterable[str]) -> list[str]:
    seen: list[str] = []
    for arg in args:
        for name in find_references(arg):
            if name not in seen:
                seen.append(name)
    return seen


def inject(args: Iterable[str], resolve: Callable[[str], str]) -> list[str]:
    """Return a copy of ``args`` with every reference replaced by its value."""
    return [REFERENCE_RE.sub(lambda m: resolve(m.group(1)), arg) for arg in args]


def make_scrubber(resolved: dict[str, str]) -> Callable[[str], str]:
    """Build a function that masks every known secret value in a string.

    Longer values are replaced first so a secret that contains another secret
    as a substring is not partially unmasked.

    SECURITY NOTE — defense-in-depth, NOT a boundary. This is a literal
    substring replace, so it stops *accidental* echoes of a value but is
    trivially defeated by any reversible transform (base64/hex/reversal) a
    program applies before printing. A determined agent that controls the
    command can bypass it. For "the agent must never obtain the value", use the
    resolver/proxy (`bv serve`), where the value never enters the agent at all.
    See docs/SECURITY-redteam.md.
    """
    items = sorted(
        ((value, name) for name, value in resolved.items() if value),
        key=lambda pair: len(pair[0]),
        reverse=True,
    )

    def scrub(text: str) -> str:
        if not text:
            return text
        for value, name in items:
            if value in text:
                text = text.replace(value, f"[redacted:{name}]")
        return text

    return scrub
