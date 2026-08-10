"""Redaction — the single most important module in this project.

This is the ONLY place allowed to touch a raw secret value. Everything downstream
(storage, logs, dashboard, exports) must consume the redacted outputs here, never
the raw match.

Guarantees:
  * ``fingerprint`` is a stable, one-way SHA-256 hash used for dedup. It cannot be
    reversed into the secret.
  * ``mask`` returns a short, human-readable preview that reveals at most the first
    4 and last 4 characters, with the body replaced by a fixed marker. For short
    secrets it reveals nothing.
  * ``Redacted`` carries only non-reversible fields. There is deliberately no field
    that stores the raw secret.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

# How many leading/trailing chars a mask may reveal.
_EDGE = 4
# Minimum length before we reveal any edges at all. Below this, reveal nothing so
# that short/low-entropy secrets aren't effectively disclosed.
_MIN_REVEAL_LEN = 12


def fingerprint(raw: str) -> str:
    """Return a stable, non-reversible SHA-256 hex digest of the raw secret.

    Used purely for deduplication. Not stored alongside anything that could act as
    a rainbow-table hint.
    """
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def mask(raw: str) -> str:
    """Return a redacted preview that reveals at most the edge characters.

    Examples:
        "AKIAIOSFODNN7EXAMPLE" -> "AKIA…MPLE"
        "shortkey"             -> "…"  (too short to reveal edges)
    """
    n = len(raw)
    if n < _MIN_REVEAL_LEN:
        return "…"
    return f"{raw[:_EDGE]}…{raw[-_EDGE:]}"


@dataclass(frozen=True)
class Redacted:
    """A secret reduced to only non-reversible, safe-to-store fields."""

    fingerprint: str
    preview: str
    length: int

    def __repr__(self) -> str:  # never let a repr leak more than the preview
        return f"Redacted(preview={self.preview!r}, len={self.length})"


def redact(raw: str) -> Redacted:
    """Reduce a raw secret to its safe, non-reversible representation.

    Call this immediately after detection; drop the raw value right after.
    """
    return Redacted(fingerprint=fingerprint(raw), preview=mask(raw), length=len(raw))
