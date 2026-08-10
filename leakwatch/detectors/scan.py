"""Run detection rules over a blob of text.

Yields lightweight ``Match`` records. A match still carries the raw secret — it is
the caller's responsibility (the pipeline) to redact immediately and never persist
it. Nothing here writes to disk or logs the raw value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from .patterns import Rule, active_rules, shannon_entropy


@dataclass(frozen=True)
class Match:
    provider: str
    raw: str  # transient — redact and drop; never persist or log this
    line: int

    def __repr__(self) -> str:  # keep the raw secret out of any accidental repr/log
        return f"Match(provider={self.provider!r}, line={self.line}, raw=<redacted>)"


def _extract(rule: Rule, m) -> str:
    return m.group(rule.group) if rule.group is not None else m.group(0)


def scan(text: str, allowlist: list[str] | None = None) -> Iterator[Match]:
    """Yield matches for every active rule that fires in ``text``.

    Deduplicates identical (provider, raw) pairs within a single blob so a repeated
    key doesn't emit twice from one file.
    """
    rules = active_rules(allowlist)
    seen: set[tuple[str, str]] = set()
    for rule in rules:
        for m in rule.regex.finditer(text):
            raw = _extract(rule, m)
            if not raw:
                continue
            if rule.entropy_min and shannon_entropy(raw) < rule.entropy_min:
                continue
            key = (rule.provider, raw)
            if key in seen:
                continue
            seen.add(key)
            line = text.count("\n", 0, m.start()) + 1
            yield Match(provider=rule.provider, raw=raw, line=line)
