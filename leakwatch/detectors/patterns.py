"""Provider detection rules.

Small, high-precision first. Each rule pairs a provider name with a compiled regex
that matches the credential's canonical shape. These mirror the well-known formats
used by tools like gitleaks/detect-secrets; the goal is high signal, not exhaustive
coverage. Expand deliberately — a noisy rule floods the dashboard with false
positives.

A rule may define ``entropy_min`` to require a minimum Shannon entropy on the match,
which suppresses obvious placeholders like ``sk_live_xxxxxxxxxxxx``.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass


def shannon_entropy(value: str) -> float:
    """Bits-per-character Shannon entropy of a string."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@dataclass(frozen=True)
class Rule:
    provider: str
    regex: re.Pattern[str]
    # Optional entropy floor applied to the matched secret (or its capture group).
    entropy_min: float = 0.0
    # If set, entropy/redaction use this capture group instead of the whole match.
    group: int | None = None


# NOTE: these patterns match credential SHAPES, not any real key.
RULES: tuple[Rule, ...] = (
    Rule("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule(
        "aws_secret_access_key",
        # AWS secret shows up next to an aws_secret* assignment; require the context
        # word to cut down on random 40-char base64 false positives.
        re.compile(
            r"aws_secret_access_key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+]{40})",
            re.IGNORECASE,
        ),
        entropy_min=4.0,
        group=1,
    ),
    Rule("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), entropy_min=3.5),
    Rule("stripe_secret_key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\b"), entropy_min=3.5),
    Rule("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    Rule("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), entropy_min=3.0),
    Rule("github_pat", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    Rule("github_fine_grained_pat", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b")),
    Rule("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}")),
    Rule(
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    Rule(
        "generic_assignment",
        # key/token/secret/password = "<20+ high-entropy chars>"; last-resort catch.
        re.compile(
            r"(?:api[_-]?key|secret|token|passwd|password)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]",
            re.IGNORECASE,
        ),
        entropy_min=3.8,
        group=1,
    ),
)


def active_rules(allowlist: list[str] | None) -> tuple[Rule, ...]:
    """Filter rules by an optional provider allowlist (empty/None = all)."""
    if not allowlist:
        return RULES
    wanted = {a.lower() for a in allowlist}
    return tuple(r for r in RULES if r.provider.lower() in wanted)
