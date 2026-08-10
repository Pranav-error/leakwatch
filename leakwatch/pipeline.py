"""The pipeline: scan a blob, redact each match, and persist a redacted finding.

This is the choke point where the raw secret dies. A ``Match`` carrying a raw value
enters; only a ``RedactedFinding`` leaves toward storage. The raw string is never
written to the DB and never logged.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .core.redact import redact
from .core.store import RedactedFinding, Store
from .detectors.scan import scan

log = logging.getLogger("leakwatch.pipeline")


@dataclass(frozen=True)
class BlobRef:
    """Where a blob of text came from — all public, non-secret metadata."""

    repo: str
    file_path: str
    location_url: str
    source: str  # "code_search" | "events"


def process_blob(
    text: str,
    ref: BlobRef,
    store: Store,
    allowlist: list[str] | None = None,
) -> list[RedactedFinding]:
    """Scan ``text``, redact every match, persist, and return the redacted findings.

    The raw match value from ``scan`` is consumed by ``redact`` and then goes out of
    scope — it is never returned, stored, or logged.
    """
    results: list[RedactedFinding] = []
    for match in scan(text, allowlist):
        r = redact(match.raw)  # raw enters here and is reduced to non-reversible fields
        rf = RedactedFinding(
            fingerprint=r.fingerprint,
            preview=r.preview,
            length=r.length,
            provider=match.provider,
            source=ref.source,
            repo=ref.repo,
            file_path=ref.file_path,
            location_url=ref.location_url,
            line=match.line,
        )
        store.upsert(rf)
        # Log metadata only — never the raw secret.
        log.info(
            "finding provider=%s repo=%s preview=%s url=%s",
            rf.provider,
            rf.repo,
            rf.preview,
            rf.location_url,
        )
        results.append(rf)
    return results
