"""Persistence for redacted findings.

The store accepts a ``RedactedFinding`` (already stripped of the raw secret) and
upserts it, deduping on (fingerprint, location_url).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from ..config import settings
from .models import Base, Finding


@dataclass(frozen=True)
class RedactedFinding:
    """Everything needed to persist a finding — and nothing reversible."""

    fingerprint: str
    preview: str
    length: int
    provider: str
    source: str
    repo: str
    file_path: str
    location_url: str
    line: int | None = None


class Store:
    def __init__(self, db_url: str | None = None):
        self.engine = create_engine(db_url or settings.db_url, future=True)
        Base.metadata.create_all(self.engine)
        self._Session: sessionmaker[Session] = sessionmaker(
            bind=self.engine, expire_on_commit=False, future=True
        )

    def upsert(self, rf: RedactedFinding) -> Finding:
        """Insert a new finding or refresh ``last_seen`` on an existing one.

        Returns the (attached-then-detached) Finding row.
        """
        with self._Session() as session:
            existing = session.scalar(
                select(Finding).where(
                    Finding.fingerprint == rf.fingerprint,
                    Finding.location_url == rf.location_url,
                )
            )
            if existing is not None:
                existing.last_seen = datetime.now(timezone.utc)
                session.commit()
                session.refresh(existing)
                return existing

            row = Finding(
                fingerprint=rf.fingerprint,
                preview=rf.preview,
                length=rf.length,
                provider=rf.provider,
                source=rf.source,
                repo=rf.repo,
                file_path=rf.file_path,
                location_url=rf.location_url,
                line=rf.line,
                status="new",
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return row

    def list_findings(
        self,
        provider: str | None = None,
        status: str | None = None,
        repo: str | None = None,
        limit: int = 500,
    ) -> list[Finding]:
        stmt = select(Finding).order_by(Finding.last_seen.desc())
        if provider:
            stmt = stmt.where(Finding.provider == provider)
        if status:
            stmt = stmt.where(Finding.status == status)
        if repo:
            stmt = stmt.where(Finding.repo == repo)
        stmt = stmt.limit(limit)
        with self._Session() as session:
            return list(session.scalars(stmt))

    def get(self, finding_id: int) -> Finding | None:
        with self._Session() as session:
            return session.get(Finding, finding_id)

    def set_status(self, finding_id: int, status: str) -> None:
        with self._Session() as session:
            row = session.get(Finding, finding_id)
            if row is not None:
                row.status = status
                session.commit()

    def providers(self) -> list[str]:
        with self._Session() as session:
            return sorted(set(session.scalars(select(Finding.provider))))
