"""SQLAlchemy model for a finding.

By design there is NO column that can hold a raw secret. The closest thing to the
secret is ``fingerprint`` (an irreversible SHA-256) and ``preview`` (edge-masked).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Finding(Base):
    __tablename__ = "findings"
    # One row per distinct secret per location. If the same fingerprint reappears at
    # the same URL we update last_seen instead of inserting.
    __table_args__ = (UniqueConstraint("fingerprint", "location_url", name="uq_fp_loc"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # --- redacted identity of the secret (never the secret itself) ---
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    preview: Mapped[str] = mapped_column(String(64))
    length: Mapped[int] = mapped_column(Integer)

    # --- where and what ---
    provider: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(String(32))  # "code_search" | "events"
    repo: Mapped[str] = mapped_column(String(255), index=True)
    file_path: Mapped[str] = mapped_column(String(1024))
    location_url: Mapped[str] = mapped_column(String(1024))
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # --- review workflow ---
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
