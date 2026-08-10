"""The guardrail regression test.

Plant fake secrets, run them through the full pipeline, then prove the raw secret
value appears in NONE of: the DB rows, the raw SQLite file bytes, captured logs, or
the returned records.
"""

import logging
from pathlib import Path

from leakwatch.core.store import Store
from leakwatch.pipeline import BlobRef, process_blob

# Fake, non-live secrets planted for the test.
RAW_SECRETS = [
    "AKIAIOSFODNN7EXAMPLE",
    "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
    "sk-proj-abc123DEF456ghi789JKL012mno345PQR",
]

BLOB = "\n".join(f"KEY_{i}={s}" for i, s in enumerate(RAW_SECRETS))


def _make_store(tmp_path: Path) -> tuple[Store, Path]:
    db_file = tmp_path / "test.db"
    return Store(db_url=f"sqlite:///{db_file}"), db_file


def test_raw_secret_never_reaches_storage_logs_or_return(tmp_path, caplog):
    store, db_file = _make_store(tmp_path)
    ref = BlobRef(
        repo="octo/leaky",
        file_path=".env",
        location_url="https://github.com/octo/leaky/blob/main/.env",
        source="code_search",
    )

    with caplog.at_level(logging.DEBUG):
        redacted = process_blob(BLOB, ref, store)

    assert len(redacted) == len(RAW_SECRETS)  # everything was detected

    # 1) Not in the returned redacted records.
    dumped = repr(redacted)
    for secret in RAW_SECRETS:
        assert secret not in dumped

    # 2) Not in any DB row's string representation.
    rows = store.list_findings()
    assert len(rows) == len(RAW_SECRETS)
    for row in rows:
        row_text = " ".join(
            str(v) for v in (row.fingerprint, row.preview, row.provider, row.repo, row.file_path)
        )
        for secret in RAW_SECRETS:
            assert secret not in row_text

    # 3) Not in the raw bytes of the SQLite file on disk.
    disk_bytes = db_file.read_bytes()
    for secret in RAW_SECRETS:
        assert secret.encode() not in disk_bytes

    # 4) Not in captured log output.
    for secret in RAW_SECRETS:
        assert secret not in caplog.text


def test_dedup_on_reprocess(tmp_path):
    store, _ = _make_store(tmp_path)
    ref = BlobRef(
        repo="octo/leaky",
        file_path=".env",
        location_url="https://github.com/octo/leaky/blob/main/.env",
        source="code_search",
    )
    process_blob(BLOB, ref, store)
    process_blob(BLOB, ref, store)  # same blob, same location
    assert len(store.list_findings()) == len(RAW_SECRETS)  # no duplicates
