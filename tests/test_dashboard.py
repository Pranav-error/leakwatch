"""Dashboard + disclosure tests. Uses an isolated DB via the LEAKWATCH_DB env var."""

import importlib

import pytest
from fastapi.testclient import TestClient

from leakwatch.core.redact import redact
from leakwatch.core.store import RedactedFinding


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Point config at a temp DB, then (re)import the app so its module-level Store
    # binds to the isolated database.
    monkeypatch.setenv("LEAKWATCH_DB", str(tmp_path / "dash.db"))
    import leakwatch.config as config

    importlib.reload(config)
    import leakwatch.core.store as store_mod

    importlib.reload(store_mod)
    import leakwatch.dashboard.app as app_mod

    importlib.reload(app_mod)

    # Seed one finding built through the real redaction path.
    r = redact("AKIAIOSFODNN7EXAMPLE")
    app_mod.store.upsert(
        RedactedFinding(
            fingerprint=r.fingerprint,
            preview=r.preview,
            length=r.length,
            provider="aws_access_key_id",
            source="code_search",
            repo="octo/leaky",
            file_path=".env",
            location_url="https://github.com/octo/leaky/blob/main/.env",
            line=3,
        )
    )
    return TestClient(app_mod.app)


def test_index_lists_finding_masked(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "aws_access_key_id" in resp.text
    assert "AKIA…MPLE" in resp.text
    assert "AKIAIOSFODNN7EXAMPLE" not in resp.text  # raw never rendered


def test_detail_and_disclosure_are_redacted(client):
    resp = client.get("/finding/1")
    assert resp.status_code == 200
    assert "Disclosure draft" in resp.text
    assert "octo/leaky" in resp.text
    assert "AKIAIOSFODNN7EXAMPLE" not in resp.text


def test_status_update(client):
    resp = client.post("/finding/1/status", data={"status": "reviewing"}, follow_redirects=False)
    assert resp.status_code == 303
    assert client.get("/finding/1").text.count("reviewing") >= 1


def test_disclosure_helper_never_contains_raw():
    from leakwatch.core.models import Finding
    from leakwatch.dashboard.disclosure import draft_disclosure

    f = Finding(
        provider="aws_access_key_id",
        preview="AKIA…MPLE",
        length=20,
        repo="octo/leaky",
        file_path=".env",
        location_url="https://github.com/octo/leaky/blob/main/.env",
        line=3,
        source="code_search",
        fingerprint="x" * 64,
    )
    text = draft_disclosure(f)
    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "AKIA…MPLE" in text
