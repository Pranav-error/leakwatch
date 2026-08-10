"""Source tests with a fully mocked GitHub client — no network calls."""

from pathlib import Path

from leakwatch.core.store import Store
from leakwatch.sources import code_search
from leakwatch.sources.code_search import _raw_url
from leakwatch.sources.events import EventsSource, _interesting

LEAKY = (Path(__file__).parent / "fixtures" / "leaky.env").read_text()


class FakeResp:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = text
        self.headers = {}

    def json(self):
        return self._json


class FakeClient:
    """Records GET calls and returns queued responses; get_text returns fixtures."""

    def __init__(self, search_items, blob_text):
        self.token = "fake-token"
        self._search_items = search_items
        self._blob_text = blob_text

    def get(self, url, params=None, **kw):
        if "/search/code" in url:
            return FakeResp(json_data={"items": self._search_items})
        if "/events" in url:
            return FakeResp(json_data=self._events_payload())
        if "/commits/" in url:
            return FakeResp(
                json_data={
                    "files": [
                        {
                            "filename": ".env",
                            "raw_url": "https://raw.example/.env",
                            "blob_url": "https://github.com/o/r/blob/abc/.env",
                        }
                    ]
                }
            )
        return FakeResp(status_code=404)

    def get_text(self, url):
        return self._blob_text

    def close(self):
        pass

    @staticmethod
    def _events_payload():
        return [
            {
                "type": "PushEvent",
                "repo": {"name": "octo/leaky"},
                "payload": {"commits": [{"sha": "abc123"}]},
            },
            {"type": "WatchEvent", "repo": {"name": "octo/other"}},
        ]


def test_raw_url_builds_correctly():
    item = {
        "repository": {"full_name": "octo/leaky"},
        "path": "config/.env",
        "html_url": "https://github.com/octo/leaky/blob/deadbeef/config/.env",
    }
    assert _raw_url(item) == "https://raw.githubusercontent.com/octo/leaky/deadbeef/config/.env"


def test_interesting_filter():
    assert _interesting(".env")
    assert _interesting("app/config.py")
    assert not _interesting("yarn.lock")
    assert not _interesting("bundle.min.js")


def test_code_search_stores_redacted_findings(tmp_path):
    store = Store(db_url=f"sqlite:///{tmp_path/'t.db'}")
    items = [
        {
            "repository": {"full_name": "octo/leaky"},
            "path": ".env",
            "html_url": "https://github.com/octo/leaky/blob/abc/.env",
        }
    ]
    client = FakeClient(items, LEAKY)
    n = code_search.run_once(store, client=client, queries=("dummy",))
    assert n > 0
    rows = store.list_findings()
    assert rows
    # nothing raw leaked into storage
    disk = (tmp_path / "t.db").read_bytes()
    assert b"AKIAIOSFODNN7EXAMPLE" not in disk


def test_events_source_scans_push_commits(tmp_path):
    store = Store(db_url=f"sqlite:///{tmp_path/'e.db'}")
    src = EventsSource(client=FakeClient([], LEAKY))
    n = src.run_once(store)
    assert n > 0
    # second run over the same (already-seen) commit adds nothing new
    assert src.run_once(store) == 0
