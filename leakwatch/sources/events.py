"""Public events source.

Samples the GitHub public-events firehose (`GET /events`), pulls the files changed
in recent PushEvents, fetches their raw text, and feeds them to the pipeline. This
gives freshness the Code Search index can't — leaks are caught minutes after a push.

We keep a small in-memory set of seen commit shas so re-polling doesn't rescan the
same push. It is read-only sampling, not aggressive crawling.
"""

from __future__ import annotations

import logging

from ..config import settings
from ..core.store import Store
from ..pipeline import BlobRef, process_blob
from .github_client import GitHubClient

log = logging.getLogger("leakwatch.events")

# Only inspect files that plausibly hold secrets; skip lockfiles, images, etc.
INTERESTING_SUFFIXES = (
    ".env",
    ".envrc",
    ".yml",
    ".yaml",
    ".json",
    ".js",
    ".ts",
    ".py",
    ".rb",
    ".go",
    ".sh",
    ".cfg",
    ".ini",
    ".conf",
    ".properties",
    ".pem",
    ".txt",
)


def _interesting(path: str) -> bool:
    lower = path.lower()
    if lower.endswith((".lock", ".min.js", ".map")):
        return False
    return lower.endswith(INTERESTING_SUFFIXES) or "/.env" in lower or lower.startswith(".env")


class EventsSource:
    def __init__(self, client: GitHubClient | None = None, max_seen: int = 5000):
        self.client = client or GitHubClient()
        self._seen: set[str] = set()
        self._max_seen = max_seen

    def _remember(self, sha: str) -> bool:
        """Return True if sha is new (and record it)."""
        if sha in self._seen:
            return False
        if len(self._seen) >= self._max_seen:
            self._seen.clear()  # cheap bound; freshness matters more than perfect memory
        self._seen.add(sha)
        return True

    def run_once(self, store: Store, per_page: int = 30) -> int:
        resp = self.client.get("/events", params={"per_page": per_page})
        if resp.status_code != 200:
            log.warning("events fetch failed status=%s", resp.status_code)
            return 0

        total = 0
        for event in resp.json():
            if event.get("type") != "PushEvent":
                continue
            repo = event.get("repo", {}).get("name", "")
            payload = event.get("payload", {})
            for commit in payload.get("commits", []):
                sha = commit.get("sha")
                if not sha or not self._remember(sha):
                    continue
                total += self._scan_commit(store, repo, sha)
        return total

    def _scan_commit(self, store: Store, repo: str, sha: str) -> int:
        resp = self.client.get(f"/repos/{repo}/commits/{sha}")
        if resp.status_code != 200:
            return 0
        count = 0
        for f in resp.json().get("files", []):
            path = f.get("filename", "")
            raw_url = f.get("raw_url")
            if not raw_url or not _interesting(path):
                continue
            text = self.client.get_text(raw_url)
            if not text:
                continue
            ref = BlobRef(
                repo=repo,
                file_path=path,
                location_url=f.get("blob_url", raw_url),
                source="events",
            )
            found = process_blob(text, ref, store, allowlist=settings.provider_allowlist)
            count += len(found)
        return count

    def close(self) -> None:
        self.client.close()
