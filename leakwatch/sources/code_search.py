"""Code Search source.

Sweeps GitHub's Code Search API for known secret-shaped patterns, fetches the
matching file's raw text, and feeds it to the pipeline. Requires an authenticated
token (Code Search is auth-only).

Note the API limitations: results are capped (~1000 per query), only cover indexed
default branches, and search qualifiers can't express full regexes — so we use
coarse text queries and let ``detectors`` do the precise matching.
"""

from __future__ import annotations

import logging

from ..config import settings
from ..core.store import Store
from ..pipeline import BlobRef, process_blob
from .github_client import GitHubClient

log = logging.getLogger("leakwatch.code_search")

# Coarse text queries that surface candidate files. The precise regex rules in
# detectors/ decide what's an actual finding, so these can be broad-but-cheap.
DEFAULT_QUERIES: tuple[str, ...] = (
    "AKIA language:dotenv",
    '"aws_secret_access_key"',
    "sk_live_ language:dotenv",
    '"-----BEGIN RSA PRIVATE KEY-----"',
    "AIza language:JavaScript",
    "xoxb- in:file",
)


def _raw_url(item: dict) -> str | None:
    """Turn a search item into a raw.githubusercontent.com URL."""
    repo = item.get("repository", {}).get("full_name")
    path = item.get("path")
    # html_url looks like .../blob/<sha>/<path>; grab the sha.
    html_url = item.get("html_url", "")
    if not (repo and path and "/blob/" in html_url):
        return None
    sha = html_url.split("/blob/", 1)[1].split("/", 1)[0]
    return f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"


def run_once(
    store: Store,
    client: GitHubClient | None = None,
    queries: tuple[str, ...] = DEFAULT_QUERIES,
    per_page: int = 30,
) -> int:
    """Run one sweep across all queries. Returns the number of findings stored."""
    owns_client = client is None
    client = client or GitHubClient()
    total = 0
    try:
        if not client.token:
            log.error("Code Search requires GITHUB_TOKEN; skipping sweep.")
            return 0
        for query in queries:
            total += _run_query(store, client, query, per_page)
    finally:
        if owns_client:
            client.close()
    return total


def _run_query(store: Store, client: GitHubClient, query: str, per_page: int) -> int:
    resp = client.get(
        "/search/code",
        params={"q": query, "per_page": per_page, "sort": "indexed", "order": "desc"},
    )
    if resp.status_code != 200:
        log.warning("code search failed q=%r status=%s", query, resp.status_code)
        return 0

    count = 0
    for item in resp.json().get("items", []):
        raw_url = _raw_url(item)
        if not raw_url:
            continue
        text = client.get_text(raw_url)
        if not text:
            continue
        repo = item["repository"]["full_name"]
        ref = BlobRef(
            repo=repo,
            file_path=item.get("path", ""),
            location_url=item.get("html_url", raw_url),
            source="code_search",
        )
        found = process_blob(text, ref, store, allowlist=settings.provider_allowlist)
        count += len(found)
    return count
