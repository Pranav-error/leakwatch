"""A thin, polite GitHub REST client.

Handles auth, the standard headers, and rate-limit backoff. Read-only: this client
only ever issues GET requests.
"""

from __future__ import annotations

import logging
import time

import httpx

from ..config import settings

log = logging.getLogger("leakwatch.github")

API = "https://api.github.com"


class GitHubClient:
    def __init__(self, token: str | None = None, timeout: float = 20.0):
        self.token = token or settings.github_token
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "leakwatch-responsible-disclosure",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        self._client = httpx.Client(headers=headers, timeout=timeout)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def get(self, url: str, params: dict | None = None, *, max_retries: int = 4) -> httpx.Response:
        """GET with rate-limit-aware backoff.

        On a primary/secondary rate limit (403/429 with a reset header) we sleep
        until the reset rather than hammering the API.
        """
        full = url if url.startswith("http") else f"{API}{url}"
        for attempt in range(max_retries):
            resp = self._client.get(full, params=params)
            if resp.status_code in (403, 429) and self._is_rate_limited(resp):
                wait = self._reset_wait(resp)
                log.warning("rate limited; sleeping %.0fs (attempt %d)", wait, attempt + 1)
                time.sleep(min(wait, 300))
                continue
            return resp
        return resp  # return the last response; caller inspects status

    @staticmethod
    def _is_rate_limited(resp: httpx.Response) -> bool:
        remaining = resp.headers.get("x-ratelimit-remaining")
        return remaining == "0" or "secondary rate limit" in resp.text.lower()

    @staticmethod
    def _reset_wait(resp: httpx.Response) -> float:
        retry_after = resp.headers.get("retry-after")
        if retry_after and retry_after.isdigit():
            return float(retry_after)
        reset = resp.headers.get("x-ratelimit-reset")
        if reset and reset.isdigit():
            return max(0.0, float(reset) - time.time()) + 1.0
        return 60.0

    def get_text(self, url: str) -> str | None:
        """Fetch a raw text blob (e.g. a raw.githubusercontent.com URL)."""
        resp = self.get(url)
        if resp.status_code == 200:
            return resp.text
        return None
