"""Run both detection sources on their own intervals.

Usage:
    python -m leakwatch.scheduler

Ctrl-C to stop. Requires GITHUB_TOKEN in the environment/.env.
"""

from __future__ import annotations

import logging

from apscheduler.schedulers.blocking import BlockingScheduler

from .config import settings
from .core.store import Store
from .sources import code_search
from .sources.events import EventsSource
from .sources.github_client import GitHubClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
log = logging.getLogger("leakwatch.scheduler")


def main() -> None:
    if not settings.github_token:
        raise SystemExit("GITHUB_TOKEN is required. Copy .env.example to .env and set it.")

    store = Store()
    client = GitHubClient()
    events = EventsSource(client=client)

    def code_search_job() -> None:
        try:
            n = code_search.run_once(store)
            log.info("code_search sweep stored %d finding(s)", n)
        except Exception:  # keep the scheduler alive on transient errors
            log.exception("code_search job failed")

    def events_job() -> None:
        try:
            n = events.run_once(store)
            log.info("events poll stored %d finding(s)", n)
        except Exception:
            log.exception("events job failed")

    scheduler = BlockingScheduler()
    scheduler.add_job(
        events_job, "interval", seconds=settings.events_interval, id="events", max_instances=1
    )
    scheduler.add_job(
        code_search_job,
        "interval",
        seconds=settings.code_search_interval,
        id="code_search",
        max_instances=1,
    )
    log.info(
        "starting scheduler: events every %ds, code_search every %ds",
        settings.events_interval,
        settings.code_search_interval,
    )
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("shutting down")
        client.close()


if __name__ == "__main__":
    main()
