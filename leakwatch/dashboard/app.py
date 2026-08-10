"""Localhost review dashboard.

Lists redacted findings, filters by provider/status/repo, lets you change a
finding's review status, and generates a manual disclosure draft. Binds to
127.0.0.1 by default — this is a private review tool, not a public service.

Run:
    uvicorn leakwatch.dashboard.app:app --reload
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..core.store import Store
from .disclosure import draft_disclosure

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

STATUSES = ("new", "reviewing", "notified", "resolved", "ignored")

app = FastAPI(title="LeakWatch")
store = Store()


@app.get("/", response_class=HTMLResponse)
def index(request: Request, provider: str = "", status: str = "", repo: str = ""):
    findings = store.list_findings(
        provider=provider or None, status=status or None, repo=repo or None
    )
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "findings": findings,
            "providers": store.providers(),
            "statuses": STATUSES,
            "f_provider": provider,
            "f_status": status,
            "f_repo": repo,
        },
    )


@app.get("/finding/{finding_id}", response_class=HTMLResponse)
def detail(request: Request, finding_id: int):
    finding = store.get(finding_id)
    if finding is None:
        return HTMLResponse("Not found", status_code=404)
    return templates.TemplateResponse(
        request,
        "detail.html",
        {
            "finding": finding,
            "statuses": STATUSES,
            "disclosure": draft_disclosure(finding),
        },
    )


@app.post("/finding/{finding_id}/status")
def update_status(finding_id: int, status: str = Form(...)):
    if status in STATUSES:
        store.set_status(finding_id, status)
    return RedirectResponse(url=f"/finding/{finding_id}", status_code=303)
