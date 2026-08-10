# LeakWatch

A **responsible-disclosure secret-leak monitor**. It watches public GitHub for
credentials that people accidentally commit (`.env` files, API keys, private keys),
records a **redacted** finding for you to review, and helps you notify the owner so
they can rotate the key.

It is a defensive / research tool. It is **not** a credential harvester.

## The line this tool does not cross

- **It never stores a raw secret.** Only an irreversible SHA-256 fingerprint (for
  dedup) and an edge-masked preview like `AKIA…MPLE` are persisted.
- **It never *uses* a secret.** There is no live key validation — verifying a key
  means using someone else's credential. The config flag exists only as a documented,
  unimplemented stub.
- **It never contacts anyone automatically.** The dashboard drafts a courteous
  disclosure notice; *you* review and send it by hand.
- **Do not use discovered keys.** If you find a live leak, notify the owner and/or the
  provider (many providers auto-revoke via GitHub's secret-scanning partner program).
  Accessing an account with a found key is unauthorized access — a crime in most
  jurisdictions — regardless of the owner's mistake.

## How it works

```
 sources ──▶ scan (regex rules) ──▶ redact ──▶ store (SQLite) ──▶ dashboard
   │                                   ▲
   ├─ code_search: GitHub Code Search  │  raw secret dies here — only a
   └─ events: public PushEvent stream  └─ fingerprint + masked preview move on
```

- **`detectors/`** — high-precision regex rules per provider (AWS, OpenAI, Stripe,
  Google, Slack, GitHub, PEM private keys, plus an entropy-gated generic rule).
- **`core/redact.py`** — the single choke point that reduces a raw match to
  non-reversible fields. Everything downstream consumes only that.
- **`sources/`** — `code_search.py` (indexed backfill) and `events.py` (fresh pushes).
- **`dashboard/`** — a localhost FastAPI review UI with per-finding disclosure drafts.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env         # then set GITHUB_TOKEN (read-only PAT)
```

A classic PAT with **no scopes** (or `public_repo`) is enough — Code Search just needs
an authenticated identity and it raises the events rate limit.

## Usage

Run the collectors (both sources, on their intervals):

```bash
python -m leakwatch.scheduler
```

Or run a single sweep from Python:

```python
from leakwatch.core.store import Store
from leakwatch.sources import code_search
code_search.run_once(Store())
```

Review findings in the dashboard (localhost only):

```bash
uvicorn leakwatch.dashboard.app:app --host 127.0.0.1 --port 8787
# open http://127.0.0.1:8787
```

## Tests

```bash
pytest -q
```

The suite includes `test_no_raw_leak.py`, which plants fake secrets, runs the full
pipeline, and asserts the raw value appears in **none** of: the DB rows, the raw
SQLite bytes on disk, the logs, or the returned records. If you touch the redaction or
storage path, keep that test green.

## Scope / roadmap

v1 logs to a private dashboard only. Deliberately left as opt-in follow-ups:

- Owner notification by opening a GitHub issue (currently manual copy-paste).
- Reporting to a provider's abuse/secret-scanning endpoint for auto-revocation.

## Legal & ethical note

Use this only against public data, for defense or good-faith research. Detecting a
leak does not entitle you to use it. When in doubt, notify and delete — never collect
or act on someone else's credential.
