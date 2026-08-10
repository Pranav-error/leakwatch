"""Generate a courteous, redacted disclosure notice for a finding.

The draft is text for a human to review and send by hand — LeakWatch never contacts
anyone automatically. The notice intentionally references the leak by its masked
preview and location, never the raw secret.
"""

from __future__ import annotations

from ..core.models import Finding

TEMPLATE = """\
Subject: Possible exposed secret in {repo}

Hello,

While monitoring public GitHub for accidentally-committed credentials, an automated
scan flagged what looks like a live **{provider}** secret in your repository:

  Repository: {repo}
  File:       {file_path}{line_part}
  Reference:  {location_url}
  Match:      {preview}  (redacted — the full value is not stored or included here)

If this is a real credential, please treat it as compromised:
  1. Revoke / rotate the key with the provider immediately.
  2. Remove it from the file AND from git history (a plain delete keeps it in past
     commits). Tools like `git filter-repo` or the BFG can scrub history.
  3. Consider moving secrets into environment variables or a secrets manager.

This notice is informational and sent in good faith. The secret value was never used
and is not retained.

— Sent manually after review, via a LeakWatch responsible-disclosure scan
"""


def draft_disclosure(finding: Finding) -> str:
    line_part = f" (line {finding.line})" if finding.line else ""
    return TEMPLATE.format(
        repo=finding.repo,
        provider=finding.provider,
        file_path=finding.file_path,
        line_part=line_part,
        location_url=finding.location_url,
        preview=finding.preview,
    )
