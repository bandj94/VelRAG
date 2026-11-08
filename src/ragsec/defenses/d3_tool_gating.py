"""D3: tool gating (spec §7.1).

``to`` must be exactly one plain address (``local@domain``: no display name, no
list, ASCII only) whose domain, lowercased with any trailing dot removed, is
exactly velmora.example. Anything else is blocked and logged. Every remaining
send needs user confirmation through /api/confirm.
"""

from __future__ import annotations

import re

_PLAIN_ADDRESS = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.?"
)


def check_recipient(to: object, allowed_domain: str) -> tuple[bool, str | None]:
    """Return (allowed, reason_if_blocked)."""
    if not isinstance(to, str):
        return False, "recipient is not a single string"
    value = to.strip()
    if not value:
        return False, "empty recipient"
    if not value.isascii():
        return False, "recipient contains non-ASCII characters"
    if not _PLAIN_ADDRESS.fullmatch(value):
        return False, "recipient is not exactly one plain address"
    domain = value.rsplit("@", 1)[1].lower().rstrip(".")
    if domain != allowed_domain.lower():
        return False, f"recipient domain {domain!r} is not {allowed_domain!r}"
    return True, None
