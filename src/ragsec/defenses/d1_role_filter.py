"""D1: role filter (spec §7.1).

The retrieval query filters on ``allowed_roles``, so unauthorized chunks are
never retrieved. Chroma metadata can't hold lists, so each chunk carries one
boolean flag per role (``role_employee``, ``role_hr``, ``role_it_admin``).
"""

from __future__ import annotations

from typing import Any

from ragsec.settings import ROLES


def role_flags(allowed_roles: tuple[str, ...] | list[str]) -> dict[str, bool]:
    return {f"role_{r}": (r in allowed_roles) for r in ROLES}


def where_clause(role: str) -> dict[str, Any]:
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}")
    return {f"role_{role}": True}
