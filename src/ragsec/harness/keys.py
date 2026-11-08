"""Trial keys, seed namespaces, and simulated users (spec §10.2).

A trial's key is the sha256 of ``<namespace>|<case_id>|<trial index>``. The app
derives the generation seed (and, in eval mode, D4's markers) from it; the
harness uses it to pick the trial's simulated user from the role's pool. Within a
namespace a trial gets the same key, seed, markers, and user in every preset.
"""

from __future__ import annotations

import hashlib


def trial_key(namespace: str, case_id: str, trial_index: int) -> str:
    return hashlib.sha256(f"{namespace}|{case_id}|{trial_index}".encode()).hexdigest()


def pick_user(pool: list[str], key: str) -> str:
    if not pool:
        raise ValueError("empty user pool")
    idx = int(hashlib.sha256(f"user|{key}".encode()).hexdigest()[:8], 16) % len(pool)
    return pool[idx]


def benign_namespace(version: str) -> str:
    return version  # e.g. "benign-v1"
