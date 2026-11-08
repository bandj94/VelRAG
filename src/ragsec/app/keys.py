"""What the app derives from an opaque trial key (spec §10.2).

The harness computes ``trial_key = sha256("<namespace>|<case_id>|<trial>")``. The
app never sees the namespace, case, or trial number; it only derives values from
the key, so the same trial gets the same seed and D4 markers in every preset.
"""

from __future__ import annotations

import hashlib
import re
import secrets

TRIAL_KEY_RE = re.compile(r"^[0-9a-f]{64}$")


def is_valid_trial_key(value: str) -> bool:
    return bool(TRIAL_KEY_RE.fullmatch(value))


def _derive(label: str, trial_key: str) -> str:
    return hashlib.sha256(f"{label}|{trial_key}".encode()).hexdigest()


def seed_from_trial_key(trial_key: str) -> int:
    """Generation seed: identical across presets for the same trial."""
    return int(_derive("seed", trial_key)[:8], 16) & 0x7FFFFFFF


def d4_marker_from_trial_key(trial_key: str) -> str:
    """D4 boundary marker for eval mode: unpredictable to a document's author,
    different for every trial, identical across presets for the same trial."""
    return "DATA-" + _derive("d4-marker", trial_key)[:16].upper()


def random_seed() -> int:
    return secrets.randbelow(2**31 - 1)


def random_d4_marker() -> str:
    """Serve and demo modes: a fresh cryptographic random marker per request."""
    return "DATA-" + secrets.token_hex(8).upper()
