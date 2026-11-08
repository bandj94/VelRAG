"""Process environment for every `ragsec` command (spec §4, rule 1, rule 8).

Telemetry is off everywhere it exists, and Hugging Face runs offline except
during the few steps the spec allows to download (`ragsec doctor --download`,
supply-chain check S2b, and Run 6's base-model download).

Caches are kept inside the project folder so nothing lands in the user's
profile directory (see DECISIONS.md).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

TELEMETRY_ENV: dict[str, str] = {
    "ANONYMIZED_TELEMETRY": "False",          # Chroma
    "HF_HUB_DISABLE_TELEMETRY": "1",          # Hugging Face Hub
    "PROMPTFOO_DISABLE_TELEMETRY": "1",       # promptfoo
    "PROMPTFOO_DISABLE_UPDATE": "1",          # promptfoo update check
    "DO_NOT_TRACK": "1",                      # generic opt-out honored by several tools
    "TOKENIZERS_PARALLELISM": "false",        # quiet fork warnings, no network effect
    "HF_HUB_DISABLE_SYMLINKS_WARNING": "1",   # Windows without developer mode copies files instead
}

OFFLINE_ENV: dict[str, str] = {
    "HF_HUB_OFFLINE": "1",
    "TRANSFORMERS_OFFLINE": "1",
}


def apply(root: Path, *, offline: bool = True, hf_home: Path | None = None) -> dict[str, str]:
    """Set the environment for this process (and any child it starts).

    Returns the variables that were set, for logging and tests.
    """
    applied: dict[str, str] = {}
    for key, value in TELEMETRY_ENV.items():
        os.environ[key] = value
        applied[key] = value
    if offline:
        for key, value in OFFLINE_ENV.items():
            os.environ[key] = value
            applied[key] = value
    else:
        for key in OFFLINE_ENV:
            os.environ.pop(key, None)
    hf = hf_home or (root / ".cache" / "huggingface")
    os.environ["HF_HOME"] = str(hf)
    applied["HF_HOME"] = str(hf)
    mpl = root / ".cache" / "matplotlib"
    os.environ.setdefault("MPLCONFIGDIR", str(mpl))
    applied["MPLCONFIGDIR"] = os.environ["MPLCONFIGDIR"]
    browsers = root / ".playwright"
    if browsers.is_dir() and "PLAYWRIGHT_BROWSERS_PATH" not in os.environ:
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers)
    if "PLAYWRIGHT_BROWSERS_PATH" in os.environ:
        applied["PLAYWRIGHT_BROWSERS_PATH"] = os.environ["PLAYWRIGHT_BROWSERS_PATH"]
    return applied


@contextmanager
def online(reason: str) -> Iterator[None]:
    """Temporarily allow Hugging Face downloads. ``reason`` documents why."""
    saved = {k: os.environ.get(k) for k in OFFLINE_ENV}
    for key in OFFLINE_ENV:
        os.environ.pop(key, None)
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for subprocesses: the current one plus telemetry-off settings."""
    env = dict(os.environ)
    env.update(TELEMETRY_ENV)
    if extra:
        env.update(extra)
    return env
