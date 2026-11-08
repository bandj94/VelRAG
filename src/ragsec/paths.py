"""Repository paths the APP may use.

Harness-only paths (canaries, facts, directory, benign set, attacks) live in
``ragsec.harness.paths`` so that app code cannot reach them without importing the
harness, which rule 3 forbids (and tests enforce).
"""

from __future__ import annotations

import os
from pathlib import Path


def repo_root() -> Path:
    """Locate the repository root.

    ``RAGSEC_ROOT`` overrides discovery (used by tests and by the supply-chain
    checks that run against temporary copies). Otherwise walk up from the
    current directory, then from this file, looking for ``config/app.yaml``.
    """
    env = os.environ.get("RAGSEC_ROOT")
    if env:
        return Path(env).resolve()
    here = Path(__file__).resolve()
    candidates = [Path.cwd(), *Path.cwd().parents, *here.parents]
    for p in candidates:
        if (p / "config" / "app.yaml").is_file() and (p / "pyproject.toml").is_file():
            return p
    return here.parents[2]


def config_dir(root: Path | None = None) -> Path:
    return (root or repo_root()) / "config"


def app_config_path(root: Path | None = None) -> Path:
    env = os.environ.get("RAGSEC_APP_CONFIG")
    if env:
        return Path(env).resolve()
    return config_dir(root) / "app.yaml"


def presets_dir(root: Path | None = None) -> Path:
    return config_dir(root) / "defenses"


def dlp_path(root: Path | None = None) -> Path:
    return config_dir(root) / "dlp.yaml"


def pins_path(root: Path | None = None) -> Path:
    env = os.environ.get("RAGSEC_PINS")
    if env:
        return Path(env).resolve()
    return config_dir(root) / "pins.yaml"


def ui_dir(root: Path | None = None) -> Path:
    return (root or repo_root()) / "ui"
