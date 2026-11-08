"""Server modes (spec §6.6).

Modes swap only the seed source, the clock behind D7's timeout, the generation
cache, and the eval endpoints. The pipeline code path is identical in every mode
(tested): the pipeline asks the policy for a seed and a marker and never branches
on the mode itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ragsec.app import keys


class Mode(StrEnum):
    EVAL = "eval"
    DEMO = "demo"
    SERVE = "serve"


@dataclass(frozen=True)
class ModePolicy:
    mode: Mode
    cache_enabled: bool
    eval_endpoints: bool
    trial_key_required: bool
    trial_key_allowed: bool
    virtual_timeout: bool  # True: D7's timeout uses the virtual clock; False: wall clock closes the stream

    def seed(self, trial_key: str | None) -> int:
        if self.trial_key_required:
            assert trial_key is not None
            return keys.seed_from_trial_key(trial_key)
        return keys.random_seed()

    def d4_marker(self, trial_key: str | None) -> str:
        if self.trial_key_required:
            assert trial_key is not None
            return keys.d4_marker_from_trial_key(trial_key)
        return keys.random_d4_marker()


def policy_for(mode: Mode | str) -> ModePolicy:
    mode = Mode(mode)
    if mode is Mode.EVAL:
        return ModePolicy(mode, cache_enabled=True, eval_endpoints=True, trial_key_required=True,
                          trial_key_allowed=True, virtual_timeout=True)
    if mode is Mode.DEMO:
        return ModePolicy(mode, cache_enabled=False, eval_endpoints=True, trial_key_required=False,
                          trial_key_allowed=False, virtual_timeout=False)
    return ModePolicy(mode, cache_enabled=False, eval_endpoints=False, trial_key_required=False,
                      trial_key_allowed=False, virtual_timeout=False)
