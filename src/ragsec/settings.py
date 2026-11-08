"""Typed loaders for the app's own configuration files.

Only files under ``config/`` are read here. Nothing in this module touches
scoring data (rule 3).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from ragsec import paths

ROLES: tuple[str, ...] = ("employee", "hr", "it_admin")
TIERS: tuple[str, ...] = ("general", "hr", "it_admin")
TIER_ROLES: dict[str, list[str]] = {
    "general": ["employee", "hr", "it_admin"],
    "hr": ["hr"],
    "it_admin": ["it_admin"],
}
DEFENSE_SWITCHES: tuple[str, ...] = (
    "d1_role_filter",
    "d2_output_handling",
    "d3_tool_gating",
    "d4_spotlighting",
    "d5_classifier",
    "d6_ingest_scan",
    "d7_limits",
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CompanyCfg(_Strict):
    name: str
    domain: str
    assistant: str


class ServerCfg(_Strict):
    host: str = "127.0.0.1"
    port: int = 8000


class AttackerServerCfg(_Strict):
    host: str = "127.0.0.1"
    port: int = 8765
    example_exfil_base: str


class PathsCfg(_Strict):
    corpus: str
    chroma: str
    logs: str
    generation_cache: str
    hf_home: str
    ui: str


class OllamaCfg(_Strict):
    url: str
    keep_alive: str
    prompt_refused_error_patterns: list[str] = Field(default_factory=list)
    context_filled_error_patterns: list[str] = Field(default_factory=list)


class ModelCfg(_Strict):
    name: str
    think: bool | None = None


class GenerationCfg(_Strict):
    temperature: float
    num_ctx: int
    num_predict: int
    truncate: bool
    shift: bool


class LimitsCfg(_Strict):
    max_model_calls: int
    max_tool_calls: int


class EmbeddingsCfg(_Strict):
    repo: str
    device: str = "cpu"
    batch_size: int = 16
    max_tokens: int = 512
    query_instruction: str = ""


class ChunkingCfg(_Strict):
    target_tokens: int
    overlap_tokens: int
    max_tokens: int


class HnswCfg(_Strict):
    space: str = "cosine"
    ef_construction: int = 400
    ef_search: int = 400
    max_neighbors: int = 64


class RetrievalCfg(_Strict):
    top_k: int
    collection: str
    d6_collection_prefix: str
    hnsw: HnswCfg


class ClassifierModelCfg(_Strict):
    repo: str
    malicious_label_index: int = 1


class ClassifierCfg(_Strict):
    active: Literal["primary", "fallback"]
    primary: ClassifierModelCfg
    fallback: ClassifierModelCfg
    threshold: float
    max_tokens: int = 512
    window_tokens: int = 448
    stride_tokens: int = 384

    @property
    def active_model(self) -> ClassifierModelCfg:
        return self.primary if self.active == "primary" else self.fallback

    @property
    def pin_key(self) -> str:
        return f"classifier_{self.active}"


class PromptCfg(_Strict):
    routing_code: str


class D2Cfg(_Strict):
    allowed_domain: str
    bare_domain_tlds: list[str]
    csp: str
    leak_span_words: int = 8
    leak_block_message: str


class D3Cfg(_Strict):
    allowed_domain: str


class D5Cfg(_Strict):
    candidates: int = 12
    keep: int = 4
    refusal: str


class D7Cfg(_Strict):
    num_predict: int = 512
    max_message_chars: int = 2000
    timeout_seconds: float = 20.0
    rate_per_minute: int = 10
    max_in_flight: int = 1


class TelemetryCfg(_Strict):
    splunk_hec_url: str | None = None


class AppConfig(_Strict):
    company: CompanyCfg
    server: ServerCfg
    attacker_server: AttackerServerCfg
    paths: PathsCfg
    ollama: OllamaCfg
    models: dict[str, ModelCfg]
    generation: GenerationCfg
    limits: LimitsCfg
    embeddings: EmbeddingsCfg
    chunking: ChunkingCfg
    retrieval: RetrievalCfg
    classifier: ClassifierCfg
    prompt: PromptCfg
    d2: D2Cfg
    d3: D3Cfg
    d5: D5Cfg
    d7: D7Cfg
    refusal_phrases: list[str] = Field(default_factory=list)
    telemetry: TelemetryCfg = Field(default_factory=TelemetryCfg)

    # Set by the loader; not part of the YAML.
    root: Path = Field(default=Path("."), exclude=True)

    def path(self, rel: str) -> Path:
        p = Path(rel)
        return p if p.is_absolute() else (self.root / p)

    def model(self, slot: str) -> ModelCfg:
        if slot not in self.models:
            raise KeyError(f"unknown model slot {slot!r}; expected one of {sorted(self.models)}")
        return self.models[slot]


class Preset(_Strict):
    name: str
    d1_role_filter: bool = False
    d2_output_handling: bool = False
    d3_tool_gating: bool = False
    d4_spotlighting: bool = False
    d5_classifier: bool = False
    d6_ingest_scan: bool = False
    d7_limits: bool = False

    def enabled(self) -> list[str]:
        return [s for s in DEFENSE_SWITCHES if getattr(self, s)]

    @property
    def needs_classifier(self) -> bool:
        return self.d5_classifier or self.d6_ingest_scan


class DlpPattern(_Strict):
    name: str
    data_class: str
    regex: str
    ignore_case: bool = True


class DlpConfig(_Strict):
    redaction_template: str = "[REDACTED:{data_class}]"
    role_may_see: dict[str, list[str]]
    patterns: list[DlpPattern]


class OllamaModelPin(_Strict):
    name: str | None = None
    digest: str | None = None


class OllamaPins(_Strict):
    version: str | None = None
    models: dict[str, OllamaModelPin] = Field(default_factory=dict)


class HFPin(_Strict):
    repo: str
    revision: str | None = None
    files: dict[str, str] = Field(default_factory=dict)


class Pins(_Strict):
    ollama: OllamaPins = Field(default_factory=OllamaPins)
    huggingface: dict[str, HFPin] = Field(default_factory=dict)
    promptfoo: dict[str, Any] = Field(default_factory=dict)


def _read_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_app_config(path: Path | None = None, root: Path | None = None) -> AppConfig:
    root = root or paths.repo_root()
    path = path or paths.app_config_path(root)
    cfg = AppConfig.model_validate(_read_yaml(path))
    cfg.root = root
    return cfg


def preset_names(root: Path | None = None) -> list[str]:
    return sorted(p.stem for p in paths.presets_dir(root).glob("*.yaml"))


def load_preset(name: str, root: Path | None = None) -> Preset:
    path = paths.presets_dir(root) / f"{name}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"unknown preset {name!r} (no {path})")
    preset = Preset.model_validate(_read_yaml(path))
    if preset.name != name:
        raise ValueError(f"preset file {path} declares name {preset.name!r}")
    return preset


def load_dlp(root: Path | None = None) -> DlpConfig:
    return DlpConfig.model_validate(_read_yaml(paths.dlp_path(root)))


def load_pins(path: Path | None = None, root: Path | None = None) -> Pins:
    path = path or paths.pins_path(root)
    if not path.is_file():
        return Pins()
    data = _read_yaml(path) or {}
    return Pins.model_validate(data)


def save_pins(pins: Pins, path: Path | None = None, root: Path | None = None) -> Path:
    path = path or paths.pins_path(root)
    header = (
        "# Supply-chain pins (spec §8.9). Written by `ragsec doctor` / `ragsec doctor --download`.\n"
        "# The app refuses to start if a pinned digest, hash, or revision doesn't match.\n"
        "# Never re-pin silently: if a pin stops matching, record it in DECISIONS.md and tell the user.\n"
    )
    body = yaml.safe_dump(pins.model_dump(mode="json"), sort_keys=False, allow_unicode=True)
    path.write_text(header + body, encoding="utf-8", newline="\n")
    return path
