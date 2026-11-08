"""D6: classifier at ingestion (spec §7.1).

Score every chunk at ingestion and quarantine flagged documents: they're
excluded from the index and logged. Presets with D6 on use their own collection,
built by ``ragsec ingest --d6`` with quarantine applied, so D6 never changes the
index other presets use. Poisoned documents go through the same ingestion path.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ragsec.app.classifier import WindowedClassifier


@dataclass
class ScanResult:
    quarantined: bool
    scores: list[float] = field(default_factory=list)
    flagged_chunks: list[int] = field(default_factory=list)


def scan_chunks(classifier: WindowedClassifier, chunk_texts: list[str]) -> ScanResult:
    scores = [classifier.score(t) for t in chunk_texts]
    flagged = [i for i, s in enumerate(scores) if classifier.flagged(s)]
    return ScanResult(quarantined=bool(flagged), scores=[round(s, 6) for s in scores], flagged_chunks=flagged)


def collection_name(prefix: str, threshold: float) -> str:
    """D6's collection is rebuilt when its threshold changes, so the name carries it."""
    return f"{prefix}-t{int(round(threshold * 100)):03d}"
