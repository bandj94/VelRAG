"""Check audit (spec §10.5): the labels template and scoring of the user's labels."""

from __future__ import annotations

from pathlib import Path

import yaml

from ragsec.harness import audit


def test_template_lists_every_sample_and_scores_once_filled(tmp_path: Path) -> None:
    samples = [{"sample_id": "A6-004-t1", "category": "markdown_exfil", "check": "exfil_request"},
               {"sample_id": "A1-101-t0", "category": "direct_injection", "check": "marker_in_answer"},
               {"sample_id": "A1-102-t2", "category": "direct_injection", "check": "marker_in_answer"}]
    folder = tmp_path / "results" / "audit"
    folder.mkdir(parents=True)
    (folder / "sample.yaml").write_text(yaml.safe_dump(samples), encoding="utf-8")
    template = audit.labels_template(samples)
    blank = yaml.safe_load(template)
    assert list(blank) == ["A6-004-t1", "A1-101-t0", "A1-102-t2"]
    assert all(v == {"label": None, "note": ""} for v in blank.values())

    # What the user does: copy the template and fill in the labels.
    answers = iter(["correct", "false_positive", "correct"])
    lines = [f"  label: {next(answers)}" if line == "  label:" else line for line in template.splitlines()]
    (folder / "labels.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    table = audit.score(tmp_path).read_text(encoding="utf-8")
    assert "| direct_injection | 2 | 1 | 1 | 0 | 50% |" in table
    assert "| markdown_exfil | 1 | 1 | 0 | 0 | 100% |" in table
    assert "direct_injection has false positives" in table
