"""The ``ragsec`` command line (spec §10.1). Run with ``uv run ragsec …``.

Every command runs with telemetry off and Hugging Face offline (§4); only
``ragsec doctor --download``, supply-chain check S2b, and Run 6's base-model
download go online, and only for that step.
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from ragsec import envsetup
from ragsec.paths import repo_root

app = typer.Typer(help="RAG Attack & Defense Lab", no_args_is_help=True, add_completion=False)
corpus_app = typer.Typer(help="Document templates", no_args_is_help=True)
attacks_app = typer.Typer(help="Attack sets", no_args_is_help=True)
benign_app = typer.Typer(help="Benign set", no_args_is_help=True)
audit_app = typer.Typer(help="Check audit (§10.5)", no_args_is_help=True)
demo_app = typer.Typer(help="Demo (§15.4)", no_args_is_help=True)
poison_app = typer.Typer(help="Training-data poisoning extension (§8.10)", no_args_is_help=True)
app.add_typer(corpus_app, name="corpus")
app.add_typer(attacks_app, name="attacks")
app.add_typer(benign_app, name="benign")
app.add_typer(audit_app, name="audit")
app.add_typer(demo_app, name="demo")
app.add_typer(poison_app, name="poison")


@app.callback()
def _setup() -> None:
    envsetup.apply(repo_root(), offline=True)


def _fail(msg: str, code: int = 1) -> NoReturn:
    typer.secho(msg, fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


# ------------------------------------------------------------------------- doctor
@app.command()
def doctor(download: Annotated[bool, typer.Option(help="Download models (loads .env; Run 0 only)")] = False,
           probes: Annotated[bool, typer.Option(help="Run the Ollama behaviour probes")] = True) -> None:
    """Environment checks (Run 0)."""
    from ragsec.harness import doctor as doc

    results = doc.run(download=download, probes=probes)
    raise typer.Exit(1 if any(c.status == "fail" for c in results) else 0)


# ------------------------------------------------------------------------- corpus
@corpus_app.command("render")
def corpus_render() -> None:
    """Render data/corpus_src templates into data/corpus."""
    from ragsec.harness import corpus

    issues = corpus.lint_all()
    for i in issues:
        typer.echo(f"lint: {i.doc}:{i.line}: {i.reason}: {i.text}")
    rendered = corpus.render_all()
    typer.echo(f"rendered {len(rendered)} documents into data/corpus/")
    if issues:
        _fail(f"{len(issues)} lint issue(s): templates may not hardcode amounts, durations, or counts")


@corpus_app.command("lint")
def corpus_lint() -> None:
    from ragsec.harness import corpus

    issues = corpus.lint_all()
    for i in issues:
        typer.echo(f"{i.doc}:{i.line}: {i.reason}: {i.text}")
    typer.echo("lint clean" if not issues else f"{len(issues)} issue(s)")
    raise typer.Exit(1 if issues else 0)


# ------------------------------------------------------------------------- ingest
@app.command()
def ingest(d6: Annotated[bool, typer.Option(help="Also build D6's collection (needs the classifier)")] = False) -> None:
    """Build the Chroma index (and, from Run 3, the D6 collection)."""
    from ragsec.app import integrity
    from ragsec.app.corpus import load_corpus
    from ragsec.app.embeddings import BgeEmbedder
    from ragsec.app.index import VectorIndex
    from ragsec.app.ingest import Ingestor
    from ragsec.app.server import load_classifier
    from ragsec.defenses import d6_ingest_scan
    from ragsec.settings import load_app_config, load_pins

    cfg = load_app_config()
    report = integrity.startup_check(cfg, load_pins(), slot="A", need_classifier=d6, check_ollama=False)
    if not report.ok:
        _fail("integrity check failed:\n  " + "\n  ".join(report.errors))
    e = cfg.embeddings
    embedder = BgeEmbedder(Path(str(report.details["embeddings_dir"])), device=e.device, batch_size=e.batch_size,
                           max_tokens=e.max_tokens, query_instruction=e.query_instruction)
    classifier = load_classifier(cfg, Path(str(report.details["classifier_dir"]))) if d6 else None
    index = VectorIndex(cfg.path(cfg.paths.chroma), cfg.retrieval.hnsw)
    docs = load_corpus(cfg.path(cfg.paths.corpus))
    ingestor = Ingestor(embedder=embedder, index=index, chunking=cfg.chunking, classifier=classifier)
    res = ingestor.build(cfg.retrieval.collection, docs, d6=False)
    typer.echo(f"{res['collection']}: {res['documents']} documents, {res['chunks']} chunks")
    logs = cfg.path(cfg.paths.logs)
    logs.mkdir(parents=True, exist_ok=True)
    if d6:
        name = d6_ingest_scan.collection_name(cfg.retrieval.d6_collection_prefix, cfg.classifier.threshold)
        res6 = ingestor.build(name, docs, d6=True, threshold=cfg.classifier.threshold)
        (logs / f"ingest_{name}.json").write_text(json.dumps(res6, indent=2), encoding="utf-8", newline="\n")
        typer.echo(f"{name}: quarantined {sorted(res6['quarantined'])}; scores in logs/ingest_{name}.json")


# -------------------------------------------------------------------------- serve
@app.command()
def serve(preset: Annotated[str, typer.Option(help="Defense preset (config/defenses/)")] = "baseline",
          mode: Annotated[str, typer.Option(help="serve | eval | demo")] = "serve",
          model: Annotated[str, typer.Option(help="A or B")] = "A",
          run_tag: Annotated[str | None, typer.Option(help="Run tag for the logs")] = None,
          port: Annotated[int | None, typer.Option(help="Port (default from config)")] = None,
          attacker_server: Annotated[bool, typer.Option(help="Also start the attacker server")] = True) -> None:
    """Start the app, UI, and attacker server on 127.0.0.1."""
    from ragsec.app.server import StartupError, run

    try:
        run(mode=mode, preset_name=preset, slot=model, run_tag=run_tag or secrets.token_hex(8), port=port,
            with_attacker_server=attacker_server)
    except StartupError as exc:
        _fail(str(exc), 2)


@app.command("attacker-server")
def attacker_server_cmd() -> None:
    """Run only the attacker server (127.0.0.1:8765)."""
    from ragsec import attacker_server
    from ragsec.settings import load_app_config

    cfg = load_app_config()
    attacker_server.serve(cfg.attacker_server.host, cfg.attacker_server.port,
                          cfg.path(cfg.paths.logs) / "attacker.jsonl")


@app.command()
def ask(message: str, role: str = "employee", user: str | None = None,
        url: str = "http://127.0.0.1:8000") -> None:
    """Send one question to a running server (serve/demo mode) and print the reply."""
    import httpx

    users = {"employee": "employee.user01@velmora.example", "hr": "hr.user01@velmora.example",
             "it_admin": "itadmin.user01@velmora.example"}
    r = httpx.post(f"{url}/api/chat", json={"role": role, "user_email": user or users[role], "message": message},
                   timeout=900)
    data = r.json()
    typer.echo(f"[{r.status_code}] {data.get('answer', data.get('detail'))}")
    if data.get("citations"):
        typer.echo(f"citations: {data['citations']}")
    if data.get("events"):
        typer.echo(f"events: {json.dumps(data['events'])}")


# --------------------------------------------------------------------------- eval
@app.command("eval")
def eval_cmd(suite: Annotated[str, typer.Option(help="benign,dev,heldout,adaptive (comma-separated)")],
             preset: Annotated[str, typer.Option()],
             model: Annotated[str, typer.Option(help="A or B")],
             run_id: Annotated[str, typer.Option(help="Run id; re-running resumes")],
             trials: Annotated[int | None, typer.Option(help="Trials per case (default 3 attacks, 5 benign)")] = None,
             suite_file: Annotated[Path | None, typer.Option(help="Case file for --suite adaptive-dev")] = None,
             browser: Annotated[bool, typer.Option(help="Run the Playwright exfil check")] = True,
             port: Annotated[int | None, typer.Option()] = None) -> None:
    """Run suites against one preset and one model (starts its own eval-mode server)."""
    from ragsec.harness.freeze import FreezeError
    from ragsec.harness.runner import EvalRunner, RunError

    try:
        runner = EvalRunner(suites=[s.strip() for s in suite.split(",") if s.strip()], preset=preset, model=model,
                            run_id=run_id, trials=trials, suite_file=suite_file, browser=browser, port=port)
        runner.run()
    except (FreezeError, RunError) as exc:
        _fail(str(exc), 2)


# ------------------------------------------------------------------------ attacks
@attacks_app.command("validate")
def attacks_validate(path: Annotated[list[Path] | None, typer.Argument(help="Case files (default: seeds)")] = None) -> None:
    """Validate attack cases. Seeds are user-owned: problems are reported, never fixed."""
    from ragsec.harness import attacks
    from ragsec.harness import paths as hp

    ctx = attacks.make_context()
    files = path or sorted(hp.seeds().glob("*.yaml"))
    if not files:
        _fail("no seed files in attacks/seeds/ (user-owned; see IMPLEMENTATION.md §8.5 and §16)")
    bad = 0
    for f in files:
        problems = attacks.validate_file(f, ctx)
        for cid, ps in problems.items():
            for p in ps:
                typer.echo(f"{f.name}: {cid}: {p}")
                bad += 1
    typer.echo("all cases valid" if not bad else f"{bad} problem(s)")
    raise typer.Exit(1 if bad else 0)


def _write_candidates(name: str, header: str, cases: list[dict], docs: dict[str, str]) -> Path:
    import yaml

    from ragsec.harness import paths as hp

    root = repo_root()
    for rel, text in docs.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
    out = hp.attacks(root) / "candidates" / name
    body = yaml.safe_dump(cases, sort_keys=False, allow_unicode=True, width=100)
    out.write_text(header + body, encoding="utf-8", newline="\n")
    return out


@attacks_app.command("generate")
def attacks_generate(convert: Annotated[bool, typer.Option("--convert", help="Convert promptfoo output")] = False,
                     variants: Annotated[bool, typer.Option("--variants", help="Write Claude variants")] = False) -> None:
    """Write candidate attacks (Run 2): promptfoo conversions and/or Claude variants."""
    from ragsec.harness import attacks
    from ragsec.harness import paths as hp

    if not convert and not variants:
        typer.echo(attacks.PROMPTFOO_NOTE)
        return
    root = repo_root()
    if convert:
        cases, docs, dropped = attacks.convert_promptfoo(root, hp.attacks(root) / "promptfoo" / "mapping.yaml")
        out = _write_candidates(
            "promptfoo_converted.yaml",
            "# promptfoo candidates converted with attacks/promptfoo/mapping.yaml (source: promptfoo).\n"
            "# Regenerate with `uv run ragsec attacks generate --convert`; never edit by hand.\n", cases, docs)
        typer.echo(f"wrote {len(cases)} promptfoo candidates to {out}; dropped {len(dropped)}:")
        for d in dropped:
            typer.echo(f"  - {d}")
    if variants:
        from ragsec.harness import variants as variants_mod

        cases, docs = variants_mod.build()
        out = _write_candidates(
            "claude_variants.yaml",
            "# Claude-written variants of the seeds (source: claude_variant), labeled when written.\n"
            "# Regenerate with `uv run ragsec attacks generate --variants`; never edit by hand.\n", cases, docs)
        typer.echo(f"wrote {len(cases)} Claude variants to {out} and {len(docs)} documents")


@attacks_app.command("promptfoo")
def attacks_promptfoo() -> None:
    """Generate promptfoo red-team candidates (the first run asks for your email)."""
    import shutil
    import subprocess

    from ragsec.settings import load_pins

    root = repo_root()
    version = load_pins(root=root).promptfoo.get("version")
    if not version:
        _fail("pin promptfoo.version in config/pins.yaml first (§4)")
    npx = shutil.which("npx")
    if npx is None:
        _fail("npx not found: install Node.js 22.22 or newer")
    assert npx is not None
    out_dir = root / "attacks" / "candidates" / "promptfoo"
    out_dir.mkdir(parents=True, exist_ok=True)
    env = envsetup.child_env({"npm_config_cache": str(root / ".npm-cache"),
                              "PROMPTFOO_CONFIG_DIR": str(root / ".promptfoo")})
    cmd = [npx, "-y", f"promptfoo@{version}", "redteam", "generate", "-c", "redteam.yaml",
           "-o", "../candidates/promptfoo/redteam_generated.yaml"]
    typer.echo(f"running promptfoo {version} from attacks/promptfoo/ (telemetry off)")
    code = subprocess.call(cmd, cwd=str(root / "attacks" / "promptfoo"), env=env)
    if code == 0:
        typer.echo("done: attacks/candidates/promptfoo/redteam_generated.yaml")
    raise typer.Exit(code)


SELECTION_HEADER = """\
# The 120 attack cases chosen for freezing (IMPLEMENTATION.md §8.6 step 5), written by
# `uv run ragsec attacks select`; never edit by hand.
#
# Rule: every seed is kept. Each remaining slot in a category goes to the candidate
# that closes the most §8.6 minimums still short, then to the one whose subtype, then
# injection style, then document provenance, then source, then role/direction is least
# represented so far. Ties fall to a fixed-seed shuffle (config/harness.yaml,
# selection.seed). The rule reads labels and documents only, never results.
"""


@attacks_app.command("select")
def attacks_select(
    out: Annotated[Path, typer.Option(help="Where to write the selection")] = Path("attacks/selection.yaml"),
) -> None:
    """Choose 15 cases per category from seeds and candidates, by variety, never by results."""
    from collections import Counter

    import yaml

    from ragsec.harness import attacks
    from ragsec.harness import paths as hp
    from ragsec.harness.data import load_case_file
    from ragsec.harness.runner import harness_cfg

    root = repo_root()
    hcfg = harness_cfg()
    ctx = attacks.make_context()
    files = sorted(hp.seeds(root).glob("*.yaml")) + sorted((hp.attacks(root) / "candidates").glob("*.yaml"))
    pool = [c for f in files for c in load_case_file(f)]
    problems = [f"{c.get('id', '?')}: {p}" for c in pool for p in attacks.validate_case(c, ctx)]
    if problems:
        _fail("invalid cases in the pool:\n  " + "\n  ".join(problems))
    try:
        selected = attacks.select_cases(pool, hcfg, ctx, int(hcfg["selection"]["seed"]))
    except attacks.SelectionError as exc:
        _fail(str(exc))
    target = out if out.is_absolute() else root / out
    target.parent.mkdir(parents=True, exist_ok=True)
    body = yaml.safe_dump(selected, sort_keys=False, allow_unicode=True, width=100)
    target.write_text(SELECTION_HEADER + body, encoding="utf-8", newline="\n")
    typer.echo(f"selected {len(selected)} of {len(pool)} cases -> {target}")
    for cat in attacks.CHECK_FOR_CATEGORY:
        group = [c for c in selected if c["category"] == cat]
        sources = Counter(str(c["source"]) for c in group)
        subtypes = Counter(str(attacks.labelled(c, ctx).get("subtype")) for c in group)
        typer.echo(f"  {cat}: {dict(sorted(sources.items()))}; {len(subtypes)} subtypes")


@attacks_app.command("split")
def attacks_split(selection: Annotated[Path, typer.Argument(help="YAML file with the 120 selected cases")]) -> None:
    """Preview the stratified dev/held-out split (does not write anything)."""
    from ragsec.harness import attacks
    from ragsec.harness.data import load_case_file
    from ragsec.harness.runner import harness_cfg

    hcfg = harness_cfg()
    ctx = attacks.make_context()
    cases = load_case_file(selection)
    dev, held = attacks.stratified_split(cases, int(hcfg["split"]["heldout_per_category"]),
                                         int(hcfg["split"]["seed"]), ctx)
    typer.echo(f"dev {len(dev)}, held-out {len(held)}")
    for c in sorted(held, key=lambda c: c["id"]):
        typer.echo(f"  held-out: {c['id']}")


@attacks_app.command("freeze")
def attacks_freeze(selection: Annotated[Path, typer.Argument(help="YAML file with the 120 selected cases")]) -> None:
    """Validate, check §8.6 minimums, split, and freeze dev/held-out into FREEZE.md."""
    from ragsec.harness import attacks
    from ragsec.harness.data import load_case_file
    from ragsec.harness.runner import harness_cfg

    hcfg = harness_cfg()
    ctx = attacks.make_context()
    cases = load_case_file(selection)
    problems = [f"{c['id']}: {p}" for c in cases for p in attacks.validate_case(c, ctx)]
    problems += attacks.check_minimums(cases, hcfg, ctx)
    if problems:
        _fail("cannot freeze:\n  " + "\n  ".join(problems))
    dev, held = attacks.freeze_sets(cases, repo_root(), hcfg, ctx)
    typer.echo(f"frozen: {dev} and {held}; hashes recorded in FREEZE.md")


# ------------------------------------------------------------------------- benign
@benign_app.command("validate")
def benign_validate() -> None:
    from ragsec.harness import benign

    problems = benign.validate()
    for p in problems:
        typer.echo(p)
    typer.echo("benign set valid" if not problems else f"{len(problems)} problem(s)")
    raise typer.Exit(1 if problems else 0)


@benign_app.command("freeze")
def benign_freeze(version: str = "benign-v1",
                  reason: Annotated[str, typer.Option(help="Required for benign-v2 and later")] = "") -> None:
    """Hash the benign set into FREEZE.md before its first run (§9)."""
    from ragsec.harness import benign

    if version != "benign-v1" and not reason:
        _fail("a corrected version needs --reason (the case and why; record it in DECISIONS.md too)")
    try:
        entry = benign.freeze_benign(version, "draft", reason)
    except ValueError as exc:
        _fail(str(exc))
        return
    typer.echo(f"froze {entry.file} as {entry.version}: {entry.sha256}")


@benign_app.command("final")
def benign_final() -> None:
    """Checkpoint 1: the user's "freeze benign" makes the current version final."""
    from ragsec.harness import freeze

    freeze.set_status("data/benign/benign.yaml", "final")
    typer.echo("benign set marked final in FREEZE.md")


# -------------------------------------------------------------------- supplychain
@app.command()
def supplychain(only: Annotated[list[str] | None, typer.Option(help="S1 S2a S2b S3 S4")] = None) -> None:
    """Run verification checks S1–S4 on copies and write the result table."""
    from ragsec.harness import supplychain as sc

    results = sc.run_all(only=only)
    for s in results:
        typer.echo(s.row())
    typer.echo("table written to results/summary/supplychain.md")


# -------------------------------------------------------------------------- audit
@audit_app.command("sample")
def audit_sample(model: str = "A") -> None:
    """Draw the check-audit sample (§10.5) from the baseline dev run of one model."""
    from ragsec.harness import audit
    from ragsec.harness.runner import harness_cfg

    a = harness_cfg()["audit"]
    try:
        out = audit.sample(model=model, per_category=int(a["per_category"]), per_case=int(a["per_case"]),
                           seed=int(a["seed"]))
    except RuntimeError as exc:
        _fail(str(exc))
    typer.echo(f"wrote {out} and labels_template.yaml beside it; copy the template to "
               "results/audit/labels.yaml (user-owned) and label every sample")


@audit_app.command("score")
def audit_score() -> None:
    from ragsec.harness import audit

    typer.echo(f"wrote {audit.score()}")


# ------------------------------------------------------------------------- report
@app.command()
def report(scoring: Annotated[str | None, typer.Option(help="core | run6 (scoring steps only)")] = None) -> None:
    """Summary tables, charts, and REPORT.md's generated blocks."""
    from ragsec.harness import report as rep
    from ragsec.harness.predictions import PredictionHashError

    if scoring not in (None, "core", "run6"):
        _fail("--scoring must be core or run6")
    if scoring == "run6":
        _fail("Run 6 scoring is not built yet (extension); see IMPLEMENTATION.md §10.4")
    try:
        updated = rep.run_report(scoring=scoring)
    except (rep.ReportError, PredictionHashError) as exc:
        _fail(str(exc), 2)
        return
    typer.echo(f"updated REPORT.md blocks: {', '.join(updated)}; tables and charts in results/summary/")


# --------------------------------------------------------------------------- demo
@demo_app.command("exfil")
def demo_exfil(preset: str = "baseline", port: int = 8000,
               check: Annotated[bool, typer.Option("--check", help="Headless check instead of the live UI")] = False,
               attempts: Annotated[int, typer.Option(help="Questions to ask in --check mode")] = 3) -> None:
    """Live exfiltration demo in the real UI (records well for a video); --check runs it headless."""
    from ragsec.harness import demo

    if check:
        raise typer.Exit(0 if demo.check(preset, port, attempts) else 1)
    demo.run(preset, port)


# --------------------------------------------------------------------------- load
@app.command()
def load(preset: Annotated[str, typer.Option()],
         with_attack: Annotated[bool, typer.Option("--with-attack")] = False,
         capacity: Annotated[float | None, typer.Option(help="Reuse a calibrated capacity (requests/minute)")] = None,
         port: int = 8000) -> None:
    """Load test (extension, §8.8). Starts a serve-mode server for the preset."""
    import asyncio

    from ragsec.harness import load as ld
    from ragsec.harness import paths as hp
    from ragsec.harness.data import load_directory
    from ragsec.harness.runner import harness_cfg
    from ragsec.harness.server_control import ServerProcess

    root = repo_root()
    hcfg = harness_cfg(root)
    cap_file = hp.summary(root) / "load_capacity.json"
    users = load_directory(hp.directory(root)).load_users
    server = ServerProcess(mode="serve", preset=preset, model="A", run_tag="load-" + secrets.token_hex(4),
                           port=port, root=root, log_path=hp.logs(root) / f"server_load_{preset}.log")
    server.start()
    try:
        if capacity is None:
            if cap_file.is_file():
                capacity = float(json.loads(cap_file.read_text())["capacity_per_minute"])
            elif preset == "baseline":
                capacity = asyncio.run(ld.calibrate(server.base_url, ld._questions(root),
                                                    float(hcfg["load"]["calibration_minutes"]), users[0]))
                cap_file.parent.mkdir(parents=True, exist_ok=True)
                cap_file.write_text(json.dumps({"capacity_per_minute": capacity}), encoding="utf-8", newline="\n")
            else:
                _fail("calibrate on baseline first (ragsec load --preset baseline)")
        assert capacity is not None
        result = asyncio.run(ld.run_load(server.base_url, capacity_per_minute=capacity, with_attack=with_attack,
                                         root=root, hcfg=hcfg, users=users))
        out = ld.save(result, preset, with_attack, capacity, root)
        typer.echo(json.dumps(result.summary(), indent=2))
        typer.echo(f"saved {out}")
    finally:
        server.stop()


# ------------------------------------------------------------------------- poison
@poison_app.command("build-data")
def poison_build_data() -> None:
    from ragsec.harness import poison

    typer.echo(f"wrote datasets to {poison.build_data()}")


def _train_cmd(script: str, extra: list[str]) -> None:
    import subprocess

    root = repo_root()
    cmd = ["uv", "run", "--project", str(root / "train"), "python", str(root / "train" / script), *extra]
    typer.echo("running: " + " ".join(cmd))
    raise typer.Exit(subprocess.call(cmd, cwd=root, env=envsetup.child_env()))


@poison_app.command("train")
def poison_train(dataset: Annotated[list[str] | None, typer.Option(help="Dataset names (default: all 14)")] = None) -> None:
    """Fine-tune in the separate train/ environment (CUDA PyTorch). Resumable."""
    _train_cmd("finetune.py", [f"--dataset={d}" for d in dataset or []])


@poison_app.command("eval")
def poison_eval() -> None:
    """Evaluate the base model and every fine-tune in train/."""
    _train_cmd("evaluate.py", [])


def main() -> None:
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
