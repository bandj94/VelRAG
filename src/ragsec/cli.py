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
adaptive_app = typer.Typer(help="Adaptive round (§8.7)", no_args_is_help=True)
poison_app = typer.Typer(help="Training-data poisoning extension (§8.10)", no_args_is_help=True)
app.add_typer(corpus_app, name="corpus")
app.add_typer(attacks_app, name="attacks")
app.add_typer(benign_app, name="benign")
app.add_typer(audit_app, name="audit")
app.add_typer(demo_app, name="demo")
app.add_typer(adaptive_app, name="adaptive")
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


def _run_promptfoo(workdir: Path, out_rel: str, out_dir: Path) -> int:
    """`promptfoo redteam generate -c redteam.yaml` from `workdir` at the pinned version, telemetry off."""
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
    out_dir.mkdir(parents=True, exist_ok=True)
    env = envsetup.child_env({"npm_config_cache": str(root / ".npm-cache"),
                              "PROMPTFOO_CONFIG_DIR": str(root / ".promptfoo")})
    cmd = [npx, "-y", f"promptfoo@{version}", "redteam", "generate", "-c", "redteam.yaml", "-o", out_rel]
    typer.echo(f"running promptfoo {version} from {workdir.relative_to(root).as_posix()}/ (telemetry off)")
    return subprocess.call(cmd, cwd=str(workdir), env=env)


@attacks_app.command("promptfoo")
def attacks_promptfoo() -> None:
    """Generate promptfoo red-team candidates (the first run asks for your email)."""
    root = repo_root()
    code = _run_promptfoo(root / "attacks" / "promptfoo", "../candidates/promptfoo/redteam_generated.yaml",
                          root / "attacks" / "candidates" / "promptfoo")
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


# ----------------------------------------------------------------------- adaptive
@adaptive_app.command("attempt")
def adaptive_attempt(file: Annotated[Path, typer.Argument(help="Case file in attacks/adaptive/dev/")],
                     run_id: Annotated[str | None, typer.Option(help="Default: adaptive-dev-<file stem>")] = None,
                     note: Annotated[str, typer.Option(help="One line for the attempt log")] = "") -> None:
    """Run development attempts (Model A, preset all, 3 trials, namespace adaptive-dev) and log each case."""
    from ragsec.harness import adaptive, attacks
    from ragsec.harness import paths as hp
    from ragsec.harness.data import load_case_file
    from ragsec.harness.freeze import FreezeError
    from ragsec.harness.runner import EvalRunner, RunError

    root = repo_root()
    path = file if file.is_absolute() else (Path.cwd() / file)
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError:
        _fail(f"{file} is not inside the repository")
    if rel.parts[:3] != ("attacks", "adaptive", "dev"):
        _fail("attempt files live in attacks/adaptive/dev/ (the final suite never reads that folder)")
    cases = load_case_file(path)
    if not cases:
        _fail(f"{rel} has no cases")
    ctx = attacks.make_context(root)
    problems = [f"{c.get('id', '?')}: {p}" for c in cases for p in attacks.validate_case(c, ctx)]
    log = adaptive.load_log(root)
    problems += adaptive.budget_problems(cases, log, root)
    if problems:
        for p in problems:
            typer.echo(p)
        _fail(f"{len(problems)} problem(s); nothing was run or logged")
    rid = run_id or f"adaptive-dev-{path.stem}"
    try:
        EvalRunner(suites=["adaptive-dev"], preset=adaptive.DEV_PRESET, model=adaptive.DEV_MODEL, run_id=rid,
                   trials=adaptive.DEV_TRIALS, suite_file=path).run()
    except (FreezeError, RunError) as exc:
        _fail(str(exc), 2)
    raw = hp.raw_results(root) / f"{rid}.jsonl"
    records = [json.loads(x) for x in raw.read_text(encoding="utf-8").splitlines() if x.strip()]
    try:
        entries = adaptive.entries_for_run(cases, records, file=rel.as_posix(), run_id=rid, log=log, root=root,
                                           canaries=ctx.canaries, note=note)
    except adaptive.AdaptiveError as exc:
        _fail(str(exc))
    adaptive.append_log(entries, root)
    for e in entries:
        events = sorted({ev for t in e["per_trial"] for ev in t["events"]})
        typer.echo(f"{e['case_id']} ({e['category']} attempt {e['attempt']}/{adaptive.BUDGET_PER_CATEGORY}): "
                   f"{e['successes']}/{e['trials']} | events: {', '.join(events) or '-'}")
    typer.echo(f"logged {len(entries)} attempt(s) to attacks/adaptive/attempts.jsonl")


@adaptive_app.command("promptfoo")
def adaptive_promptfoo() -> None:
    """Generate the adaptive candidates with promptfoo (attacks/adaptive/promptfoo/redteam.yaml)."""
    root = repo_root()
    work = root / "attacks" / "adaptive" / "promptfoo"
    code = _run_promptfoo(work, "redteam_generated.yaml", work)
    if code == 0:
        typer.echo("done: attacks/adaptive/promptfoo/redteam_generated.yaml")
    raise typer.Exit(code)


@adaptive_app.command("convert")
def adaptive_convert() -> None:
    """Convert promptfoo's adaptive output into labeled cases (attacks/adaptive/promptfoo/pool.yaml)."""
    import yaml

    from ragsec.harness import adaptive, attacks
    from ragsec.settings import load_pins

    root = repo_root()
    src = adaptive.generated_path(root)
    if not src.is_file():
        _fail("no promptfoo output yet: run `uv run ragsec adaptive promptfoo` first")
    out = adaptive.pool_path(root)
    if out.exists():
        _fail(f"{out.relative_to(root).as_posix()} already exists; the pool is converted once")
    ctx = attacks.make_context(root)
    version = str(load_pins(root=root).promptfoo.get("version"))
    conv = adaptive.convert_promptfoo(yaml.safe_load(src.read_text(encoding="utf-8")), version,
                                      validate=lambda c: attacks.validate_case(c, ctx))
    header = ("# Adaptive candidate pool: promptfoo's output converted by `ragsec adaptive convert`, labeled from\n"
              "# promptfoo's own metadata (plugin -> category, strategy -> technique) before any result existed.\n"
              "# Development attempts are drawn from here by `ragsec adaptive pick`; never edit by hand.\n")
    out.write_text(header + adaptive.dump_cases(conv.cases), encoding="utf-8", newline="\n")
    counts: dict[str, int] = {}
    for c in conv.cases:
        counts[c["category"]] = counts.get(c["category"], 0) + 1
    typer.echo(f"wrote {len(conv.cases)} cases to {out.relative_to(root).as_posix()}: {counts}")
    reasons: dict[str, int] = {}
    for _i, why in conv.dropped:
        key = why.split(":")[0] if why.startswith("validation") else why
        reasons[key] = reasons.get(key, 0) + 1
    typer.echo(f"dropped {len(conv.dropped)}: {reasons}")


@adaptive_app.command("pick")
def adaptive_pick(round_no: Annotated[int, typer.Option("--round", help="1 = variety; 2+ = ranked by dev results")]) -> None:
    """Draw the next development attempts from the pool into attacks/adaptive/dev/promptfoo-r<N>.yaml."""
    from ragsec.harness import adaptive
    from ragsec.harness.data import load_case_file

    root = repo_root()
    pool_file = adaptive.pool_path(root)
    if not pool_file.is_file():
        _fail("no pool yet: run `uv run ragsec adaptive convert` first")
    out = adaptive.dev_dir(root) / f"promptfoo-r{round_no}.yaml"
    if out.exists():
        _fail(f"{out.relative_to(root).as_posix()} already exists")
    picked = adaptive.pick_round(load_case_file(pool_file), adaptive.load_log(root), round_no)
    if not picked:
        _fail("nothing left to pick (budget spent or pool exhausted)")
    out.parent.mkdir(parents=True, exist_ok=True)
    header = (f"# Adaptive development attempts, round {round_no}, drawn from the promptfoo pool by\n"
              "# `ragsec adaptive pick` (rule in DECISIONS.md); each case is one attempt.\n")
    out.write_text(header + adaptive.dump_cases(picked), encoding="utf-8", newline="\n")
    by_cat: dict[str, int] = {}
    for c in picked:
        by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
    typer.echo(f"wrote {len(picked)} attempts to {out.relative_to(root).as_posix()}: {by_cat}")


@adaptive_app.command("status")
def adaptive_status() -> None:
    """Attempts used per category and the best development result."""
    from ragsec.harness import adaptive

    log = adaptive.load_log()
    if not log:
        typer.echo("no attempts logged yet")
        return
    for r in adaptive.status_rows(log):
        typer.echo(f"{r['category']:20s} {r['used']:2d}/{r['budget']} attempts | best {r['best']}/3 | "
                   f"{r['with_success']} with any success")
    for e in log:
        typer.echo(f"  {e['category']:20s} #{e['attempt']:<2d} {e['case_id']:8s} {str(e.get('subtype')):28s} "
                   f"{e['successes']}/{e['trials']}")


@adaptive_app.command("finalize")
def adaptive_finalize(per_category: Annotated[int, typer.Option(help="Cases per category")] = 3) -> None:
    """Copy the chosen attempts verbatim into attacks/adaptive/final.yaml, pinning document hashes."""
    from ragsec.harness import adaptive

    try:
        final = adaptive.finalize(per_category=per_category)
    except adaptive.AdaptiveError as exc:
        _fail(str(exc))
    typer.echo(f"wrote {len(final.cases)} cases to {final.path.relative_to(repo_root()).as_posix()}")
    for c in final.cases:
        typer.echo(f"  {c['id']:8s} {c['category']:20s} {c.get('subtype')}")


# ------------------------------------------------------------------------- tuning
@app.command()
def tune(model: str = "A") -> None:
    """§7.3 analysis of the benign tuning runs (d4, d5, d6). Reports only; never edits config."""
    from ragsec.harness import tuning

    try:
        findings = tuning.analyse(model=model)
    except tuning.TuningError as exc:
        _fail(str(exc))
    if not findings:
        _fail(f"no benign tuning runs (presets d4, d5, d6) for Model {model} yet")
    for f in findings:
        typer.echo(f"{f.defense}: {f.value} | trigger: {'yes' if f.trigger else 'no'} | allowed: {f.allowed}")
        for n in f.notes:
            typer.echo(f"    {n}")
    typer.echo(f"written to {tuning.write(findings)}")


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
def load(preset: Annotated[str | None, typer.Option(help="Defense preset to load-test")] = None,
         with_attack: Annotated[bool, typer.Option("--with-attack", help="Add the two attackers")] = False,
         calibrate: Annotated[bool, typer.Option("--calibrate", help="Measure capacity C once, on baseline")] = False,
         minutes: Annotated[float | None, typer.Option(
             help="Window length; anything but the configured 10 minutes is a smoke run the report ignores")] = None,
         run_id: Annotated[str | None, typer.Option("--run-id",
                                                    help="Default: load-<preset>-<normal|attack>")] = None,
         port: int = 8000) -> None:
    """Load test (extension, §8.8): Model A in serve mode, open-loop normal users, optional attackers."""
    from ragsec.harness import load as ld
    from ragsec.harness.freeze import FreezeError
    from ragsec.harness.server_control import ServerStartError

    root = repo_root()
    try:
        if calibrate:
            if preset not in (None, "baseline") or with_attack:
                _fail("--calibrate runs once, on baseline, without the attack")
            ld.run_calibration(root, port=port)
            return
        if preset is None:
            _fail("pass --preset (or --calibrate first)")
        meta = ld.run_load_test(root, preset=preset, with_attack=with_attack, minutes=minutes, run_id=run_id,
                                port=port)
        typer.echo(json.dumps(meta["summary"], indent=2))
    except (ld.LoadError, FreezeError, ServerStartError) as exc:
        _fail(str(exc))


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
