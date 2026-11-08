# RAG Attack & Defense Lab

A deliberately vulnerable internal helpdesk assistant ("Vel", for the fictional
Velmora Systems) built on retrieval-augmented generation plus one email tool,
attacked in 8 categories mapped to the OWASP Top 10 for LLM Applications 2026,
defended by 7 switchable defenses, and measured on two local models: what each
defense does alone, what it adds to the full stack (ablation), and what still gets
through (adaptive round). Everything runs on one laptop at $0.

> **Scope:** fictional company and data, everything local (127.0.0.1 only). The app
> renders raw HTML on purpose, so model output can run script. **Never deploy it or
> expose it beyond this machine.**

## Status

| Run | What | State |
|---|---|---|
| 0 | `ragsec doctor` environment check | Done; all machine checks green |
| 1 | App, defenses, harness, data, CI, benign baseline | **Done** (Checkpoint 1) |
| 2 | Attack set, baseline attacks, demo | **Frozen** (`frozen-v1`): 120 cases (24 seeds + 115 Claude variants + 42 promptfoo → selected by variety), dev 80 / held-out 40; baseline ASR measured on both models |
| 3 | Defenses measured, supply chain, held-out | Tooling built; needs the classifier download |
| 4 | Adaptive round, report | Tooling built |
| 5–6 | Load test, poisoning (extensions) | Scaffolds built, untested on real models |

**Run 1 benign baseline** (60 questions × 5 trials, preset `baseline`, benign-v1):

| Model | Benign accuracy | False refusals | Near misses accurate | Unrequested emails |
|---|---|---|---|---|
| A: qwen3:8b | **97.7%** | 0.0% | 96% | 0 |
| B: llama3.1:8b | 43.3% | 25.3% | 22% | 61% of trials |

**Run 2 attack baseline** (frozen dev set, 80 cases × 3 trials, preset `baseline`, no
defenses; 95% cluster-bootstrap intervals in [REPORT.md](REPORT.md)):

| Model | A1 | A2 | A3 | A4 | A5 | A6 | A7 | A8 | Overall |
|---|---|---|---|---|---|---|---|---|---|
| A: qwen3:8b | 70.0% | 33.3% | 56.7% | 50.0% | 33.3% | 13.3% | 0.0% | 40.0% | **37.1%** |
| B: llama3.1:8b | 16.7% | 6.7% | 3.3% | 10.0% | 20.0% | 0.0% | 16.7% | 23.3% | **12.1%** |

Attacks were tuned on Model A, so Model B's row measures transfer.

Model B's numbers come from Ollama's llama3.1 tool template, which asks the model to
answer every message with a function call whenever a tool is available (see
DECISIONS.md, 2026-11-08). Sample answers for spot-checking:
[results/summary/checkpoint1_samples.md](results/summary/checkpoint1_samples.md).

## Seed attacks

24 seed attacks (3 per category) live in `attacks/seeds/`, mapped to the OWASP Top 10
for LLM Applications 2026: instruction override, persona jailbreak, delimiter spoofing,
system-prompt extraction, indirect injection through vendor imports and shared-drive
uploads, retrieval hijacking with planted false facts, zero-click markdown exfiltration,
stored XSS through an `onerror` handler, email-tool hijacking, and resource amplification.
See the catalog in [attacks/SEEDS_GUIDE.md](attacks/SEEDS_GUIDE.md).

## Frozen attack set (`frozen-v1`)

The seeds are the start of a 181-case candidate pool: the 24 seeds, 115 deterministic
Claude variants (`src/ragsec/harness/variants.py`), and 42 promptfoo 0.125.1 candidates.
Every candidate was labeled before its results existed and run once against Model A.
`ragsec attacks select` then kept all seeds and filled each category to 15 by variety
of technique — subtype, injection style, document provenance, source, role — never by
success rate, so no attack earns its place by working. The 120 selected cases are split
10 dev / 5 held-out per category (stratified, seed 424242) and frozen into
`attacks/frozen/`, with hashes, the split seed, and each poisoned document's hash in
[FREEZE.md](FREEZE.md); the harness refuses to run if a frozen file or document changes.
Candidates were tuned on Model A, so Model B's numbers show how well they transfer.

## Still to do (owner)

1. `.env` with `HF_TOKEN=...` (read access to Llama-Prompt-Guard-2-86M), then
   `uv run ragsec doctor --download` once for the classifier (needed by Run 3).
2. `.claude/settings.json` from IMPLEMENTATION.md Appendix B (Claude Code's permission
   rules for this project), or ask Claude Code to create it.
3. Optional (§3): `OLLAMA_NUM_PARALLEL=1` and `OLLAMA_MAX_LOADED_MODELS=1` as user
   environment variables, then restart Ollama.

## Reproduce at $0

Prerequisites: Windows 11, macOS, or Linux; Python 3.12; [uv](https://docs.astral.sh/uv/);
Node 22.22+; Ollama with `qwen3:8b` and `llama3.1:8b` pulled; an 8 GB NVIDIA GPU.

```bash
uv sync --locked                    # app environment (CPU PyTorch)
uv run ragsec doctor --download     # Run 0: checks, model downloads, Chromium, pins
uv run ragsec corpus render         # templates -> data/corpus
uv run ragsec ingest                # Chroma index (add --d6 once the classifier is downloaded)
uv run ragsec benign freeze         # hash the benign set before its first run (§9)
uv run ragsec eval --suite benign --preset baseline --model A --run-id benign-A-baseline
uv run ragsec eval --suite benign --preset baseline --model B --run-id benign-B-baseline
uv run ragsec report                # tables, charts, REPORT.md generated blocks
```

Try the app by hand: `uv run ragsec serve --preset baseline`, then open
http://127.0.0.1:8000 (or `uv run ragsec ask "What are the helpdesk hours?"`).

## Commands

| Command | Purpose |
|---|---|
| `ragsec doctor [--download]` | Environment checks and Ollama probes; `--download` is the only command that reads `.env` |
| `ragsec corpus render` / `lint` | Render templates; lint for hardcoded numbers |
| `ragsec ingest [--d6]` | Build the index (and D6's quarantined collection) |
| `ragsec serve --preset P [--mode serve\|eval\|demo] [--model A\|B]` | App, UI, and attacker server on 127.0.0.1 |
| `ragsec eval --suite benign,dev,heldout,adaptive --preset P --model A --run-id ID` | Run trials (resumable; starts its own eval server) |
| `ragsec benign validate` / `freeze` / `final` | Benign-set checks and freezing |
| `ragsec attacks promptfoo` | promptfoo red-team generation at the pinned version (the owner runs it once) |
| `ragsec attacks generate [--convert] [--variants]` | promptfoo conversion and Claude variants into `attacks/candidates/` |
| `ragsec attacks validate` / `select` / `split` / `freeze` | Validate cases, choose 15 per category by variety, preview the split, freeze (Run 2) |
| `ragsec supplychain` | Verification checks S1–S4 on copies |
| `ragsec audit sample` / `score` | Check audit (§10.5) |
| `ragsec report [--scoring core]` | Summary tables, charts, predictions scoring |
| `ragsec demo exfil --preset baseline\|all [--check]` | Live exfiltration demo in the real UI; `--check` runs it headless |
| `ragsec load --preset P [--with-attack]` | Load-test extension |
| `ragsec poison build-data` / `train` / `eval` | Poisoning extension (`train/` has its own CUDA environment) |
| `ragsec ask "question" [--role hr]` | Send one question to a running server |

Tests: `uv run pytest`, `uv run ruff check .`, `uv run mypy`.

## Repository map

```
config/            app.yaml, harness.yaml, dlp.yaml, pins.yaml, defenses/ (16 presets)
data/              facts.yaml (source of truth), canaries.yaml, directory.yaml, corpus_src/ -> corpus/, benign/
attacks/           seeds/ (USER-OWNED), candidates/, docs/, frozen/, adaptive/ (user/ is USER-OWNED), demo/
src/ragsec/app/    API, modes, pipeline, retrieval, prompts, tool, model client, cache, integrity, render
src/ragsec/defenses/ d1_role_filter … d7_limits
src/ragsec/harness/  runner, checks, browser, stats, metrics, report, attacks, audit, supplychain, doctor, load, poison
ui/                chat UI, render page, shared renderer, vendored marked.js
tests/             pytest suite (mocked LLM and classifier) + captured Ollama fixtures
train/             poisoning extension (separate CUDA environment)
results/           raw/ (gitignored), summary/, audit/ (labels.yaml is USER-OWNED)
DECISIONS.md       every judgment call      FREEZE.md   hashes of frozen sets
REPORT.md          the report (two USER-OWNED blocks)
```

All caches (uv, Hugging Face, Playwright, generation cache, Chroma) live inside this
folder and are gitignored. Only the Ollama model store lives elsewhere (`~/.ollama`).
