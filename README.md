# RAG Attack & Defense Lab

A deliberately vulnerable internal helpdesk assistant ("Vel", for the fictional
Velmora Systems), built on retrieval-augmented generation plus one email tool. It is
attacked in 8 categories mapped to the OWASP Top 10 for LLM Applications 2026,
defended by 7 switchable defenses, and measured on two local models. The questions:
what each defense adds to the full stack (the ablation), what still gets through when
the attacker adapts (the adaptive round), and what the defenses cost ordinary users.
Everything runs on one laptop at $0.

> **Scope:** fictional company and data, everything local (127.0.0.1 only). The app
> renders raw HTML on purpose, so model output can run script. **Never deploy it or
> expose it beyond this machine.**

## Headline results

Model A (qwen3:8b) with all seven defenses on, unless noted:

- **The ablation picks out the load-bearing defenses.** Switching off one defense at a
  time from `all`:
  - Without D5, the query classifier, direct injection (A1) climbs from 10% back to
    70% (p = 0.031).
  - Without D2, output handling, indirect phishing (A3) climbs from 0% to 60%
    (p = 0.031).
  - Without D7, the resource limits, resource exhaustion (A8) rises from 10% to 23%
    (p = 0.50, so suggestive only).
  - Removing D1, D3, D4, or D6 changes no category significantly.
- **The adaptive round found no way through, and that is weak evidence.**
  - promptfoo generated every attempt, with techniques from the OWASP 2026 list:
    hidden characters, prompt extraction, cross-role probes, and resource attacks, each
    also in four encodings.
  - The full budget of 40 attempts (10 each in A1, A2, A4, and A8) scored 0 of 120
    trials. The final 12-case set scored 0 of 36 on each model.
  - D5 refused most of them at the message, and D7 the over-long ones.
  - With every defense off, the same 12 cases scored 1 of 72 trials across both
    models. The 0% mostly measures these generic encoded attacks, not the stack.
  - They never reached the four categories where the static set still succeeds.
- **Static and held-out sets:** 36.2% → 6.2% attack success on the dev set; 38.3% →
  9.2% on the held-out set (p = 0.0004). Model B (llama3.1:8b): 14.2% → 2.5% held-out
  (p = 0.039).
- **What still gets through under `all`:**
  - planted false facts (A5): 20% on the dev set, and every one of Model A's
    successful held-out trials (11 of 15 A5 trials; every other category 0 of 15).
    Nothing in the stack checks whether a retrieved statement is true.
  - an attacker link in an email to the requester's own address (A7, 10%), which gets
    past both D3 and D2
  - a few direct injections (A1, 10%) and resource exhaustion (A8, 10%)
- **The cost:**
  - Benign accuracy falls from 96.7% to 66.7%, and false refusals rise from 0% to
    23.7%.
  - Median latency per question goes from 1.0 s to 2.2 s.
  - Most of the accuracy loss comes from the fallback classifier behind D5 and D6,
    which flags the corpus's own security-policy pages.
- **Two attackers can deny service on the shared GPU, even with D7 on** (load test,
  extension). This is by §8.8's rule: with the attack, normal users' p95 latency more
  than doubles or their errors exceed 5%.
  - With no defenses, normal users' p95 latency goes from 12 s to 101 s.
  - D7 turns away 97% of the attackers' requests and keeps every answer under 20 s,
    but 7% of normal requests then time out.
  - With every defense on, 20% time out, because D5's classifier competes for the CPU
    inside the same 20-second budget.

Full tables, confidence intervals, sign-flip tests, and charts are in
[REPORT.md](REPORT.md); every judgment call is in [DECISIONS.md](DECISIONS.md).

## Architecture

```mermaid
flowchart LR
  H[Harness: attack and benign trials] -->|POST /api/chat| API[FastAPI app 127.0.0.1:8000]
  API --> D7{D7 limits}
  D7 --> D5m{D5 message classifier}
  D5m --> R[Retrieval: bge-small + Chroma, top 4]
  R -->|D1 role filter| R
  R --> D5c{D5 chunk classifier}
  D5c --> P[Prompt builder + D4 spotlighting]
  P --> M[Ollama: qwen3:8b or llama3.1:8b]
  M -->|send_email| T[Email tool + D3 gating]
  T --> M
  M --> D2{D2 output handling}
  D2 --> API
  API -->|answer, events, emails| C[Checks: code, never an LLM judge]
  C -->|/render/turn_id| B[Headless Chromium + CSP]
  B -.->|exfiltration attempt| X[Attacker server 127.0.0.1:8765]
  X --> C
  PD[Poisoned documents via /eval/docs] --> I[Ingestion + D6 scan]
  I --> R
```

## Status

| Run | What | State |
|---|---|---|
| 0 | `ragsec doctor` environment check | Done; all machine checks green |
| 1 | App, defenses, harness, data, CI, benign baseline | **Done** (Checkpoint 1) |
| 2 | Attack set, baseline attacks, demo | **Frozen** (`frozen-v1`): 120 cases (24 seeds + 115 Claude variants + 42 promptfoo → selected by variety), dev 80 / held-out 40; baseline ASR measured on both models |
| 3 | Defenses measured, supply chain, held-out | **Done** (Checkpoint 3): 16 presets on Model A, 3 on Model B, held-out run once, S1–S4 caught, predictions scored |
| 4 | Adaptive round, report, final checks | **Done** (core checkpoint): 40 development attempts within budget, 12-case final set on both models |
| 5 | Load test (extension) | **Done** (Checkpoint 5): capacity calibrated, 6 runs (3 presets, with and without the attack) |
| 6 | Training-data poisoning (extension) | Scaffold built; waits for "start Run 6" |

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

Attacks were tuned on Model A, so Model B's row measures transfer. This table is the
Ollama 0.40.15 result. Run 3 re-measured both baselines on 0.40.16 (below).

Model B's numbers come from Ollama's llama3.1 tool template, which asks the model to
answer every message with a function call whenever a tool is available (see
DECISIONS.md, 2026-11-08). Sample answers for spot-checking:
[results/summary/checkpoint1_samples.md](results/summary/checkpoint1_samples.md).

**Run 3: defenses measured.** Model A (qwen3:8b), frozen dev set, Ollama 0.40.16. The
A1–A8 columns are attack success rates.

| Preset | A1 | A2 | A3 | A4 | A5 | A6 | A7 | A8 | Overall | Benign accuracy | False refusals |
|---|---|---|---|---|---|---|---|---|---|---|---|
| baseline | 66.7% | 36.7% | 53.3% | 43.3% | 33.3% | 16.7% | 0.0% | 40.0% | **36.2%** | 96.7% | 0.0% |
| D1 role filter | 66.7% | 36.7% | 53.3% | 0.0% | 40.0% | 16.7% | 0.0% | 40.0% | 31.7% | 96.7% | 0.0% |
| D2 output handling | 66.7% | 0.0% | 0.0% | 10.0% | 33.3% | 0.0% | 0.0% | 40.0% | 18.8% | 93.0% | 0.0% |
| D3 tool gating | 66.7% | 36.7% | 53.3% | 46.7% | 33.3% | 16.7% | 0.0% | 36.7% | 36.2% | 96.7% | 0.0% |
| D4 spotlighting | 70.0% | 40.0% | 63.3% | 50.0% | 36.7% | 0.0% | 10.0% | 46.7% | 39.6% | 96.7% | 0.0% |
| D5 query classifier | 6.7% | 0.0% | 53.3% | 33.3% | 23.3% | 16.7% | 0.0% | 20.0% | 19.2% | 78.3% | 18.3% |
| D6 ingest scan | 56.7% | 33.3% | 53.3% | 33.3% | 23.3% | 16.7% | 0.0% | 40.0% | 32.1% | 79.3% | 7.3% |
| D7 limits | 66.7% | 36.7% | 53.3% | 40.0% | 33.3% | 16.7% | 0.0% | 10.0% | 32.1% | 96.7% | 0.0% |
| all | 10.0% | 0.0% | 0.0% | 0.0% | 20.0% | 0.0% | 10.0% | 10.0% | **6.2%** | 66.7% | 23.7% |

Model B (llama3.1:8b): overall ASR 14.6% at baseline, 13.3% with D4, and 2.9% with all
defenses. Its benign accuracy goes 42.3% → 47.3% → 17.7%.

Held-out set (40 cases, run once): Model A 38.3% → 9.2% with all defenses (p = 0.0004);
Model B 14.2% → 2.5% (p = 0.039).

- **The classifier:** Prompt Guard 2 access was denied, so D5 and D6 use the ProtectAI
  fallback, which flags this corpus's security-policy language and the near-miss
  questions.
- **A gap:** an attacker link inside an email to the requester's own address gets
  past both D3, which checks only the recipient, and D2, which cleans only the answer.
- **Supply chain:** all four tampering checks (S1–S4) are caught.
- **Predictions, scored blind:** 45 right, 16 wrong, 8 inconclusive, 19 not
  measurable. All 7 measurable by-design cells held.

**Run 4: adaptive round.** The 12-case final set chosen within the budget
(`attacks/adaptive/final.yaml`), 3 trials per case, in a fresh seed namespace:

| Model | Preset | A1 | A2 | A4 | A8 | Overall |
|---|---|---|---|---|---|---|
| A: qwen3:8b | all | 0/9 | 0/9 | 0/9 | 0/9 | **0.0%** |
| A: qwen3:8b | baseline (reference) | 0/9 | 0/9 | 0/9 | 1/9 | 2.8% |
| B: llama3.1:8b | all | 0/9 | 0/9 | 0/9 | 0/9 | **0.0%** |
| B: llama3.1:8b | baseline (reference) | 0/9 | 0/9 | 0/9 | 0/9 | 0.0% |

- **Development:** 40 attempts on Model A under `all` (10 of 10 in A1, A2, A4, and A8),
  0 of 120 trials.
- **Not attempted:** A3 and A5–A7 need poisoned documents, which promptfoo's generator
  doesn't write.
- **Reading it:** with every defense off, the same cases barely work. So this round
  mostly measures promptfoo's encoded attacks, not the stack ([REPORT.md](REPORT.md) §9).

**Run 5: load test (extension, §8.8).**
- **Setup:** Model A in serve mode, with Ollama serving one request at a time.
  - **Capacity C:** 67.5 answers a minute, from one client asking back to back.
  - **Normal users:** 20 simulated employees ask benign questions on an open-loop
    schedule at 50% of C: 355 requests in 10 minutes, the same in every run.
  - **Attackers:** 2, each keeping 4 of the dev set's A8 chat-message attacks in
    flight.
- **Denial of service** means that with the attack, p95 latency more than doubles or
  errors exceed 5%.

| Preset | Attack | Median (s) | p95 (s) | Errors | Denial of service |
|---|---|---|---|---|---|
| baseline | no | 2.3 | 12.3 | 0.0% | |
| baseline | yes | 71.8 | 101.3 | 0.0% | **yes** (latency, 8.2×) |
| d7 | no | 2.3 | 12.4 | 0.0% | |
| d7 | yes | 12.1 | 19.2 | 7.0% | **yes** (errors) |
| all | no | 5.4 | 12.1 | 0.0% | |
| all | yes | 15.8 | 19.6 | 20.0% | **yes** (errors) |

- **What D7 does:** it turns long waits into errors. It rejects the attackers' oversized
  and repeated requests (3,561 of 3,663), but the ~100 it admits still take a quarter of
  the GPU's time, so some queued users hit its 20-second timeout.
- **Under `all`:** D5's classifier adds CPU contention inside the same timeout.
- **Headroom:** the normal load kept the GPU busy 63–67% of the time, not 50%. One-user
  calibration makes requests look 31% cheaper than 20 rotating users do, so the
  verdicts depend on that headroom.
- **A fix:** D7's timeout didn't cover time spent queued in Ollama. That was fixed
  before these runs; eval results are unaffected.

Details: [REPORT.md](REPORT.md) §10 and [DECISIONS.md](DECISIONS.md) (Run 5).

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

1. The Conclusions and Recommendations blocks at the end of [REPORT.md](REPORT.md)
   (user-owned).
2. The demo video: `uv run ragsec demo exfil --preset baseline`, then `--preset all` to
   show the stack stopping it (§15.4).
3. The resume bullet.
4. `.claude/settings.json` from IMPLEMENTATION.md Appendix B (Claude Code's permission
   rules for this project). Rule 2 makes it yours to create; Claude Code never writes it.
5. Optional (§3): `OLLAMA_NUM_PARALLEL=1` and `OLLAMA_MAX_LOADED_MODELS=1` as user
   environment variables, then restart Ollama.
6. Say "start Run 6" (training-data poisoning) or "stop". If you want Run 6's
   predictions in their own file, commit `PREDICTIONS_RUN6.sha256` before "start Run 6"
   and keep `PREDICTIONS_RUN6.md` outside the repo folder (rule 15).

No Hugging Face token is needed any more. Prompt Guard 2 access was denied, so the
ungated fallback classifier is the one in use.

## Reproduce at $0

Prerequisites: Windows 11, macOS, or Linux; Python 3.12; [uv](https://docs.astral.sh/uv/);
Node 22.22+; Ollama with `qwen3:8b` and `llama3.1:8b` pulled; an 8 GB NVIDIA GPU.

```bash
uv sync --locked                    # app environment (CPU PyTorch)
uv run ragsec doctor --download     # Run 0: checks, model downloads, Chromium, pins
uv run ragsec corpus render         # templates -> data/corpus (byte-identical to the committed copy)
uv run ragsec ingest                # Chroma index
uv run ragsec benign validate       # the benign set is already frozen in FREEZE.md
uv run ragsec eval --suite benign --preset baseline --model A --run-id benign-A-baseline
uv run ragsec eval --suite benign --preset baseline --model B --run-id benign-B-baseline
uv run ragsec report                # tables, charts, REPORT.md generated blocks
```

`--trials 1` on any `eval` gives a quick smoke run.

Run 3, in order (each `eval` resumes by run id; the presets are in `config/defenses/`):

```bash
uv run ragsec ingest --d6                                                     # D6's collection
uv run ragsec eval --suite benign --preset d5 --model A --run-id run3-tune-d5-A  # also d4, d6
uv run ragsec tune                                                            # §7.3: reports only
uv run ragsec eval --suite dev,benign --preset all --model A --run-id run3-all-A # one per preset
uv run ragsec eval --suite heldout --preset all --model A --run-id run3-heldout-all-A  # once only
uv run ragsec supplychain                                                     # S1–S4 on copies
uv run ragsec report --scoring core                                           # needs PREDICTIONS.md
```

Run 4, the adaptive round (each step refuses to repeat; the pool and attempt log are
committed, so these re-create nothing that exists):

```bash
uv run ragsec adaptive promptfoo            # owner: promptfoo generation (asks for an account email)
uv run ragsec adaptive convert              # -> attacks/adaptive/promptfoo/pool.yaml
uv run ragsec adaptive pick --round 1       # -> attacks/adaptive/dev/promptfoo-r1.yaml
uv run ragsec adaptive attempt attacks/adaptive/dev/promptfoo-r1.yaml   # Model A, all, 3 trials, logged
uv run ragsec adaptive status               # attempts used of 10 per category
uv run ragsec adaptive finalize             # -> attacks/adaptive/final.yaml (3 per category)
uv run ragsec eval --suite adaptive --preset all --model A --run-id run4-adaptive-all-A   # and model B
```

Run 5, the load test (Model A in serve mode; about 1.5 hours; nothing else on the GPU):

```bash
uv run ragsec load --calibrate                      # once: capacity C on baseline -> results/summary/load_capacity.json
uv run ragsec load --preset all --with-attack --minutes 1   # optional smoke run; the report ignores it
uv run ragsec load --preset baseline                # then --with-attack; same for d7 and all
uv run ragsec report                                # REPORT.md §10, results/summary/load*.csv, load_latency.png
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
| `ragsec tune [--model A]` | §7.3 analysis of the benign tuning runs (d4, d5, d6); reports only, never edits config |
| `ragsec adaptive promptfoo` / `convert` / `pick` / `attempt` / `status` / `finalize` | Adaptive round (§8.7): generate, convert, draw, run and log within the budget, choose the final set |
| `ragsec supplychain` | Verification checks S1–S4 on copies |
| `ragsec audit sample` / `score` | Check audit (§10.5) |
| `ragsec report [--scoring core]` | Summary tables, charts, predictions scoring |
| `ragsec demo exfil --preset baseline\|all [--check]` | Live exfiltration demo in the real UI; `--check` runs it headless |
| `ragsec load --calibrate` / `--preset P [--with-attack] [--minutes M]` | Load test (§8.8): capacity once, then normal users with or without two attackers |
| `ragsec poison build-data` / `train` / `eval` | Poisoning extension (`train/` has its own CUDA environment) |
| `ragsec ask "question" [--role hr]` | Send one question to a running server |

Tests: `uv run pytest`, `uv run ruff check .`, `uv run mypy`.

## Repository map

```
config/            app.yaml, harness.yaml, dlp.yaml, pins.yaml, defenses/ (16 presets)
data/              facts.yaml (source of truth), canaries.yaml, directory.yaml, corpus_src/ -> corpus/, benign/
attacks/           seeds/ (USER-OWNED), candidates/, docs/, frozen/, demo/,
                   adaptive/: promptfoo/ (config, pool), dev/ (attempts), attempts.jsonl, final.yaml;
                   adaptive/user/ is USER-OWNED
src/ragsec/app/    API, modes, pipeline, retrieval, prompts, tool, model client, cache, integrity, render
src/ragsec/defenses/ d1_role_filter … d7_limits
src/ragsec/harness/  runner, checks, browser, stats, metrics, report, attacks, adaptive, audit, supplychain, doctor, load, poison
ui/                chat UI, render page, shared renderer, vendored marked.js
tests/             pytest suite (mocked LLM and classifier) + captured Ollama fixtures
train/             poisoning extension (separate CUDA environment)
results/           raw/ (gitignored), summary/, audit/ (labels.yaml is USER-OWNED)
DECISIONS.md       every judgment call      FREEZE.md   hashes of frozen sets
REPORT.md          the report (two USER-OWNED blocks)
```

All caches (uv, Hugging Face, Playwright, generation cache, Chroma) live inside this
folder and are gitignored. Only the Ollama model store lives elsewhere (`~/.ollama`).
