# FREEZE

Hashes of every frozen file, with seeds, namespaces, and dates (rule 4). The
harness reads the table below and refuses to run a frozen suite whose file no
longer matches its hash. Never edit a frozen file: new attacks go into a new,
labeled set, and the only benign exception is §9's correction rule (a new
version, recorded here and in DECISIONS.md, before Checkpoint 1).

How entries get here:
- Benign set: `uv run ragsec benign freeze` before its first run (benign-v1);
  `uv run ragsec benign final` at Checkpoint 1 when the user says "freeze benign".
- Attack sets: `uv run ragsec attacks freeze <selection.yaml>` in Run 2 (dev and
  held-out, split seed and namespace recorded in the Notes column).

Seed namespaces: `benign-v1` (or the current benign version), `candidates`,
`frozen-v1`, `adaptive-dev`, `adaptive-final` (§10.2).

<!-- FREEZE:TABLE:BEGIN -->
| File | Version | SHA-256 | Status | Date | Notes |
|---|---|---|---|---|---|
| `data/benign/benign.yaml` | benign-v1 | bb808421db0cd8e4a402531d1257f481a82286215bcdab619485c3a3d0934f08 | draft | 2026-11-08 |  |
| `attacks/frozen/dev.yaml` | frozen-v1 | 991ee5d62ed6978e32db3b2190ee3264bfdce8d2f900e7b124e87172c5d79511 | final | 2026-11-09 | split seed 424242; namespace frozen-v1 |
| `attacks/frozen/heldout.yaml` | frozen-v1 | 92bf3d9d447663f85dee4606d6c9b121b848961c9d58041bc21657074b0715b9 | final | 2026-11-09 | split seed 424242; namespace frozen-v1 |
<!-- FREEZE:TABLE:END -->
