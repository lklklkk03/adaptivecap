# AdaptiveCap

Reference implementation and data for the paper **"AdaptiveCap: Adaptive Capability Control
for Secure and Flexible LLM Agent Workflows"** (Electronics, 2026).

## Repository layout

- `adaptivecap/` — the AdaptiveCap enforcement pipeline: dependency-chain scope isolation,
  the dual-layer declassification auditor (deterministic Layer-1 gates + LLM Layer-2),
  and automatic privilege recovery.
- `experiments/` — the experiment scripts that produce every table and figure in the paper
  (`exp1`…`exp9`), the scenario definitions, and the regression test suite.
- `reports/` — the archived report for every experiment (JSON + Markdown);
  `reports/archive/` holds the raw run archives with the run manifests
  (classifier, verdict-cache state, patch flags, machine specification).
- `supplementary/Supplementary_Material.pdf` — the supplementary material document
  (Tables S1–S7 and the verbatim Layer-2 audit prompt, Section S7).
- `Table_S1_per_scenario.csv` — per-scenario results for all 151 scenarios (Table S1).
- `Table_S2_per_call.csv` — per-call decision log, one row per tool call (Table S2).

Every aggregate reported in the paper is recomputable from the two CSV files.

## Requirements

- Python 3.13.
- The upstream ChainCaps artifact (https://github.com/Jxcup/chaincaps-code) is required for
  the comparison runs: the experiment scripts import the `chaincaps` package and read
  `raid_v3_results.json` from a ChainCaps checkout (see `_CHAINCAPS_ROOT` in
  `experiments/scenarios.py`).
- A DeepSeek API key is required for the live Layer-2 classifier; the deterministic Mock
  classifier supports offline reproduction of the pipeline logic.
