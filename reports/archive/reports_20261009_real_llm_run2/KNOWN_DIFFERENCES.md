# KNOWN DIFFERENCES between archived runs (read before citing raw JSON)

> **Update (2026-10-10): the exp1/exp7 discrepancy described below has been
> removed.** `experiments/exp7_baselines.py` now reads its AdaptiveCap and
> ChainCaps rows (main set, realistic-workflow subset and the
> order-robustness sweep) directly from `exp1_baseline.json` instead of
> replaying the live classifier, and `reports/exp7_baselines.json` has been
> regenerated accordingly (EC 90.9% BCR, FP 5 — identical to exp1; McNemar
> 19 discordant pairs, p = 3.8e-06, which is also the value cited in the
> manuscript). The archived JSON in *this directory* is the historical
> record of the original run and still contains the difference below; the
> `demo/experiments/reports/` copies are the ones the manuscript cites.
> The code and data changes made `exp7_baselines.py` produce zero LLM calls
> on re-run, so the reference rows can no longer drift.

The archived reports in this directory are the raw outputs of the revision
runs. Two reports contain the same system (AdaptiveCap) evaluated on the same
151 scenarios, and they differ by exactly one scenario. The manuscript always
uses the exp1 numbers (see below), but a reader auditing the raw JSON will see
the difference, so it is documented here.

## 1. AdaptiveCap on FP-09: exp1 says 50/55 BCR, exp7 says 49/55

| Report | BCR | FP (step-level) | Note |
| --- | --- | --- | --- |
| `exp1_baseline.json` (main run) | 90.9% (50/55) | 5 | used by the paper |
| `exp1c_measurement_correction.json` | 90.9% (50/55) | 5 | corrected re-query of the two empty-completion cases |
| `exp7_baselines.json` | 89.1% (49/55) | 6 | its own replay of the same scenarios |

**Cause.** Scenario FP-09 (a meet-tension false positive) receives different
Layer-2 verdicts across calls from the provider even at temperature 0. In the
main run the call returned an empty completion (43.8 s) which the client then
recorded as YELLOW; under the documented YELLOW convention for FP-06..09 the
scenario counts as completed. In exp7's replay the same prompt returned RED,
which the convention does not tolerate, so the scenario fails and also counts
one wrongly blocked step. Both values are faithful recordings of their run.

**How the manuscript handles it.** `exp1c` re-queried both affected scenarios
with the client that now retries empty completions; FP-09's re-query returned
an explicit YELLOW, so the corrected headline metrics are unchanged
(ABR 97.9%, BCR 90.9%, FP 5). Every AdaptiveCap figure in the paper comes from
exp1 + exp1c; exp7 supplies the *other* baselines' rows only, and its
AdaptiveCap row is not cited. The single-scenario difference is also disclosed
in the paper (Errata item 16).

**If you want to remove the discrepancy entirely.** Done on 2026-10-10:
`experiments/exp7_baselines.py` now reads the AdaptiveCap and ChainCaps rows
from `exp1_baseline.json` instead of replaying them (the pattern is also used
in `exp7b_baseline_sweep.py` and `exp9_rw_diagnosis.py`), and
`reports/exp7_baselines.json` was regenerated. All archived AdaptiveCap rows
are now identical; see the update note at the top of this file.

## 2. Latency samples come from two different populations

* `exp6_overhead.json` (LLM path): 30 engineered short prompts, cache disabled
  → p50 2,005 ms.
* The benchmark's own audit traffic (`llm_audit_log_exp1.jsonl`, 98 live calls
  with full lineage and payload context) → p50 2.9 s, p95 33.8 s, max 47.1 s.

The paper reports both and explains the difference (prompt length). Use the
second one when quoting "typical" audit latency in a deployment argument.

## 3. Provider throughput varied by two orders of magnitude

Calls ranged from ~2 s to ~160 s over the two runs, and the throttle windows
are visible in the timestamps of `llm_audit_log.jsonl`. This affects wall-clock
time only, never the recorded verdicts or the measured hot-path latency.

> **Update (2026-10-10, later):** a privilege-inference fix (Slack/GitHub sinks
> resolved to their API endpoint scopes instead of argument-level scopes) was
> applied to `elasticap/engine.py`. It recovers four benign scenarios
> (MCP-BN09, RW-B09, RW-B13, RW-B19) that had been conservatively blocked
> because whitelisted endpoint grants could not match the inferred scopes.
> `reports/exp1_baseline.json` was updated by replaying exactly the affected
> scenarios (all deterministic: their sinks are now budget-authorized, no
> model calls) and recomputing the aggregates, CIs and the call ledger
> (BCR 98.2%, FP 1, 114 audited calls). exp1b/exp7/exp7b/exp9 and all
> supplementary exports were regenerated accordingly; the manuscript cites
> these values and records the fix as Errata item 17. The archived JSONs in
> this directory remain the historical record of the pre-fix runs.
