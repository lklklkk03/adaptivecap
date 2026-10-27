# Experiment 1b — No-Audit Control

The auditor removed entirely (`auditor=None`): every suspended sink is blocked by the budget, no model is consulted. The full-system row is the exp1 run (same scenarios, live classifier).

| Configuration | ABR | BCR | FP (step) | FN |
|---|---|---|---|---|
| Full AdaptiveCap | 97.9% | 90.9% | 5 | 2 |
| No auditor (deterministic only) | 97.9% | 78.2% | 12 | 2 |

**Attack block rate is identical (yes): 97.9% with and without the model in the loop.** The false-negative sets are the same scenarios in both configurations (G1-062, G1-066) — a pre-existing tool-classification limitation (search/read tools declared as sinks do not enter the data-flow DAG), not a classifier decision.

The auditor's measurable contribution is availability: it rescues 7 benign scenarios (78.2% → 90.9% BCR), all of them sanitize-then-share workflows whose aggregation the semantic layer verifies.
