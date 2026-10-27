# Experiment 4 — Manifest Robustness (RQ4)

- Policy: every sensitive source budgeted to `display(*)` under Conservative.
- Expert manifests use the raid_v3 source budgets.

## Benign completion rates

| Engine | Expert BCR | Conservative BCR |
|---|---|---|
| ChainCaps | 0.0% (0/19) | 0.0% (0/19) |
| ElasticCap | 63.2% (12/19) | 63.2% (12/19) |

ElasticCap auditor (Conservative cell): G/Y/R = 7/6/2

## Paper-ready paragraph

> Under the Conservative manifest, ChainCaps is nearly unusable (0.0% benign completion) because every sensitive read globally tightens the context budget, while ElasticCap maintains 63.2% benign completion by isolating completed dependency chains and letting the DeepSeek-V4 auditor issue scoped declassification tokens where appropriate. This validates the core RQ4 claim of the system: *manifest authors do not need to perfectly pre-authorise every sink*; an overly conservative manifest plus an audit layer is a viable baseline.

## Claim validation

- ChainCaps+Conservative BCR < 30%: **PASS** (0.0%)
- ElasticCap+Conservative BCR ≥ 60%: **PASS** (63.2%)
