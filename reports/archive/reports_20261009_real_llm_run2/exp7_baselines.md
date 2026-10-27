# Experiment 7 — Multi-Baseline Comparison (RQ5)

- Scenarios: 151 total (FP=9, SC=14, G1=128: 92 adv + 36 ben)

## Aggregate metrics

| System | ABR | BCR | FP (step-level) | FN |
|---|---|---|---|---|
| ElasticCap | 97.9% | 89.1% | 6 | 2 |
| ChainCaps | 97.9% | 56.4% | 14 | 2 |
| Fides | 40.6% | 80.0% | 11 | 57 |
| PFI | 4.2% | 74.5% | 23 | 92 |
| CoarseTaint | 79.2% | 56.4% | 24 | 20 |
| NoDefense | 0.0% | 100.0% | 0 | 96 |

## Interpretation

- **ElasticCap** should match or exceed ChainCaps on ABR while
  significantly exceeding all baselines on BCR.
- **ChainCaps** high ABR from monotonic budget decay; BCR limited
  by context poisoning and no recovery mechanism.
- **Fides** (C/I labels): coarse confidentiality/integrity labels
  cannot represent per-source sink subsets → moderate BCR, lower ABR.
- **PFI** (per-tool isolation): no cross-tool composition tracking
  → high BCR (everything allowed) but very low ABR (attacks pass).
- **CoarseTaint** (3-level taint): lumps all internal sources together
  → cannot distinguish authorized vs unauthorized cross-scope flows.
- **NoDefense**: unconditional allow-all → 100% BCR, 0% ABR
  (security lower bound).

## Paper-ready paragraph

> We compare ElasticCap against 6 baselines on a unified 151-scenario benchmark. ElasticCap achieves 97.9% ABR and 89.1% BCR, matching ChainCaps on security (97.9% ABR) while substantially exceeding it on availability (56.4% BCR). Fides C/I labels (40.6%/80.0%) and CoarseTaint (79.2%/56.4%) suffer from representational limitations that conflate distinct sink authorities. PFI (4.2%/74.5%) lacks cross-tool composition analysis, trading security for availability. NoDefense (0.0%/100.0%) establishes the security lower bound.


## Realistic Workflows Validation (50 scenarios)

- 30 attack + 20 benign natural-distribution tasks

- Uses real MCP tool names: filesystem_read, slack_post_message, etc.

| System | ABR | BCR | FP | FN | BCR 95% CI |
|---|---|---|---|---|---|
| ElasticCap | 100.0% | 85.0% | 3 | 0 | [70.0%, 100.0%] |
| ChainCaps | 100.0% | 85.0% | 3 | 0 | [70.0%, 100.0%] |

### Dependency-annotation availability (R2-7 diagnosis)

| Set | scenarios | with >=1 annotation | without annotation | annotated steps / total |
|---|---|---|---|---|
| all | 50 | 0 | 50 | 0 / 213 |
| benign | 20 | 0 | 20 | 0 / 78 |
| attacks | 30 | 0 | 30 | 0 / 135 |

## Order-Robustness Sweep (AdaptiveCap, 3 orders)

- ElasticCap ABR: 97.9% ± 0.0%

- ElasticCap BCR: 89.1% ± 0.0%

- Scenario order is permuted; verdicts are reused from the process-wide LLM cache, so a zero spread confirms that the pipeline is order-independent — this is NOT a seed-variance measure (see the bootstrap CI for uncertainty).


## Bootstrap 95% CI and significance

| System | ABR [95% CI] | BCR [95% CI] |
|---|---|---|
| ElasticCap | 97.9% [94.8%, 100.0%] | 89.1% [80.0%, 96.4%] |
| ChainCaps | 97.9% [94.8%, 100.0%] | 56.4% [41.8%, 70.9%] |
| Fides | 40.6% [31.2%, 50.0%] | 80.0% [69.1%, 89.1%] |
| PFI | 4.2% [1.0%, 9.4%] | 74.5% [63.6%, 85.5%] |
| CoarseTaint | 79.2% [70.8%, 87.5%] | 56.4% [43.6%, 69.1%] |
| NoDefense | 0.0% [0.0%, 0.0%] | 100.0% [100.0%, 100.0%] |

Paired McNemar (AdaptiveCap vs ChainCaps, per-scenario correctness): discordant pairs = 18 (AdaptiveCap-only 18, ChainCaps-only 0), exact p = 7.63e-06


## Call-level accounting (AdaptiveCap, all scenarios)

| Layer | Count | Share of sink attempts |
|---|---|---|
| authorized by budget (no audit) | 72 | 37.9% |
| suspended to auditor | 118 | 62.1% |
| Layer-1 GREEN | 0 | 0.0% |
| Layer-2 reached | 117 | 61.6% |

- Total tool calls: 566; sink attempts: 190


## Paper-ready paragraph (extended)

> On the 50 realistic workflow scenarios (30 attack + 20 benign), ElasticCap achieves 100.0% ABR and 85.0% BCR, compared to ChainCaps' 100.0% ABR and 85.0% BCR (BCR 95% CI: AdaptiveCap [70.0%, 100.0%], ChainCaps [70.0%, 100.0%]). 50 of these 50 scenarios carry no explicit dependency annotation, so the conservative global-meet fallback applies. Order-robustness over 3 permutations: ABR 97.9%±0.0%, BCR 89.1%±0.0%.
