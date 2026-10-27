# Experiment 9 — Realistic-Workflow Diagnosis (R2-7)

## 1. Description of the 50 scenarios

- Source: chaincaps.attacks.realistic_workflows (upstream ChainCaps repository; 30 attack + 20 benign)
- Composition: 30 attack + 20 benign, 213 tool calls, 39 distinct tool chains
- Scenarios whose sources carry declared budgets: 45/50

## 2. Annotation availability

| Quantity | Value |
|---|---|
| Scenarios with >= 1 explicit dependency annotation | 0 |
| Scenarios without any annotation | 50 |
| Annotated steps / total steps | 0 / 213 |

With no annotations every sink falls back to the conservative global meet across all active components (ChainCaps behaviour), so this set cannot exercise scope isolation as shipped.

## 3. Annotation upper bound

| Variant | System | ABR | BCR | BCR 95% CI | FP (step) |
|---|---|---|---|---|---|
| as-is (no annotations) | ElasticCap | 100.0% | 100.0% | [100.0%, 100.0%] | 0 |
| as-is (no annotations) | ChainCaps | 100.0% | 85.0% | [70.0%, 100.0%] | 3 |
| deps-annotated | ElasticCap | 100.0% | 100.0% | [100.0%, 100.0%] | 0 |
| deps-annotated | ChainCaps | 100.0% | 85.0% | [70.0%, 100.0%] | 3 |
| deps+sink-scopes | ElasticCap | 100.0% | 100.0% | [100.0%, 100.0%] | 0 |
| deps+sink-scopes | ChainCaps | 100.0% | 85.0% | [70.0%, 100.0%] | 3 |

Variant (a) reconstructs the true data flow (`step i` consumes `step i-1`); variant (b) additionally declares the sink scope that the engines cannot infer from non-standard target arguments (`channel`, `repo`).
