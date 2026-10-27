# Experiment 6 — Runtime Overhead (revision)

**Machine.** Intel(R) Xeon(R) Gold 6148 CPU @ 2.40GHz x80 cores, 125.5 GB RAM, Linux-6.8.0-41-generic-x86_64-with-glibc2.39, Python 3.13.5 (bare metal, no container).

## Deterministic hot path (no network I/O)

| Component | n | min (ms) | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) |
|---|---|---|---|---|---|---|
| Scope bucket (component + context budget) | 2000 | 0.0156 | 0.0219 | 0.0389 | 0.0438 | 0.0540 |
| Layer-1 audit (pattern + k-anonymity + target) | 2000 | 0.0097 | 0.0107 | 0.0393 | 0.0454 | 140.7722 |
| Token issuance (HMAC-SHA256) | 2000 | 0.0124 | 0.0134 | 0.0142 | 0.0240 | 0.0299 |
| Integrated AdaptiveCap per call (Layer-2 disabled) | 800 | 0.0262 | 0.0276 | 0.0323 | 0.0899 | 0.1568 |

## LLM path (live DeepSeek, verdict cache disabled)

| Measurement | n | min (ms) | p50 (ms) | p95 (ms) | p99 (ms) | max (ms) | mean (ms) |
|---|---|---|---|---|---|---|---|
| Layer-2 LLM (live API, cache disabled) | 30 | 1380 | 2005 | 3074 | 4145 | 4145 | 2132 |

Verdicts returned: {'GREEN': 30}


## ChainCaps on the same machine (hot path only)

| Measurement | n | p50 (ms) | p95 (ms) | p99 (ms) | mean (ms) |
|---|---|---|---|---|---|
| Integrated ChainCaps per call (same machine) | 800 | 0.0160 | 0.0173 | 0.0193 | 0.0160 |

| DAG size | p50 (ms) | p95 (ms) | mean (ms) |
|---|---|---|---|
| 10 | 0.0116 | 0.0130 | 0.0119 |
| 50 | 0.0115 | 0.0183 | 0.0123 |
| 100 | 0.0116 | 0.0125 | 0.0120 |
| 500 | 0.0113 | 0.0150 | 0.0121 |
| 1000 | 0.0113 | 0.0119 | 0.0115 |

## Amortized cost

- Audit trigger rate on the benchmark: **20.85% of all tool calls** (118 of 566 calls; 62.1% of sink attempts). Source: exp1_baseline.json call_summary.
- Expected per-call cost = trigger rate x measured LLM latency = 20.85% x 2132 ms = **444.4 ms per call** (1324.0 ms per sink attempt).

The withdrawn 0.080 ms figure was a cache-hit reading and is not reproduced; the deterministic path is reported above and the LLM cost is reported as a per-trigger cost, not amortized into a sub-millisecond number.
