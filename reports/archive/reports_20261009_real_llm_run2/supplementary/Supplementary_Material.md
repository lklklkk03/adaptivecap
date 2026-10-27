# AdaptiveCap — Supplementary Material

Every aggregate figure in the manuscript is derivable from Table S1 (per scenario) and Table S2 (per call). All data come from the single end-to-end run described in Section 5.1 of the paper; the run manifest (classifier, cache state, patch flags, machine) is archived with the reports.

## Provenance of main-text artifacts

| Artifact | Experiment | Classifier | Cache |
|---|---|---|---|
| Tables 1–2, Figure 2 | exp1 | DeepSeek V4 Pro | on |
| Table 7 (call accounting) | exp1 | DeepSeek V4 Pro | on |
| Table 5 (overhead, hot path) | exp6 | none | n/a |
| Table 5 (overhead, LLM path) | exp6 | DeepSeek V4 Pro | off |
| Table 6 (adaptive attacks) | exp8 | DeepSeek V4 Pro | on |
| Table 8 / Figure 4 (baselines) | exp7 | DeepSeek V4 Pro | on |
| Figure 3 (ablation) | exp5 | DeepSeek V4 Pro | on |
| SC-C2 verdict log | exp3 | DeepSeek V4 Pro | on |
| Regression tests | test suite | mock | n/a |

## Table S1 — Per-scenario results

See `Table_S1_per_scenario.csv`. Columns: `scenario_id`, `scenario`, `subset` (FP / SC-A / SC-B / SC-C / G1 / realistic), `task_type` (ground truth), `n_steps`, `attack_step`, and per system the outcome, the step-level false-positive count and the auditor tally (GREEN/RED/YELLOW).

## Table S2 — Per-call decisions

See `Table_S2_per_call.csv`. One row per tool call for AdaptiveCap and ChainCaps with the budget decision, the audit verdict, the deciding layer and the expected outcome. This table contains the SC-C2 Layer-2 verdict log cited in Section 5.4.

## Table S3a — Baseline configuration sweep

Knobs swept per re-implemented baseline; the configuration used in the headline table is the default (oracle-inferred) setting, which the sweep shows is the most favourable on BCR at or above the default ABR.


**Fides**

| Setting | ABR | BCR | FP (step) | FN |
|---|---|---|---|---|
| default (oracle-inferred) | 40.6% | 80.0% | 11 | 57 |
| all sources INTERNAL (strict) | 40.6% | 74.5% | 14 | 57 |
| all sources PUBLIC (lax) | 3.1% | 81.8% | 10 | 93 |

**PFI**

| Setting | ABR | BCR | FP (step) | FN |
|---|---|---|---|---|
| blocked_tools={} | 4.2% | 74.5% | 23 | 92 |
| blocked_tools=['execute_shell', 'shell_exec'] | 15.6% | 74.5% | 23 | 81 |
| blocked_tools=['email_send', 'fetch_url', 'filesystem_write', 'github_create_issue', 'github_create_pr', 'memory_store', 'send_email', 'send_http', 'shell_exec', 'slack_post_message', 'write_file'] | 88.5% | 16.4% | 71 | 11 |
| blocked_tools=['execute_shell', 'github_create_issue', 'github_create_pr', 'shell_exec'] | 24.0% | 72.7% | 25 | 73 |

**CoarseTaint**

| Setting | ABR | BCR | FP (step) | FN |
|---|---|---|---|---|
| default (oracle-inferred) | 79.2% | 56.4% | 24 | 20 |
| all sources INTERNAL (strict) | 37.5% | 89.1% | 6 | 60 |
| all sources SENSITIVE (strictest) | 82.3% | 40.0% | 33 | 17 |
| all sources PUBLIC (lax) | 2.1% | 100.0% | 0 | 94 |

**ChainCaps**

| Setting | ABR | BCR | FP (step) | FN |
|---|---|---|---|---|
| default (ground-truth manifests) | 97.9% | 56.4% | 14 | 2 |
| all sources unrestricted (upper bound) | 9.4% | 100.0% | 0 | 87 |

Paired McNemar (AdaptiveCap vs ChainCaps): discordant 19, p = 3.81e-06.


## Table S3b — Annotation availability and the upper bound (50 realistic scenarios)

| Variant | System | ABR | BCR | BCR 95% CI | FP (step) |
|---|---|---|---|---|---|
| as-is (no annotations) | ElasticCap | 100.0% | 85.0% | [70.0%, 100.0%] | 3 |
| as-is (no annotations) | ChainCaps | 100.0% | 85.0% | [70.0%, 100.0%] | 3 |
| deps-annotated | ElasticCap | 100.0% | 85.0% | [70.0%, 100.0%] | 3 |
| deps-annotated | ChainCaps | 100.0% | 85.0% | [70.0%, 100.0%] | 3 |
| deps+sink-scopes | ElasticCap | 100.0% | 100.0% | [100.0%, 100.0%] | 0 |
| deps+sink-scopes | ChainCaps | 100.0% | 85.0% | [70.0%, 100.0%] | 3 |

Annotation availability: 50 of 50 scenarios carry no explicit dependency annotation (0 of 213 steps).

Variant `deps-annotated` reconstructs the true data flow; `deps+sink-scopes` additionally declares each legitimate sink's target scope (attack sinks are deliberately not declared).


## Table S4 — Composition of the 50 realistic scenarios

| Quantity | Value |
|---|---|
| Provenance | chaincaps.attacks.realistic_workflows (upstream ChainCaps repository; 30 attack + 20 benign) |
| Scenarios | 50 |
| Attack / benign | 30 / 20 |
| Tool calls | 213 |
| Distinct tool chains | 39 |
| Scenarios with declared source budgets | 45 |

**Tool chains.**

| Tool chain | Scenarios |
|---|---|
| filesystem_read -> summarize_text -> format_data -> email_send | 5 |
| postgres_query -> format_data -> summarize_text -> slack_post_message | 3 |
| postgres_query -> format_data -> summarize_text -> email_send | 2 |
| filesystem_read -> summarize_text -> format_data -> slack_post_message | 2 |
| filesystem_read -> summarize_text -> format_data -> filesystem_write | 2 |
| filesystem_read -> summarize_text -> format_data -> display_to_user | 2 |
| fetch_url -> summarize_text -> format_data -> display_to_user | 2 |
| filesystem_read -> summarize_text -> format_data -> fetch_url | 1 |
| filesystem_read -> format_data -> summarize_text -> github_create_issue | 1 |
| filesystem_read -> summarize_text -> format_data -> browser_navigate | 1 |
| filesystem_read -> summarize_text -> memory_store -> memory_retrieve -> fetch_url | 1 |
| filesystem_read -> summarize_text -> format_data -> shell_exec | 1 |
| filesystem_read -> translate_text -> format_data -> fetch_url | 1 |
| filesystem_read -> summarize_text -> filesystem_write -> filesystem_read -> fetch_url | 1 |
| postgres_query -> format_data -> memory_store -> memory_retrieve -> summarize_text -> email_send | 1 |
| filesystem_read -> summarize_text -> shell_exec -> filesystem_read -> fetch_url | 1 |
| fetch_url -> summarize_text -> format_data -> github_create_issue | 1 |
| filesystem_read -> translate_text -> format_data -> filesystem_write -> slack_post_message | 1 |
| postgres_query -> summarize_text -> format_data -> summarize_text -> email_send | 1 |
| filesystem_read -> summarize_text -> format_data -> github_create_pr | 1 |
| browser_navigate -> browser_screenshot -> summarize_text -> format_data -> email_send | 1 |
| memory_retrieve -> summarize_text -> format_data -> fetch_url | 1 |
| fetch_url -> filesystem_read -> summarize_text -> format_data -> slack_post_message | 1 |
| postgres_query -> postgres_query -> summarize_text -> format_data -> email_send | 1 |
| filesystem_read -> filesystem_read -> summarize_text -> format_data -> github_create_issue | 1 |
| fetch_url -> filesystem_read -> summarize_text -> format_data -> email_send | 1 |
| postgres_query -> format_data -> summarize_text -> fetch_url | 1 |
| filesystem_read -> filesystem_read -> summarize_text -> format_data -> email_send | 1 |
| filesystem_read -> filesystem_read -> summarize_text -> format_data -> slack_post_message | 1 |
| fetch_url -> filesystem_read -> summarize_text -> format_data -> browser_navigate | 1 |
| filesystem_read -> summarize_text -> display_to_user | 1 |
| postgres_query -> format_data -> display_to_user | 1 |
| fetch_url -> summarize_text -> format_data -> slack_post_message | 1 |
| filesystem_read -> summarize_text -> format_data -> github_create_issue | 1 |
| postgres_query -> format_data -> summarize_text -> filesystem_write | 1 |
| fetch_url -> translate_text -> summarize_text -> display_to_user | 1 |
| fetch_url -> summarize_text -> format_data -> memory_store | 1 |
| filesystem_read -> format_data -> summarize_text -> filesystem_write | 1 |
| postgres_query -> summarize_text -> format_data -> display_to_user | 1 |

## Table S5 — Adaptive attack outcomes

| Attack | Mechanism targeted | Pre-revision | Revised | Deciding layer | Layer-2 raw verdict |
|---|---|---|---|---|---|
| AA-A1 | threat-model: annotation forgery | ALLOWED | ALLOWED | budget | — |
| AA-A2 | control: conservative fallback | blocked | blocked | layer2-llm | RED |
| AA-B1 | threat-model: recovery soundness (P4) | ALLOWED | ALLOWED | budget | — |
| AA-B2 | control: conservative fallback | blocked | blocked | layer2-llm | RED |
| AA-C1 | threat-model: cross-chain splitting | ALLOWED | ALLOWED | budget | — |
| AA-C2 | control: conservative fallback | blocked | blocked | layer2-llm | RED |
| AA-D1 | auditor injection (Layer-2) | blocked | blocked | layer2-llm | RED |
| AA-D2 | auditor injection (indirect) | blocked | blocked | layer2-llm | RED |
| AA-D3 | auditor injection (content override) | ALLOWED | blocked | layer2-llm | RED |
| AA-E1 | P3: minimum group size | ALLOWED | blocked | layer1-red | — |
| AA-E2 | P3: per-record operator | blocked | blocked | layer1-red | — |
| AA-E3 | P3: minimum group size | ALLOWED | blocked | layer1-red | — |

## Table S6 — Overhead measurements

Machine: cpu=Intel(R) Xeon(R) Gold 6148 CPU @ 2.40GHz, n_cpu=80, mem_gb=125.5, os=Linux-6.8.0-41-generic-x86_64-with-glibc2.39, python=3.13.5

| Measurement | n | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|
| Scope bucket (component + context budget) | 2000 | 0.0219 | 0.0389 | 0.0438 |
| Layer-1 audit (pattern + k-anonymity + target) | 2000 | 0.0107 | 0.0393 | 0.0454 |
| Token issuance (HMAC-SHA256) | 2000 | 0.0134 | 0.0142 | 0.0240 |
| Integrated AdaptiveCap per call (Layer-2 disabled) | 800 | 0.0276 | 0.0323 | 0.0899 |
| Integrated ChainCaps per call (same machine) | 800 | 0.0160 | 0.0173 | 0.0193 |
| Layer-2 LLM (live API, cache disabled) | 30 | 2004.7 | 3073.8 | 4145.0 |

Expected cost: 444.4 ms per tool call at the measured trigger rate 20.85%.

