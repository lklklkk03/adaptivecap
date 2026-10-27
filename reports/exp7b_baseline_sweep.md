# Experiment 7b — Baseline Configuration Sweep

- Scenario set: 151 (FP + SC + G1, identical to Tables 1-3)
- All baselines receive oracle-level label/taint assignment derived from the ground-truth budgets, i.e. the assignment most favourable to each baseline.

## Fides

| Setting | ABR | BCR | FP (step) | FN |
|---|---|---|---|---|
| default (oracle-inferred) | 40.6% | 80.0% | 11 | 57 |
| all sources INTERNAL (strict) | 40.6% | 74.5% | 14 | 57 |
| all sources PUBLIC (lax) | 3.1% | 81.8% | 10 | 93 |

## PFI

| Setting | ABR | BCR | FP (step) | FN |
|---|---|---|---|---|
| blocked_tools={} | 4.2% | 74.5% | 23 | 92 |
| blocked_tools=['execute_shell', 'shell_exec'] | 15.6% | 74.5% | 23 | 81 |
| blocked_tools=['email_send', 'fetch_url', 'filesystem_write', 'github_create_issue', 'github_create_pr', 'memory_store', 'send_email', 'send_http', 'shell_exec', 'slack_post_message', 'write_file'] | 88.5% | 16.4% | 71 | 11 |
| blocked_tools=['execute_shell', 'github_create_issue', 'github_create_pr', 'shell_exec'] | 24.0% | 72.7% | 25 | 73 |

## CoarseTaint

| Setting | ABR | BCR | FP (step) | FN |
|---|---|---|---|---|
| default (oracle-inferred) | 79.2% | 56.4% | 24 | 20 |
| all sources INTERNAL (strict) | 37.5% | 89.1% | 6 | 60 |
| all sources SENSITIVE (strictest) | 82.3% | 40.0% | 33 | 17 |
| all sources PUBLIC (lax) | 2.1% | 100.0% | 0 | 94 |

## ChainCaps

| Setting | ABR | BCR | FP (step) | FN |
|---|---|---|---|---|
| default (ground-truth manifests) | 97.9% | 56.4% | 14 | 2 |
| all sources unrestricted (upper bound) | 9.4% | 100.0% | 0 | 87 |

## Reported configuration

| System | Reported setting | ABR | BCR [95% CI] | FP (step) |
|---|---|---|---|---|
| AdaptiveCap | full (scope + auditor + recovery, P3 revised) | 97.9% | 98.2% [94.5%, 100.0%] | 1 |
| ChainCaps | default (ground-truth manifests, global budget) | 97.9% | 56.4% [41.8%, 70.9%] | 14 |

Paired McNemar (per-scenario correctness, AdaptiveCap vs ChainCaps): discordant 23 (AdaptiveCap-only 23, ChainCaps-only 0), exact p = 2.38e-07.
