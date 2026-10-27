"""Measurement-stability correction for the real-LLM run (revision record).

During the run, two audit calls received empty completions from the provider
(43.8 s and 47.1 s responses with no content). The client recorded them as
``YellowSentinel`` -> YELLOW escalations, which enter the metrics as if the
model had judged them. Both affected scenarios are identified here by their
audit prompt hash, re-queried with the fixed client (which now retries on an
empty completion instead of escalating), and the corrected outcomes and
headline metrics are written to ``reports/exp1c_measurement_correction.json``.

The correction is reported, not applied silently: the paper cites it in the
errata, and the corrected figures are the ones used there.

Usage::
    python experiments/measurement_stability_correction.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .reports import REPORTS_DIR, aggregate_outcomes, write_report, markdown_table
from .engines_adapter import run_elasticap
from .exp1_baseline import _to_result
from .scenarios import (
    load_raid_v3_group4_fps, build_scope_crossing_scenarios, load_raid_v3_group1,
)
from .llm_auditor import build_auditor  # noqa: F401  (constructs the audit log)
from adaptivecap.llm_client import make_llm_classifier, YellowSentinel

# Scenario ids whose audit decisions were affected (identified from the
# archived audit-log snapshot by raw_verdict == "YellowSentinel").
AFFECTED = ["FP-09", "G1-076"]


def _scenarios():
    fps = load_raid_v3_group4_fps()
    scs = build_scope_crossing_scenarios()
    g1 = load_raid_v3_group1()
    fp_ids = {s.task_id for s in fps}
    sc_ids = {s.task_id for s in scs}
    g1d = [s for s in g1 if s.task_id not in fp_ids and s.task_id not in sc_ids]
    return fps + scs + g1d


def main(prefer_deepseek: bool = True) -> Dict:
    print("=" * 72)
    print("Measurement-stability correction (empty completions)")
    print("=" * 72)
    scenarios = _scenarios()
    affected = [s for s in scenarios if s.task_id in AFFECTED]
    print(f"Re-querying {len(affected)} affected scenario(s) with the fixed "
          f"retry-on-empty client ...")

    # Build an auditor whose classifier retries empty completions (the fixed
    # client) and records the raw verdict for each decision.
    base = make_llm_classifier()
    raw_log: List[str] = []

    def recording(prompt: str):
        v = base(prompt)
        raw_log.append("YellowSentinel" if isinstance(v, YellowSentinel) else str(v))
        return v

    from adaptivecap.auditor import DeclassificationAuditor
    aud = DeclassificationAuditor(signing_key=b"exp1c-32-byte-hmac-signing-key",
                                 llm_classifier=recording)

    corrections = []
    for s in affected:
        out = run_elasticap(s, auditor=aud)
        res = _to_result(out, s, "elasticap", s.expected_elasticap)
        corrections.append({
            "task_id": s.task_id,
            "name": s.name,
            "task_type": s.task_type,
            "outcomes": out.outcomes,
            "audit_verdicts": [v["verdict"] for v in out.audit_verdicts],
            "raw_verdicts": list(raw_log),
            "benign_completed": res.benign_completed,
        })
        raw_log.clear()
        print(f"  {s.task_id}: outcomes={out.outcomes} "
              f"verdicts={corrections[-1]['audit_verdicts']} "
              f"completed={res.benign_completed}")

    # Apply the corrected outcomes to exp1's per-scenario results and
    # recompute the headline metrics.
    exp1 = json.loads((REPORTS_DIR / "exp1_baseline.json").read_text())
    per = {r["notebook"]["task_id"]: r for r in exp1["per_scenario_elasticap"]}
    changes = []
    for c in corrections:
        old = per[c["task_id"]]
        old_verdicts = [v for _s, v in old["notebook"]["audits"]]
        if list(old["outcomes"]) != list(c["outcomes"]) or old["benign_completed"] != c["benign_completed"]:
            changes.append({
                "task_id": c["task_id"],
                "old_outcomes": old["outcomes"],
                "new_outcomes": c["outcomes"],
                "old_completed": old["benign_completed"],
                "new_completed": c["benign_completed"],
                "old_verdicts": old_verdicts,
            })

    # Recompute metrics from exp1's reported outcomes with the corrections.
    from .reports import ScenarioResult
    results = []
    for r in exp1["per_scenario_elasticap"]:
        tid = r["notebook"]["task_id"]
        local = r
        for c in corrections:
            if c["task_id"] == tid:
                local = dict(r)
                local["outcomes"] = c["outcomes"]
                local["benign_completed"] = c["benign_completed"]
        results.append(ScenarioResult(
            name=local["name"], task_type=local["task_type"],
            category=local["category"], engine="elasticap",
            outcomes=local["outcomes"], expected=local["expected"],
            attack_step=local["attack_step"],
            attack_blocked=local["attack_blocked"],
            benign_completed=local["benign_completed"],
            fp=local["fp"], fn=local["fn"], notebook=local["notebook"]))
    m = aggregate_outcomes(results, "elasticap-corrected")

    md = ["# Measurement-stability correction\n",
          "Two audit calls received empty provider completions during the run "
          "(43.8 s and 47.1 s), which the wrapper recorded as YELLOW "
          "escalations. The affected scenarios are re-queried with the fixed "
          "client (retry on empty completion) and the corrected outcomes are "
          "reported here; the paper cites these corrected figures.\n",
          markdown_table(["Scenario", "Raw verdict (run)", "Verdict (re-query)",
                          "Completed (run)", "Completed (corrected)"],
                         [[c["task_id"], "YellowSentinel",
                           ", ".join(c["audit_verdicts"]) or "none",
                           str(per[c["task_id"]]["benign_completed"]),
                           str(c["benign_completed"])] for c in corrections]),
          "",
          f"Corrected headline metrics: ABR {m.attack_block_rate:.1%} "
          f"({m.attacks_blocked}/{m.attack_scenarios}), BCR "
          f"{m.benign_completion_rate:.1%} ({m.benign_completed}/"
          f"{m.benign_scenarios}), FP (step) {m.false_positives}, FN "
          f"{m.false_negatives}.\n",
          ]

    payload = {
        "affected": AFFECTED,
        "corrections": corrections,
        "changes": changes,
        "corrected_metrics": m.to_dict(),
        "note": ("The correction affects at most two benign scenarios; attack "
                 "blocking is unaffected (a YELLOW escalation and a RED both "
                 "block)."),
    }
    j, p = write_report("exp1c_measurement_correction", payload, "\n".join(md))
    print(f"\nReport: {p}")
    return payload


if __name__ == "__main__":
    main()
