"""Package the supplementary material (Tables S1–S4) from the run reports.

Produces, in the output directory:

  * ``Supplementary_Material.md``  — Tables S1 (per scenario), S2 (per call
    summary), S3 (baseline configuration sweep + RW annotation diagnosis),
    S4 (realistic-workflow composition and the annotation upper bound), plus
    the provenance note tying every main-text table to its experiment.
  * ``Table_S1_per_scenario.csv``  — machine-readable per-scenario results.
  * ``Table_S2_per_call.csv``      — machine-readable per-call decisions.

Usage::

    python experiments/pack_supplementary.py [--reports DIR] [--out DIR]
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional

REPORTS_DEFAULT = Path(__file__).resolve().parent / "reports"



# ---------------------------------------------------------------------------
# Table S7 — fidelity of the re-implemented baselines
# ---------------------------------------------------------------------------

BASELINE_FIDELITY = [
    {
        "baseline": "Fides",
        "original": "Information-flow control for agent tool calls with "
                    "confidentiality/integrity labels and flow checks "
                    "(as described in the cited work).",
        "ours": "Three-level confidentiality {PUBLIC, INTERNAL, SECRET} x "
                "two-level integrity {UNTRUSTED, TRUSTED}; a sink is allowed "
                "iff conf(data) <= conf(sink) and integ(data) >= integ(sink); "
                "labels for each source are inferred from its ground-truth "
                "budget, i.e. oracle-level assignment.",
        "deviation": "Label assignment is oracle-level (generous to the "
                     "baseline); a scalar label cannot express a per-sink "
                     "subset, which is the representational limit the paper "
                     "reports.",
        "verification": "Description-level only: no released implementation "
                        "was available in our environment to cross-check "
                        "behaviour, and no author confirmation was obtained.",
    },
    {
        "baseline": "PFI",
        "original": "Per-function (per-tool) isolation to prevent privilege "
                    "escalation; each tool call is authorized independently.",
        "ours": "A static permission set per tool; a call is allowed iff the "
                "tool's set covers it. No cross-tool data-flow tracking; a "
                "blocked-tool set is exposed as the tuning knob (Table S3).",
        "deviation": "No LLM-mediated authorization step and no planner "
                     "split; the model is the tool-permission table itself, "
                     "which is the property that makes the 4.2% ABR a "
                     "structural result rather than a tuning artefact.",
        "verification": "Description-level only (see Fides).",
    },
    {
        "baseline": "CoarseTaint",
        "original": "The coarse provenance taint (CPT) baseline shipped in "
                    "the released ChainCaps artifact and run in its own "
                    "evaluation (registered as \u201cCPT\u201d in the upstream "
                    "raid_v3 harness). No standalone publication exists.",
        "ours": "The upstream CoarseTaintBaseline executed unmodified: "
                "three-level provenance taint "
                "PUBLIC < INTERNAL < SENSITIVE with join = max, per-sink "
                "block thresholds, and optional resource-pattern escalation.",
        "deviation": "None \u2014 the upstream implementation is executed "
                     "unmodified. The submission\u2019s description of it as a "
                     "self-implemented baseline was an error, corrected in "
                     "the Errata.",
        "verification": "Identity by construction (we execute the upstream "
                        "class itself), with its upstream default "
                        "configuration; no independent author confirmation "
                        "beyond the artifact itself.",
    },
    {
        "baseline": "NoDefense",
        "original": "Not a published system; an unconditional allow-all "
                    "lower bound for the security axis.",
        "ours": "Allow every call.",
        "deviation": "None (it is defined by its behaviour).",
        "verification": "Not applicable.",
    },
    {
        "baseline": "ChainCaps",
        "original": "Monotonic capability attenuation with a global context "
                    "budget (the system this paper extends).",
        "ours": "NOT a re-implementation: the pipeline executes the upstream "
                "implementation from the cited repository "
                "(chaincaps.proxy.engine.ChainCapsEngine) unmodified, with "
                "ground-truth source budgets translated into its budget type.",
        "deviation": "None in the engine; the only adaptation is the "
                     "budget-type translation layer, which is exercised by "
                     "every baseline run identically.",
        "verification": "Behaviour cross-checked against the upstream "
                        "repository's own recorded benchmark results, which "
                        "the repository ships (raid_v3 results) - the ABR/FP "
                        "values that repository records for its FP set "
                        "reproduce in our harness.",
    },
]


def _fidelity_table() -> str:
    headers = ["Baseline", "Mechanism in the cited work", "Our implementation",
               "Known deviations", "Independent verification"]
    rows = [[b["baseline"], b["original"], b["ours"], b["deviation"],
             b["verification"]] for b in BASELINE_FIDELITY]
    return "\n".join(["| " + " | ".join(headers) + " |",
                      "|" + "|".join(["---"] * len(headers)) + "|"]
                     + ["| " + " | ".join(str(c) for c in r) + " |"
                        for r in rows])


def _load(reports: Path, name: str) -> Optional[Dict]:
    p = reports / f"{name}.json"
    return json.loads(p.read_text()) if p.exists() else None


def _md_table(headers: List[str], rows: List[List[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join(["---"] * len(headers)) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


def _rw_composition(exp9: Dict) -> str:
    d = exp9["description"]
    lines = [_md_table(
        ["Quantity", "Value"],
        [["Provenance", d["source"]],
         ["Scenarios", str(d["n_scenarios"])],
         ["Attack / benign", f"{d['n_attacks']} / {d['n_benign']}"],
         ["Tool calls", str(d["total_steps"])],
         ["Distinct tool chains", str(d["distinct_tool_chains"])],
         ["Scenarios with declared source budgets",
          str(d["scenarios_with_declared_source_budgets"])]])]
    lines.append("\n**Tool chains.**\n")
    lines.append(_md_table(
        ["Tool chain", "Scenarios"],
        [[k, str(v)] for k, v in sorted(d["tool_chain_counts"].items(),
                                        key=lambda kv: -kv[1])]))
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default=str(REPORTS_DEFAULT))
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)
    reports = Path(args.reports)
    out = Path(args.out) if args.out else reports / "supplementary"
    out.mkdir(parents=True, exist_ok=True)

    exp1 = _load(reports, "exp1_baseline")
    exp7b = _load(reports, "exp7b_baseline_sweep")
    exp8 = _load(reports, "exp8_adaptive")
    exp9 = _load(reports, "exp9_rw_diagnosis")
    exp6 = _load(reports, "exp6_overhead")
    if exp1 is None:
        print("exp1_baseline.json is required (run exp1 first)", file=sys.stderr)
        return 1

    # Copy the CSVs produced by exp0_export (which may have written them
    # into `out` already; fall back to `reports` for the postprocess flow).
    for src_name, dst_name in (("exp0_per_scenario.csv", "Table_S1_per_scenario.csv"),
                               ("exp0_per_call.csv", "Table_S2_per_call.csv")):
        src = reports / src_name
        if not src.exists():
            src = out / src_name
        if src.exists():
            shutil.copyfile(src, out / dst_name)

    md: List[str] = ["# AdaptiveCap — Supplementary Material\n",
                     "Every aggregate figure in the manuscript is derivable "
                     "from Table S1 (per scenario) and Table S2 (per call). "
                     "All data come from the single end-to-end run described "
                     "in Section 5.1 of the paper; the run manifest "
                     "(classifier, cache state, patch flags, machine) is "
                     "archived with the reports.\n",
                     "## Provenance of main-text artifacts\n",
                     _md_table(
                         ["Artifact", "Experiment", "Classifier", "Cache"],
                         [["Tables 2–3, Figure 2", "exp1", "DeepSeek V4 Pro", "on"],
                          ["Table 7 (call accounting)", "exp1", "DeepSeek V4 Pro", "on"],
                          ["Table 4, Figure 4 (overhead, hot path)", "exp6", "none", "n/a"],
                          ["Table 4, Figure 4 (overhead, LLM path)", "exp6", "DeepSeek V4 Pro", "off"],
                          ["Table 5 (adaptive attacks)", "exp8", "DeepSeek V4 Pro", "on"],
                          ["Table 6, Figure 5 (baselines)", "exp7", "DeepSeek V4 Pro", "on"],
                          ["Figure 3 (ablation)", "exp5", "DeepSeek V4 Pro", "on"],
                          ["SC-C2 verdict log", "exp3", "DeepSeek V4 Pro", "on"],
                          ["Regression tests", "test suite", "mock", "n/a"]]),
                     "\n## Table S1 — Per-scenario results\n",
                     "See `Table_S1_per_scenario.csv`. Columns: `scenario_id`, "
                     "`scenario`, `subset` (FP / SC-A / SC-B / SC-C / G1 / "
                     "realistic), `ablation` (yes = member of the 46-scenario "
                     "ablation subset of Section 5.7), `task_type` (ground "
                     "truth), `n_steps`, `attack_step`, and per system the "
                     "outcome, the step-level false-positive count and the "
                     "auditor tally (GREEN/RED/YELLOW).\n",
                     "## Table S2 — Per-call decisions\n",
                     "See `Table_S2_per_call.csv`. One row per tool call for "
                     "AdaptiveCap and ChainCaps with the budget decision, the "
                     "audit verdict, the deciding layer and the expected "
                     "outcome. This table contains the SC-C2 Layer-2 verdict "
                     "log cited in Section 5.5.\n"]

    if exp7b:
        md += ["## Table S3a — Baseline configuration sweep\n",
               "Knobs swept per re-implemented baseline; the configuration "
               "used in the headline table is the default (oracle-inferred) "
               "setting, which the sweep shows is the most favourable on BCR "
               "at or above the default ABR.\n"]
        for system, rows in exp7b["sweep"].items():
            md.append(f"\n**{system}**\n")
            md.append(_md_table(
                ["Setting", "ABR", "BCR", "FP (step)", "FN"],
                [[r["setting"], f"{r['abr']:.1%}", f"{r['bcr']:.1%}",
                  str(r["fp"]), str(r["fn"])] for r in rows]))
        sig = (exp7b.get("significance") or {})
        if sig:
            md.append(f"\nPaired McNemar (AdaptiveCap vs ChainCaps): "
                      f"discordant {sig['n_discordant']}, p = "
                      f"{sig['p_value']:.2e}.\n")

    if exp9:
        md += ["\n## Table S3b — Annotation availability and the upper bound "
               "(50 realistic scenarios)\n",
               _md_table(
                   ["Variant", "System", "ABR", "BCR", "BCR 95% CI", "FP (step)"],
                   [[v["label"], s,
                     f"{v[s]['abr']:.1%}", f"{v[s]['bcr']:.1%}",
                     f"[{v[s]['ci']['bcr'][1]:.1%}, {v[s]['ci']['bcr'][2]:.1%}]",
                     str(v[s]["fp"])]
                    for v in exp9["variants"] for s in ("ElasticCap", "ChainCaps")]),
               f"\nAnnotation availability: "
               f"{exp9['annotation_availability']['scenarios_without_annotation']}"
               f" of {exp9['description']['n_scenarios']} scenarios carry no "
               f"explicit dependency annotation "
               f"({exp9['annotation_availability']['annotated_steps']} of "
               f"{exp9['annotation_availability']['total_steps']} steps).\n",
               "Variant `deps-annotated` reconstructs the true data flow; "
               "`deps+sink-scopes` additionally declares each legitimate "
               "sink's target scope (attack sinks are deliberately not "
               "declared).\n",
               "\n## Table S4 — Composition of the 50 realistic scenarios\n",
               _rw_composition(exp9)]

    if exp8:
        md += ["\n## Table S5 — Adaptive attack outcomes\n",
               _md_table(
                   ["Attack", "Mechanism targeted", "Pre-revision", "Revised",
                    "Deciding layer", "Layer-2 raw verdict"],
                   [[r["task_id"], r["mechanism"],
                     "blocked" if b["blocked"] else "ALLOWED",
                     "blocked" if r["blocked"] else "ALLOWED",
                     r.get("audit_decided_by") or "budget",
                     r.get("llm_raw_verdict") or "—"]
                    for r, b in zip(
                        exp8["after"]["rows"],
                        exp8["before"]["rows"])])]

    md += ["\n## Table S7 — Fidelity of the re-implemented baselines\n",
           "We state the mechanism described in the cited work, what we "
           "implemented, the known deviations, and whether independent "
           "verification (released code or author confirmation) was possible; "
           "for Fides and PFI it was not, which is itself reported as a "
           "limitation. ChainCaps and CoarseTaint are not re-implementations: "
           "the upstream engine and the upstream coarse provenance taint "
           "(CPT) baseline from the released ChainCaps artifact are executed "
           "unmodified.\n",
           _fidelity_table()]

    if exp6:
        md += ["\n## Table S6 — Overhead measurements\n",
               "Machine: " + ", ".join(
                   f"{k}={v}" for k, v in exp6["machine"].items()) + "\n"]
        rows = []
        for key in ("scope_bucket", "layer1", "token", "integrated"):
            r = exp6["hot_path"][key]
            rows.append([r["name"], str(r["n"]), f"{r['p50_ms']:.4f}",
                         f"{r['p95_ms']:.4f}", f"{r['p99_ms']:.4f}"])
        ch = exp6["chaincaps"]["integrated"]
        rows.append([ch["name"], str(ch["n"]), f"{ch['p50_ms']:.4f}",
                     f"{ch['p95_ms']:.4f}", f"{ch['p99_ms']:.4f}"])
        llm = exp6.get("llm_path") or {}
        if llm.get("n"):
            rows.append([llm["name"], str(llm["n"]), f"{llm['p50_ms']:.1f}",
                         f"{llm['p95_ms']:.1f}", f"{llm['p99_ms']:.1f}"])
        md.append(_md_table(["Measurement", "n", "p50 (ms)", "p95 (ms)",
                             "p99 (ms)"], rows))
        if exp6.get("amortized"):
            a = exp6["amortized"]
            md.append(f"\nExpected cost: {a['expected_ms_per_call']:.1f} ms per "
                      f"tool call at the measured trigger rate "
                      f"{a['trigger_rate_per_call']:.2%}.\n")

    (out / "Supplementary_Material.md").write_text("\n".join(md) + "\n",
                                                  encoding="utf-8")
    files = sorted(p.name for p in out.glob("*"))
    print(f"Supplementary package written to {out}:")
    for f in files:
        print(f"  - {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
