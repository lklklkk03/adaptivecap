"""Experiment 0 — Supplementary per-scenario / per-call export (W1).

Reads the stored experiment reports and emits the two tables that make every
aggregate figure in the paper recomputable:

  * ``reports/exp0_per_scenario.{csv,md}`` — one row per scenario: ID,
    subset, ground-truth label, and each system's outcome (attack blocked /
    benign completed), plus the step-level false-positive count and the
    auditor verdict tally (GREEN/RED/YELLOW).
  * ``reports/exp0_per_call.csv`` — one row per tool call (scenario, step,
    tool, expected, allowed, budget authorization, audit verdict, deciding
    layer) for both ElasticCap and ChainCaps.

It also runs a *reconciliation pass*: it recomputes every headline aggregate
from the per-scenario table and reports any figure in the paper that cannot
be derived from the stored data. That check is the acceptance criterion for
the revision's number-consistency work.

Usage::

    python experiments/exp0_export.py [--reports DIR] [--out DIR]
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from experiments.reports import markdown_table  # noqa: E402


def _load(reports_dir: Path, name: str) -> Optional[Dict]:
    p = reports_dir / f"{name}.json"
    if not p.exists():
        return None
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def _safe_name(name: str, limit: int = 70) -> str:
    return name[:limit].replace("|", "/")


_ABLATION_IDS = None


def _ablation_ids() -> set:
    """Scenario IDs of the exp5 ablation subset (FP + SC + G1 subset).

    Mirrors ``exp5_ablation.main``'s assembly exactly (fps + scs +
    ``_subset_group1(20)``) so the S1 ``ablation`` tag identifies precisely
    the 46 scenarios the ablation study ran.
    """
    global _ABLATION_IDS
    if _ABLATION_IDS is None:
        from experiments.exp5_ablation import _subset_group1
        from experiments.scenarios import (
            load_raid_v3_group4_fps, build_scope_crossing_scenarios,
        )
        members = (list(load_raid_v3_group4_fps())
                   + list(build_scope_crossing_scenarios())
                   + list(_subset_group1(20)))
        _ABLATION_IDS = {s.task_id for s in members}
    return _ABLATION_IDS


def build_per_scenario_rows(exp1: Dict, exp7: Optional[Dict]) -> List[Dict]:
    """Merge exp1 (EC/ChainCaps) and exp7 (baselines) per-scenario data."""
    rows: Dict[str, Dict] = {}

    def _row(entry: Dict, engine: str) -> Dict:
        nb = entry.get("notebook") or {}
        tid = nb.get("task_id") or entry["name"].split(":")[0].strip()
        row = rows.setdefault(tid, {
            "scenario_id": tid,
            "scenario": entry["name"],
            "subset": nb.get("subset", ""),
            "task_type": entry["task_type"],
            "n_steps": len(entry["outcomes"]),
            "attack_step": entry.get("attack_step"),
        })
        systems = row.setdefault("systems", {})
        systems[engine] = {
            "effect": ("blocked" if entry.get("attack_blocked") else
                       "allowed") if entry["task_type"] == "adversarial"
                      else ("completed" if entry.get("benign_completed") else "failed"),
            "attack_blocked": entry.get("attack_blocked"),
            "benign_completed": entry.get("benign_completed"),
            "fp_steps": entry.get("fp"),
            "fn": entry.get("fn"),
            "green": nb.get("auditor_green"),
            "red": nb.get("auditor_red"),
            "yellow": nb.get("auditor_yellow"),
            "outcomes": "".join("T" if o else "F" for o in entry["outcomes"]),
            "expected": "".join("T" if o else "F" for o in entry["expected"]),
        }
        return row

    for entry in exp1.get("per_scenario_elasticap", []):
        _row(entry, "AdaptiveCap")
    for entry in exp1.get("per_scenario_chaincaps", []):
        _row(entry, "ChainCaps")
    if exp7:
        for engine, entries in (exp7.get("per_scenario") or {}).items():
            for entry in entries:
                _row(entry, engine)
    abl = _ablation_ids()
    for tid, row in rows.items():
        row["ablation"] = "yes" if tid in abl else ""
    return [rows[k] for k in sorted(rows)]


def build_per_call_rows(exp1: Dict) -> List[Dict]:
    return exp1.get("per_call", [])


def recompute_aggregates(rows: List[Dict]) -> Dict:
    """Recompute each headline aggregate from the per-scenario table."""
    systems = sorted({s for r in rows for s in r["systems"]})
    out: Dict[str, Dict] = {}
    for sysname in systems:
        adv = [r for r in rows if r["task_type"] == "adversarial"
               and sysname in r["systems"]]
        ben = [r for r in rows if r["task_type"] == "benign"
               and sysname in r["systems"]]
        blocked = sum(1 for r in adv if r["systems"][sysname]["attack_blocked"])
        completed = sum(1 for r in ben if r["systems"][sysname]["benign_completed"])
        fps = sum(r["systems"][sysname]["fp_steps"] or 0 for r in ben)
        fns = sum(1 for r in adv if r["systems"][sysname]["fn"])
        out[sysname] = {
            "n_attack": len(adv),
            "n_benign": len(ben),
            "attacks_blocked": blocked,
            "benign_completed": completed,
            "abr": blocked / len(adv) if adv else 0.0,
            "bcr": completed / len(ben) if ben else 0.0,
            "fp_steps": fps,
            "fn": fns,
        }
    return out


def reconcile(rows: List[Dict], exp1: Dict, exp7: Optional[Dict],
              exp5: Optional[Dict] = None) -> List[Dict]:
    """Compare recomputed aggregates against every stored/reported figure."""
    recomputed = recompute_aggregates(rows)
    checks: List[Dict] = []

    def _check(label: str, claimed, actual, source: str):
        ok = (claimed == actual)
        checks.append({
            "figure": label, "claimed": claimed, "recomputed": actual,
            "source": source, "match": ok,
        })

    ec = recomputed.get("AdaptiveCap", {})
    cc = recomputed.get("ChainCaps", {})
    _check("ABR AdaptiveCap", exp1["elasticap"]["attack_block_rate"],
           round(ec.get("abr", 0), 4), "exp1.json vs per-scenario table")
    _check("BCR AdaptiveCap", exp1["elasticap"]["benign_completion_rate"],
           round(ec.get("bcr", 0), 4), "exp1.json vs per-scenario table")
    _check("FP steps AdaptiveCap", exp1["elasticap"]["false_positives"],
           ec.get("fp_steps"), "exp1.json vs per-scenario table")
    _check("ABR ChainCaps", exp1["chaincaps"]["attack_block_rate"],
           round(cc.get("abr", 0), 4), "exp1.json vs per-scenario table")
    _check("BCR ChainCaps", exp1["chaincaps"]["benign_completion_rate"],
           round(cc.get("bcr", 0), 4), "exp1.json vs per-scenario table")
    _check("FP steps ChainCaps", exp1["chaincaps"]["false_positives"],
           cc.get("fp_steps"), "exp1.json vs per-scenario table")
    if exp7:
        for sysname, metrics in (exp7.get("metrics") or {}).items():
            r = recomputed.get(sysname)
            if not r:
                continue
            _check(f"ABR {sysname} (exp7)", metrics["attack_block_rate"],
                   round(r["abr"], 4), "exp7.json vs per-scenario table")
            _check(f"BCR {sysname} (exp7)", metrics["benign_completion_rate"],
                   round(r["bcr"], 4), "exp7.json vs per-scenario table")
    if exp5:
        abl = [r for r in rows if r.get("ablation") == "yes"]
        abl_benign = [r for r in abl if r["task_type"] == "benign"]
        full_m = (exp5.get("metrics") or {}).get("Full") or {}
        _check("Ablation subset size (exp5)", exp5.get("n_scenarios"),
               len(abl), "exp5.json vs S1 ablation tag")
        _check("Ablation benign scenarios (exp5)",
               full_m.get("benign_scenarios"), len(abl_benign),
               "exp5.json vs S1 ablation tag")
    return checks


def write_csv(path: Path, rows: List[Dict], fields: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def write_markdown(path: Path, rows: List[Dict], systems: List[str],
                   checks: List[Dict]) -> None:
    lines = ["# Supplementary Table S1 — Per-scenario results\n",
             "Ground truth: `task_type` (benign / adversarial). `Outcome` is "
             "the scenario-level verdict; `FP` counts benign *steps* wrongly "
             "blocked (step-level), `Audits` is the auditor verdict tally "
             "(GREEN/RED/YELLOW). `ablation=yes` marks the 46-scenario "
             "ablation subset of Section 5.7 (9 FP + 14 SC + 20 "
             "G1-adversarial + 3 G1-benign). All aggregate figures in the "
             "paper are derivable from this table.\n",
             ""
             ]
    header = ["scenario_id", "subset", "ablation", "ground_truth", "steps",
              "attack_step"]
    for s in systems:
        header += [f"{s}:outcome", f"{s}:FP_steps", f"{s}:audits"]
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join(["---"] * len(header)) + "|")
    for r in rows:
        cells = [r["scenario_id"], r["subset"], r["ablation"],
                 r["task_type"], str(r["n_steps"]), str(r["attack_step"])]
        for s in systems:
            d = r["systems"].get(s)
            if not d:
                cells += ["—", "—", "—"]
            else:
                audits = ("—" if d.get("green") is None
                          else f"{d['green']}/{d['red']}/{d['yellow']}")
                cells += [d["effect"], str(d["fp_steps"]), audits]
        lines.append("| " + " | ".join(cells) + " |")

    lines += ["\n## Reconciliation — every aggregate derivable from S1\n",
              "| Figure | Stored value | Recomputed from S1 | Match | Source |",
              "|---|---|---|---|---|"]
    for c in checks:
        mark = "✅" if c["match"] else "❌"
        lines.append(f"| {c['figure']} | {c['claimed']} | {c['recomputed']} | "
                     f"{mark} | {c['source']} |")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Export supplementary tables (W1)")
    ap.add_argument("--reports", default=str(
        Path(__file__).resolve().parent / "reports"))
    ap.add_argument("--out", default=None,
                    help="output directory (defaults to --reports)")
    args = ap.parse_args(argv)

    reports_dir = Path(args.reports)
    out_dir = Path(args.out) if args.out else reports_dir

    exp1 = _load(reports_dir, "exp1_baseline")
    if exp1 is None:
        print(f"exp1_baseline.json not found in {reports_dir}", file=sys.stderr)
        return 1
    exp7 = _load(reports_dir, "exp7_baselines")
    exp5 = _load(reports_dir, "exp5_ablation")

    rows = build_per_scenario_rows(exp1, exp7)
    systems = sorted({s for r in rows for s in r["systems"]})
    checks = reconcile(rows, exp1, exp7, exp5)

    scenario_fields = ["scenario_id", "scenario", "subset", "ablation",
                       "task_type", "n_steps", "attack_step"]
    for s in systems:
        scenario_fields += [f"{s}_outcome", f"{s}_fp_steps", f"{s}_audits"]
    flat_rows = []
    for r in rows:
        flat = {k: r[k] for k in ("scenario_id", "scenario", "subset",
                                  "ablation", "task_type", "n_steps",
                                  "attack_step")}
        for s in systems:
            d = r["systems"].get(s) or {}
            flat[f"{s}_outcome"] = d.get("effect", "")
            flat[f"{s}_fp_steps"] = d.get("fp_steps", "")
            flat[f"{s}_audits"] = ("" if d.get("green") is None
                                   else f"{d['green']}/{d['red']}/{d['yellow']}")
        flat_rows.append(flat)

    write_csv(out_dir / "exp0_per_scenario.csv", flat_rows, scenario_fields)
    write_markdown(out_dir / "exp0_per_scenario.md", rows, systems, checks)

    per_call = build_per_call_rows(exp1)
    if per_call:
        write_csv(out_dir / "exp0_per_call.csv", per_call,
                  list(per_call[0].keys()))

    print(f"Wrote {out_dir / 'exp0_per_scenario.csv'} ({len(rows)} scenarios)")
    print(f"Wrote {out_dir / 'exp0_per_scenario.md'}")
    if per_call:
        print(f"Wrote {out_dir / 'exp0_per_call.csv'} ({len(per_call)} calls)")
    bad = [c for c in checks if not c["match"]]
    if bad:
        print(f"\n{len(bad)} reconciliation MISMATCH(es):")
        for c in bad:
            print(f"  - {c['figure']}: stored={c['claimed']} "
                  f"recomputed={c['recomputed']}")
        return 2
    print(f"\nAll {len(checks)} aggregate figures reconciled against S1.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
