#!/usr/bin/env python3
"""Fix the ``subset`` metadata label in a run report (presentation-only).

Background: ``exp1_baseline.py`` labels each scenario with a subset tag. An
earlier revision of that label used only the ``task_id`` prefix, so the 50
realistic-workflow scenarios loaded through ``load_raid_v3_group1`` (ids
``G1-nnn``, names ``RW-...``) were tagged ``G1``. The current code tags them
``realistic`` by name. This script rewrites the stored label so the archived
report matches what the current code produces. It touches metadata only ---
no outcome, no metric, no expected value --- and prints every change.

Usage::
    python fix_subset_labels.py [--reports DIR] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict


def _load(reports: Path, name: str):
    p = reports / f"{name}.json"
    if not p.exists():
        return None, None
    return json.loads(p.read_text()), p


def fix(reports: Path, dry_run: bool = False) -> int:
    changed = 0
    for fname in ("exp1_baseline", "exp7_baselines", "exp5_ablation",
                  "exp2_root_cause", "exp3_scope_crossing"):
        data, path = _load(reports, fname)
        if data is None:
            continue
        n_fixed = 0

        def _fix_list(entries):
            k = 0
            for r in entries or []:
                if not isinstance(r, dict):
                    continue
                nb = r.get("notebook")
                if isinstance(nb, dict) and nb.get("subset") == "G1" \
                        and str(r.get("name", "")).startswith("RW-"):
                    nb["subset"] = "realistic"
                    k += 1
            return k

        for field in [k for k in data if k.startswith("per_scenario")]:
            value = data[field]
            if isinstance(value, dict):          # exp7: {system: [entries]}
                for entries in value.values():
                    n_fixed += _fix_list(entries)
            else:                                 # exp1: [entries]
                n_fixed += _fix_list(value)
        # realistic_workflows block (exp7)
        rw = data.get("realistic_workflows") or {}
        for entries in (rw.get("per_scenario") or {}).values():
            n_fixed += _fix_list(entries)
        if n_fixed:
            changed += n_fixed
            print(f"  {fname}: {n_fixed} labels G1 -> realistic")
            if not dry_run:
                path.write_text(json.dumps(data, indent=2, ensure_ascii=False,
                                           default=str), encoding="utf-8")
    print(f"total labels fixed: {changed}{' (dry run)' if dry_run else ''}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default=str(
        Path(__file__).resolve().parent / "reports"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    return fix(Path(args.reports), args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
