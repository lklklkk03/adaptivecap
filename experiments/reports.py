"""Metrics aggregation + JSON/Markdown report writers for the experiments.

Tiny but used by all six experiments so their output is uniform:
  * :func:`aggregate_outcomes` — compute ABR / BCR / FPR / FNR / scope switch
    counts from a list of outcomes & metadata.
  * :func:`write_report`       — drop ``reports/expN_*.{json,md}`` files.
  * :func:`load_baseline`      — read ChainCaps v3 results so exp1 can compare
    apples-to-apples without re-running the baseline in every experiment.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .scenarios import _CHAINCAPS_ROOT

REPORTS_DIR = Path(os.environ.get(
    "ELASTICCAP_REPORTS_DIR",
    Path(__file__).resolve().parent / "reports",
))


@dataclass
class Metrics:
    """Top-line metrics for an engine / condition."""
    name: str
    attack_scenarios: int = 0
    benign_scenarios: int = 0
    attacks_blocked: int = 0
    benign_completed: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    scope_switch_count: int = 0
    auditor_green: int = 0
    auditor_red: int = 0
    auditor_yellow: int = 0
    mean_latency_ms: float = 0.0

    @property
    def attack_block_rate(self) -> float:
        return self.attacks_blocked / max(self.attack_scenarios, 1)

    @property
    def benign_completion_rate(self) -> float:
        return self.benign_completed / max(self.benign_scenarios, 1)

    @property
    def false_positive_rate(self) -> float:
        return self.false_positives / max(self.benign_scenarios, 1)

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["attack_block_rate"] = round(self.attack_block_rate, 4)
        d["benign_completion_rate"] = round(self.benign_completion_rate, 4)
        d["false_positive_rate"] = round(self.false_positive_rate, 4)
        return d


@dataclass
class ScenarioResult:
    """Per-scenario decision record consumed by aggregators and reports."""
    name: str
    task_type: str
    category: str
    engine: str
    outcomes: List[bool]
    expected: List[bool]
    attack_step: Optional[int] = None
    attack_blocked: Optional[bool] = None
    benign_completed: Optional[bool] = None
    fp: int = 0   # benign steps wrongly blocked
    fn: int = 0   # attack steps wrongly allowed
    notebook: Dict = field(default_factory=dict)  # extra diag info


def aggregate_outcomes(results: List[ScenarioResult],
                       name: str,
                       track_scope_switch: bool = False) -> Metrics:
    """Aggregate per-scenario results into :class:`Metrics`."""
    m = Metrics(name=name)
    for r in results:
        if r.task_type == "adversarial":
            m.attack_scenarios += 1
            if r.attack_blocked:
                m.attacks_blocked += 1
            if r.attack_step is not None and r.attack_step < len(r.outcomes):
                # FN: attack step allowed when expected False
                if r.outcomes[r.attack_step] and not r.expected[r.attack_step]:
                    m.false_negatives += 1
        else:
            m.benign_scenarios += 1
            if r.benign_completed:
                m.benign_completed += 1
            # FP: any benign step wrongly blocked
            m.false_positives += r.fp
        if r.notebook.get("scope_switch"):
            m.scope_switch_count += 1
        for k, target in (
            ("auditor_green", m.auditor_green),
            ("auditor_red", m.auditor_red),
            ("auditor_yellow", m.auditor_yellow),
        ):
            # mutated via notebook counts below
            pass
        m.auditor_green += int(r.notebook.get("auditor_green", 0))
        m.auditor_red += int(r.notebook.get("auditor_red", 0))
        m.auditor_yellow += int(r.notebook.get("auditor_yellow", 0))
    return m


def write_report(prefix: str,
                 payload: Dict,
                 markdown: str,
                 ) -> Tuple[Path, Path]:
    """Write ``reports/{prefix}.json`` and ``reports/{prefix}.md`` files."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    json_path = REPORTS_DIR / f"{prefix}.json"
    md_path = REPORTS_DIR / f"{prefix}.md"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(markdown)
    return json_path, md_path


def load_baseline() -> Dict:
    """Read the ChainCaps raid_v3 precomputed results, if present."""
    p = _CHAINCAPS_ROOT / "results" / "raid_v3_results.json"
    if not p.exists():
        return {}
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def bootstrap_ci(results: List["ScenarioResult"],
                 n_resamples: int = 1000,
                 seed: int = 42,
                 alpha: float = 0.05) -> Dict[str, List[float]]:
    """Scenario-level bootstrap 95% CI for BCR, ABR and the FP step count.

    Resamples *scenarios* with replacement (the scenario is the unit of
    analysis), recomputes each metric on the resample and reports the
    percentile interval. This is the uncertainty statement used in place of
    the withdrawn multi-seed variance: the LLM pipeline is deterministic
    given a fixed verdict cache/temperature, so repeated runs would not
    produce variance — the uncertainty is over the scenario sample.
    """
    import random as _random

    benign = [r for r in results if r.task_type == "benign"]
    attacks = [r for r in results if r.task_type == "adversarial"]
    rng = _random.Random(seed)

    def _pct(samples: List[float], q: float) -> float:
        s = sorted(samples)
        if not s:
            return 0.0
        idx = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
        return s[idx]

    bcr, abr, fp = [], [], []
    for _ in range(n_resamples):
        rb = [benign[rng.randrange(len(benign))] for _ in range(len(benign))] if benign else []
        ra = [attacks[rng.randrange(len(attacks))] for _ in range(len(attacks))] if attacks else []
        bcr.append(sum(1 for r in rb if r.benign_completed) / max(len(rb), 1))
        abr.append(sum(1 for r in ra if r.attack_blocked) / max(len(ra), 1))
        fp.append(sum(r.fp for r in rb))

    return {
        "bcr": [sum(1 for r in benign if r.benign_completed) / max(len(benign), 1),
                _pct(bcr, alpha / 2), _pct(bcr, 1 - alpha / 2)],
        "abr": [sum(1 for r in attacks if r.attack_blocked) / max(len(attacks), 1),
                _pct(abr, alpha / 2), _pct(abr, 1 - alpha / 2)],
        "fp_steps": [sum(r.fp for r in benign),
                     _pct(fp, alpha / 2), _pct(fp, 1 - alpha / 2)],
        "n_benign": len(benign),
        "n_adversarial": len(attacks),
        "n_resamples": n_resamples,
        "seed": seed,
    }


def mcnemar_exact(a_correct: List[bool], b_correct: List[bool]) -> Dict:
    """Exact McNemar test on paired per-scenario correctness vectors."""
    from math import comb
    n01 = sum(1 for a, b in zip(a_correct, b_correct) if a and not b)
    n10 = sum(1 for a, b in zip(a_correct, b_correct) if not a and b)
    n = n01 + n10
    if n == 0:
        p = 1.0
    else:
        tail = sum(comb(n, k) for k in range(0, min(n01, n10) + 1))
        p = min(1.0, 2 * tail / (2 ** n))
    return {"n_a_only": n01, "n_b_only": n10, "n_discordant": n,
            "p_value": p}


def markdown_table(headers: List[str], rows: List[List]) -> str:
    """Render a simple Markdown table from headers + rows."""
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join(["---"] * len(headers)) + "|"]
    for row in rows:
        out.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(out)


__all__ = [
    "Metrics",
    "ScenarioResult",
    "aggregate_outcomes",
    "write_report",
    "load_baseline",
    "markdown_table",
    "bootstrap_ci",
    "mcnemar_exact",
    "REPORTS_DIR",
]