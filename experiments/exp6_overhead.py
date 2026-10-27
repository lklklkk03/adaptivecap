"""Experiment 6 — Runtime overhead (revision W2; responds to R1-5, R2-5, R3).

The submission reported a "0.080 ms amortized per-call overhead" derived
from a *cache-hit* reading of the Layer-2 latency and compared it against
ChainCaps' 0.13 ms figure measured on different hardware. This revision
re-measures both systems on the same machine and reports the two paths
separately:

  * **Deterministic hot path** — scope-bucket lookup, Layer-1 audit
    (sensitive-pattern + k-anonymity + target checks) and HMAC token
    issuance, each micro-benchmarked, plus the integrated per-call overhead
    of the whole enforcement pipeline with Layer-2 disabled.
  * **LLM path** — live DeepSeek calls with the verdict cache *disabled*,
    one unique prompt per sample (``>= 30`` samples), reported as
    p50/p95/p99/min/max/mean.
  * **Amortization** — the trigger rate measured on the benchmark
    (audited sink requests / all tool calls, from the exp1 call-level table)
    multiplied by the measured LLM latency, reported as the per-call
    expected cost. This replaces the withdrawn 0.080 ms figure.

ChainCaps is re-measured on the same machine (its engine makes no LLM
calls: pure hot path), including a DAG-size sweep so the comparison is
like-for-like. The machine specification is recorded in the report and in
the paper's footnote.

Outputs ``reports/exp6_overhead.{json,md}``.
"""

from __future__ import annotations

import json
import os
import platform
import statistics
import time
from pathlib import Path
from typing import Dict, List, Optional

from .reports import write_report, markdown_table
from .scenarios import (
    build_scope_crossing_scenarios, load_raid_v3_group4_fps,
)
from .engines_adapter import SHARED_MANIFESTS
from .llm_auditor import reset_audit_log

from elasticap.budget import Budget, SinkPrivilege, SinkType, budget_display_only
from elasticap.dag import ElasticDAG
from elasticap.auditor import DeclassificationAuditor
from elasticap.token_issuer import issue_declassification_token
from elasticap.engine import ToolCall, ElasticCapEngine
from elasticap.llm_client import (
    make_llm_classifier, llm_cache_enabled, llm_cache_stats, reset_llm_cache,
    YellowSentinel,
)

REPORTS_DIR = Path(os.environ.get(
    "ELASTICCAP_REPORTS_DIR",
    Path(__file__).resolve().parent / "reports",
))

N_LLM_SAMPLES = int(os.environ.get("ELASTICCAP_EXP6_LLM_SAMPLES", "30"))


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------

def _summarize(samples_ms: List[float], name: str, n: Optional[int] = None) -> Dict:
    s = sorted(samples_ms)
    k = len(s)

    def _q(q: float) -> float:
        if not k:
            return float("nan")
        idx = min(k - 1, max(0, int(round(q * (k - 1)))))
        return s[idx]

    return {
        "name": name,
        "n": n if n is not None else k,
        "min_ms": s[0] if k else None,
        "p50_ms": _q(0.50) if k else None,
        "p95_ms": _q(0.95) if k else None,
        "p99_ms": _q(0.99) if k else None,
        "max_ms": s[-1] if k else None,
        "mean_ms": statistics.mean(s) if k else None,
    }


def _bench(name: str, fn, n: int = 2000, warmup: int = 20) -> Dict:
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t) * 1000.0)
    return _summarize(samples, name)


# ---------------------------------------------------------------------------
# Hot-path micro-benchmarks
# ---------------------------------------------------------------------------

def bench_scope_bucket() -> Dict:
    dag = ElasticDAG(signing_key=b"k" * 32)
    sb = budget_display_only()
    pre_node = dag.add_source("x.csv", sb, "read_file")

    def go():
        dag._find_or_create_component([pre_node])
        dag.get_context_budget([pre_node])
    return _bench("Scope bucket (component + context budget)", go, n=2000)


def bench_layer1() -> Dict:
    aud = DeclassificationAuditor(signing_key=b"k" * 32, llm_classifier=None)
    from elasticap.dag import DataNode
    node = DataNode(node_id="src", label="read_file(secret.env)",
                    budget=budget_display_only(), tool_name="read_file",
                    is_source=True, tool_args={"path": "secret.env"})
    call = ToolCall("send_email", {"to": "hr@corp.com", "body": "x"})
    return _bench("Layer-1 audit (pattern + k-anonymity + target)",
                  lambda: aud.audit(call, [node],
                                    "Send summary to HR department at hr@corp.com"),
                  n=2000)


def bench_token() -> Dict:
    sk = b"k" * 32
    priv = SinkPrivilege(SinkType.SEND_EMAIL, "@corp.com")
    return _bench("Token issuance (HMAC-SHA256)",
                  lambda: issue_declassification_token(sk, priv, ["n1", "n2", "n3"]),
                  n=2000)


def bench_integrated_hot_path() -> Dict:
    """Per-call latency of the full pipeline with Layer-2 disabled.

    The auditor is built without a classifier, so suspended sinks resolve to
    YELLOW deterministically — the measurement contains no network I/O and
    captures exactly what every call pays.
    """
    reset_audit_log()
    auditor = DeclassificationAuditor(signing_key=b"k" * 32, llm_classifier=None)
    scs = build_scope_crossing_scenarios()
    fps = load_raid_v3_group4_fps()
    scenario = (fps + scs)[0]
    engine = ElasticCapEngine(manifests=dict(SHARED_MANIFESTS),
                              source_budget_overrides=dict(scenario.source_budgets),
                              auditor=auditor)
    engine.set_user_intent(scenario.user_intent)

    def one_pass():
        nonlocal engine
        engine = ElasticCapEngine(manifests=dict(SHARED_MANIFESTS),
                                  source_budget_overrides=dict(scenario.source_budgets),
                                  auditor=auditor)
        engine.set_user_intent(scenario.user_intent)
        for tool, args, deps in scenario.steps:
            engine.process_tool_call(ToolCall(tool, dict(args),
                                              list(deps) if deps else []))

    samples = []
    n_passes = 200
    for _ in range(5):
        one_pass()
    for _ in range(n_passes):
        t = time.perf_counter()
        one_pass()
        samples.append((time.perf_counter() - t) * 1000.0 / max(len(scenario.steps), 1))
    return _summarize(samples, "Integrated AdaptiveCap per call (Layer-2 disabled)",
                      n=n_passes * len(scenario.steps))


# ---------------------------------------------------------------------------
# LLM-path benchmark (cache disabled, unique prompts)
# ---------------------------------------------------------------------------

def _unique_audit_prompt(i: int) -> str:
    """A representative audit prompt with a unique marker per sample."""
    return (
        f"USER'S ORIGINAL REQUEST: send the aggregated quarterly figures to "
        f"cfo@corp.com (request #{i})\n"
        f"BLOCKED OPERATION:\n  Tool: send_email\n  Target: {{'to': "
        f"'cfo@corp.com'}}\n  Body: Dept A avg=85000, Dept B avg=92000 "
        f"(batch {i})\n"
        f"DATA LINEAGE (last 5 nodes):\n  - read salary.csv (tool: read_file)\n"
        f"  - aggregate_stats (tool: aggregate_stats)\n"
        f"QUESTION: Has the data been sufficiently sanitized/aggregated such "
        f"that sending it to the target is safe?\n"
        f"Respond with exactly one word: GREEN, YELLOW, or RED."
    )


def bench_llm_path(n_samples: int = N_LLM_SAMPLES) -> Dict:
    print(f"Measuring the live LLM path ({n_samples} unique prompts, "
          f"cache disabled) ...")
    prev = os.environ.get("ELASTICCAP_LLM_CACHE")
    os.environ["ELASTICCAP_LLM_CACHE"] = "0"
    # Re-import time flag: the module-level flag was read at import, so read
    # it fresh here by reloading just the flag through the helper.
    import elasticap.llm_client as _llmc
    _llmc._LLM_CACHE_ENABLED = False
    reset_llm_cache()

    cls = make_llm_classifier()
    if not getattr(cls, "is_available", False):
        if prev is not None:
            os.environ["ELASTICCAP_LLM_CACHE"] = prev
        return {"name": "Layer-2 LLM (live API)", "n": 0,
                "note": "LLM unavailable; skipped",
                "cache_enabled_during_measurement": False}

    samples: List[float] = []
    verdicts: List[str] = []
    for i in range(n_samples):
        t = time.perf_counter()
        v = cls(_unique_audit_prompt(i))
        samples.append((time.perf_counter() - t) * 1000.0)
        verdicts.append("unavailable" if isinstance(v, YellowSentinel) else str(v))
        if (i + 1) % 10 == 0:
            print(f"  {i + 1}/{n_samples} samples, "
                  f"mean so far {statistics.mean(samples):.0f} ms", flush=True)

    _llmc._LLM_CACHE_ENABLED = bool(prev != "0")
    if prev is not None:
        os.environ["ELASTICCAP_LLM_CACHE"] = prev
    else:
        os.environ.pop("ELASTICCAP_LLM_CACHE", None)

    out = _summarize(samples, "Layer-2 LLM (live API, cache disabled)")
    out["verdicts"] = {v: verdicts.count(v) for v in set(verdicts)}
    out["cache_enabled_during_measurement"] = False
    return out


# ---------------------------------------------------------------------------
# ChainCaps, same machine
# ---------------------------------------------------------------------------

def bench_chaincaps_hot_path() -> Dict:
    """ChainCaps engine latency on this machine (pure hot path)."""
    from experiments.scenarios import _CHAINCAPS_ROOT
    import sys as _sys
    if str(_CHAINCAPS_ROOT) not in _sys.path:
        _sys.path.insert(0, str(_CHAINCAPS_ROOT))
    from chaincaps.proxy.engine import ChainCapsEngine, ToolCall as CCToolCall

    fps = load_raid_v3_group4_fps()
    scs = build_scope_crossing_scenarios()
    scenario = (fps + scs)[0]

    def one_pass():
        engine = ChainCapsEngine()
        for tool, args, deps in scenario.steps:
            engine.process_tool_call(CCToolCall(
                tool_name=tool, arguments=dict(args),
                data_dependencies=list(deps) if deps else []))

    samples = []
    n_passes = 200
    for _ in range(5):
        one_pass()
    for _ in range(n_passes):
        t = time.perf_counter()
        one_pass()
        samples.append((time.perf_counter() - t) * 1000.0 / max(len(scenario.steps), 1))
    return _summarize(samples, "Integrated ChainCaps per call (same machine)",
                      n=n_passes * len(scenario.steps))


def bench_chaincaps_dag_sweep(sizes=(10, 50, 100, 500, 1000)) -> List[Dict]:
    """Per-call latency vs DAG size (ChainCaps' own published sweep)."""
    from experiments.scenarios import _CHAINCAPS_ROOT
    import sys as _sys
    if str(_CHAINCAPS_ROOT) not in _sys.path:
        _sys.path.insert(0, str(_CHAINCAPS_ROOT))
    from chaincaps.proxy.engine import ChainCapsEngine, ToolCall as CCToolCall
    from chaincaps.core.budget import (
        Budget as CCBudget, SinkPrivilege as CCSinkPrivilege, SinkType as CCSinkType,
    )

    rows = []
    for n in sizes:
        engine = ChainCapsEngine()
        node_ids = []
        for i in range(n):
            call = CCToolCall("read_file", {"path": f"file_{i}.txt"},
                              data_dependencies=node_ids[-3:] if node_ids else [])
            res = engine.process_tool_call(call)
            if res.output_node_id:
                node_ids.append(res.output_node_id)
        samples = []
        for _ in range(100):
            t = time.perf_counter()
            engine.process_tool_call(CCToolCall(
                "read_file", {"path": "test.txt"},
                data_dependencies=node_ids[-3:]))
            samples.append((time.perf_counter() - t) * 1000.0)
        row = _summarize(samples, f"ChainCaps DAG size {n}", n=100)
        row["dag_size"] = n
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Amortization from measured trigger rate
# ---------------------------------------------------------------------------

def _trigger_rate_from_exp1() -> Optional[Dict]:
    """Read the call-level accounting from the exp1 report, if present."""
    p = REPORTS_DIR / "exp1_baseline.json"
    if not p.exists():
        return None
    d = json.loads(p.read_text())
    cs = d.get("call_summary") or {}
    total = (cs.get("total_tool_calls") or {}).get("count")
    sinks = (cs.get("sink_attempts") or {}).get("count")
    audited = (cs.get("sink_attempts_suspended_to_audit") or {}).get("count")
    if not total:
        return None
    return {
        "total_tool_calls": total,
        "sink_attempts": sinks,
        "audited_sink_requests": audited,
        "trigger_rate_per_call": (audited or 0) / total,
        "trigger_rate_per_sink": (audited or 0) / max(sinks or 1, 1),
        "source": "exp1_baseline.json call_summary",
    }


def main(prefer_deepseek: bool = True) -> Dict:
    print("=" * 72)
    print("Experiment 6: Runtime overhead (revision W2)")
    print("=" * 72)

    machine = {
        "cpu": next((l.split(":", 1)[1].strip()
                     for l in Path("/proc/cpuinfo").read_text().splitlines()
                     if l.startswith("model name")), "unknown"),
        "n_cpu": os.cpu_count(),
        "mem_gb": next((round(int(l.split()[1]) / 1024 / 1024, 1)
                        for l in Path("/proc/meminfo").read_text().splitlines()
                        if l.startswith("MemTotal")), 0),
        "os": platform.platform(),
        "python": platform.python_version(),
    }
    print(f"Machine: {machine['cpu']} x{machine['n_cpu']}, "
          f"{machine['mem_gb']} GB, {machine['os']}")

    print("Hot-path micro-benchmarks ...")
    hot = {
        "scope_bucket": bench_scope_bucket(),
        "layer1": bench_layer1(),
        "token": bench_token(),
        "integrated": bench_integrated_hot_path(),
    }

    print("ChainCaps same-machine measurement ...")
    chaincaps = {
        "integrated": bench_chaincaps_hot_path(),
        "dag_sweep": bench_chaincaps_dag_sweep(),
    }

    llm = bench_llm_path() if prefer_deepseek else {
        "name": "Layer-2 LLM (live API)", "n": 0,
        "note": "skipped (mock mode)"}

    trigger = _trigger_rate_from_exp1()
    amortized = None
    if trigger and llm.get("mean_ms"):
        amortized = {
            "trigger_rate_per_call": trigger["trigger_rate_per_call"],
            "llm_mean_ms": llm["mean_ms"],
            "expected_ms_per_call": trigger["trigger_rate_per_call"] * llm["mean_ms"],
            "expected_ms_per_sink": trigger["trigger_rate_per_sink"] * llm["mean_ms"],
        }

    md = ["# Experiment 6 — Runtime Overhead (revision)\n",
          f"**Machine.** {machine['cpu']} x{machine['n_cpu']} cores, "
          f"{machine['mem_gb']} GB RAM, {machine['os']}, "
          f"Python {machine['python']} (bare metal, no container).",
          "",
          "## Deterministic hot path (no network I/O)\n",
          markdown_table(
              ["Component", "n", "min (ms)", "p50 (ms)", "p95 (ms)",
               "p99 (ms)", "max (ms)"],
              [[r["name"], str(r["n"]),
                f"{r['min_ms']:.4f}", f"{r['p50_ms']:.4f}",
                f"{r['p95_ms']:.4f}", f"{r['p99_ms']:.4f}",
                f"{r['max_ms']:.4f}"]
               for r in (hot[k] for k in ("scope_bucket", "layer1", "token",
                                          "integrated"))]),
          "",
          "## LLM path (live DeepSeek, verdict cache disabled)\n",
          ]
    if llm.get("n"):
        md.append(markdown_table(
            ["Measurement", "n", "min (ms)", "p50 (ms)", "p95 (ms)",
             "p99 (ms)", "max (ms)", "mean (ms)"],
            [[llm["name"], str(llm["n"]),
              f"{llm['min_ms']:.0f}", f"{llm['p50_ms']:.0f}",
              f"{llm['p95_ms']:.0f}", f"{llm['p99_ms']:.0f}",
              f"{llm['max_ms']:.0f}", f"{llm['mean_ms']:.0f}"]]))
        md.append(f"\nVerdicts returned: {llm.get('verdicts')}\n")
    else:
        md.append(f"\n_{llm.get('note', 'not measured')}_\n")

    md += ["\n## ChainCaps on the same machine (hot path only)\n",
           markdown_table(
               ["Measurement", "n", "p50 (ms)", "p95 (ms)", "p99 (ms)"
                , "mean (ms)"],
               [[r["name"], str(r["n"]), f"{r['p50_ms']:.4f}",
                 f"{r['p95_ms']:.4f}", f"{r['p99_ms']:.4f}",
                 f"{r['mean_ms']:.4f}"]
                for r in [chaincaps["integrated"]]]),
           "",
           markdown_table(
               ["DAG size", "p50 (ms)", "p95 (ms)", "mean (ms)"],
               [[str(r["dag_size"]), f"{r['p50_ms']:.4f}",
                 f"{r['p95_ms']:.4f}", f"{r['mean_ms']:.4f}"]
                for r in chaincaps["dag_sweep"]]),
           ]

    md += ["\n## Amortized cost\n"]
    if trigger:
        md.append(f"- Audit trigger rate on the benchmark: "
                  f"**{trigger['trigger_rate_per_call']:.2%} of all tool calls** "
                  f"({trigger['audited_sink_requests']} of "
                  f"{trigger['total_tool_calls']} calls; "
                  f"{trigger['trigger_rate_per_sink']:.1%} of sink attempts). "
                  f"Source: {trigger['source']}.")
    if amortized:
        md.append(f"- Expected per-call cost = trigger rate x measured LLM "
                  f"latency = {amortized['trigger_rate_per_call']:.2%} x "
                  f"{amortized['llm_mean_ms']:.0f} ms = "
                  f"**{amortized['expected_ms_per_call']:.1f} ms per call** "
                  f"({amortized['expected_ms_per_sink']:.1f} ms per sink "
                  f"attempt).")
    md.append("\nThe withdrawn 0.080 ms figure was a cache-hit reading and is "
              "not reproduced; the deterministic path is reported above and "
              "the LLM cost is reported as a per-trigger cost, not amortized "
              "into a sub-millisecond number.\n")

    payload = {
        "machine": machine,
        "hot_path": hot,
        "llm_path": llm,
        "chaincaps": chaincaps,
        "trigger_rate": trigger,
        "amortized": amortized,
        "config": {
            "llm_cache_enabled_at_measurement": llm.get(
                "cache_enabled_during_measurement", False),
            "llm_samples": N_LLM_SAMPLES,
            "cache_stats_after": llm_cache_stats(),
        },
    }
    j, m = write_report("exp6_overhead", payload, "\n".join(md))
    print(f"\nReport: {m}")
    return payload


if __name__ == "__main__":
    prefer = os.environ.get("ELASTICCAP_LLM", "auto") != "mock"
    main(prefer_deepseek=prefer)
