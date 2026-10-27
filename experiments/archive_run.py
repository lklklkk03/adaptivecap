"""Archive a run's reports with a reproducibility manifest.

Copies ``experiments/reports/`` to ``experiments/archive/reports_<tag>/`` and
writes ``run_manifest.json`` recording the classifier, cache state, patch
flags, machine specification and git revision. Every rerun reported in the
paper points at one of these archives.

Usage::

    python experiments/archive_run.py --tag real_llm_run1 [--reports DIR]
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def _git_rev(repo: Path) -> str:
    try:
        out = subprocess.run(["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=10)
        dirty = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                               capture_output=True, text=True, timeout=10)
        rev = out.stdout.strip() or "unknown"
        return rev + ("+dirty" if dirty.stdout.strip() else "")
    except Exception:
        return "unknown"


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "unknown"


def _mem_gb() -> float:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal"):
                return round(int(line.split()[1]) / 1024 / 1024, 1)
    except Exception:
        pass
    return 0.0


def _container() -> str:
    try:
        cg = Path("/proc/1/cgroup").read_text().strip()
    except Exception:
        cg = ""
    if "docker" in cg or "kubepods" in cg or "lxc" in cg:
        return "container"
    return "bare-metal"


def collect_manifest(reports_dir: Path, tag: str) -> dict:
    import os
    repo = Path(__file__).resolve().parents[2]
    classifier = None
    exp1 = reports_dir / "exp1_baseline.json"
    if exp1.exists():
        d = json.loads(exp1.read_text())
        classifier = {
            "classifier": d.get("classifier"),
            "model": d.get("model"),
            "config": d.get("config"),
        }
    return {
        "tag": tag,
        "archived_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "reports_dir": str(reports_dir),
        "git_rev": _git_rev(repo),
        "env": {
            "ELASTICCAP_LLM": os.environ.get("ELASTICCAP_LLM", "auto"),
            "ELASTICCAP_LLM_CACHE": os.environ.get("ELASTICCAP_LLM_CACHE", "1"),
            "ELASTICCAP_P3_HARDENING": os.environ.get("ELASTICCAP_P3_HARDENING", "1"),
            "ELASTICCAP_MIN_GROUP_K": os.environ.get("ELASTICCAP_MIN_GROUP_K", "5"),
        },
        "machine": {
            "cpu": _cpu_model(),
            "n_cores": os.cpu_count(),
            "mem_gb": _mem_gb(),
            "os": platform.platform(),
            "python": sys.version.split()[0],
            "container": _container(),
        },
        "classifier": classifier,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Archive experiment reports")
    ap.add_argument("--tag", required=True, help="archive name suffix")
    ap.add_argument("--reports", default=str(
        Path(__file__).resolve().parent / "reports"))
    ap.add_argument("--archive-root", default=str(
        Path(__file__).resolve().parent / "archive"))
    args = ap.parse_args(argv)

    reports_dir = Path(args.reports)
    if not reports_dir.is_dir():
        print(f"no such reports dir: {reports_dir}", file=sys.stderr)
        return 1

    stamp = datetime.now().strftime("%Y%m%d")
    dest = Path(args.archive_root) / f"reports_{stamp}_{args.tag}"
    if dest.exists():
        print(f"archive already exists: {dest}", file=sys.stderr)
        return 1
    shutil.copytree(reports_dir, dest)

    manifest = collect_manifest(reports_dir, args.tag)
    (dest / "run_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Archived {len(list(dest.glob('*')))} files to {dest}")
    print(json.dumps(manifest, indent=2)[:400])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
