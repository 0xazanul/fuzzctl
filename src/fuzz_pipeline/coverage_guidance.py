from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .manifest import TargetManifest
from .util import ensure_dir, find_latest_run, read_json, rel_to, write_json


TOTAL_RE = re.compile(
    r"TOTAL\s+\d+\s+\d+\s+([0-9.]+)%\s+\d+\s+\d+\s+([0-9.]+)%\s+\d+\s+\d+\s+([0-9.]+)%"
)


def _coverage_numbers(run_dir: Path) -> dict[str, float] | None:
    reports = sorted((run_dir / "coverage").glob("*.report.txt"))
    if not reports:
        return None
    totals = []
    for report in reports:
        text = report.read_text(encoding="utf-8", errors="replace")
        match = TOTAL_RE.search(text)
        if not match:
            continue
        totals.append(
            {
                "region": float(match.group(1)),
                "function": float(match.group(2)),
                "line": float(match.group(3)),
                "report": str(report),
            }
        )
    if not totals:
        return None
    weakest = min(totals, key=lambda item: (item["line"], item["function"], item["region"]))
    return {
        "region": weakest["region"],
        "function": weakest["function"],
        "line": weakest["line"],
        "report": weakest["report"],
        "reports": len(totals),
        "mode": "weakest_harness_report",
        "average": {
            "region": round(sum(item["region"] for item in totals) / len(totals), 2),
            "function": round(sum(item["function"] for item in totals) / len(totals), 2),
            "line": round(sum(item["line"] for item in totals) / len(totals), 2),
        },
    }


def _afl_summary(run_dir: Path) -> dict[str, Any]:
    stats_files = sorted(run_dir.rglob("fuzzer_stats"))
    execs = paths = crashes = hangs = 0
    for path in stats_files:
        data = {}
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                data[k.strip()] = v.strip()
        execs += int(float(data.get("execs_done", "0") or 0))
        paths += int(float(data.get("corpus_count", data.get("paths_total", "0")) or 0))
        crashes += int(float(data.get("saved_crashes", "0") or 0))
        hangs += int(float(data.get("saved_hangs", "0") or 0))
    return {"stats_files": len(stats_files), "execs": execs, "paths": paths, "crashes": crashes, "hangs": hangs}


def coverage_guidance(workspace: Path, manifest: TargetManifest, run_id: str | None = None) -> Path:
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else find_latest_run(workspace, manifest.name)
    out = ensure_dir(run_dir / "guidance")
    coverage = _coverage_numbers(run_dir)
    afl = _afl_summary(run_dir)
    recommendations: list[str] = []

    if coverage is None:
        recommendations.append("Run `fuzzctl coverage <target> --run <id>` before judging harness quality.")
    else:
        if coverage["line"] < 20:
            recommendations.append("Line coverage is extremely shallow; assume the harness is not yet exercising the real parser until proven otherwise.")
        if coverage["line"] < 40:
            recommendations.append("Line coverage is low; add valid seeds from tests/samples and verify the harness reaches parser logic.")
        elif coverage["line"] < 70:
            recommendations.append("Line coverage is moderate; inspect uncovered parser branches and add targeted seeds/dictionary tokens.")
        else:
            recommendations.append("Coverage is acceptable for a first pass; prioritize crash depth, corpus minimization, and longer AFL++ campaigns.")
        if coverage["function"] < 80:
            recommendations.append("Function coverage misses meaningful code; split harnesses by API/format instead of fuzzing one broad entrypoint.")
        if coverage["region"] < 35:
            recommendations.append("Region coverage is weak; prefer more valid structure in seeds before adding more campaign hours.")

    if not manifest.dictionary:
        recommendations.append("No dictionary is configured; extract magic bytes, keywords, headers, and format markers into a dictionary.")

    if not any(h.type == "libfuzzer" for h in manifest.harnesses):
        recommendations.append("Add a libFuzzer harness for fast smoke/repro/minimization if the target exposes an in-process parser API.")

    if not any("persistent" in h.name.lower() or h.input_mode == "persistent" for h in manifest.harnesses):
        recommendations.append("If the harness is hot-loop safe, add AFL++ persistent mode to improve exec/sec.")

    if afl["stats_files"] and afl["paths"] < 20:
        recommendations.append("AFL++ path growth is low; try CMPLOG, smaller seed corpus, dictionary, and removing checksums from fuzz builds.")

    if afl["stats_files"] and afl["execs"] > 0 and afl["crashes"] == 0:
        recommendations.append("No AFL++ crashes yet; run longer only after confirming coverage is still growing.")

    recommendations.append(f"Score the harness with `fuzzctl harness score {manifest.name}` before treating a campaign as ready for bounty-grade triage.")

    triage_path = run_dir / "triage" / "unique_crashes.json"
    if triage_path.exists():
        crashes = read_json(triage_path).get("crashes", [])
        if crashes:
            recommendations.append("Unique crashes exist; minimize/report before expanding campaign scope.")

    data = {
        "target": manifest.name,
        "run": str(run_dir),
        "coverage": coverage,
        "afl": afl,
        "recommendations": recommendations
    }
    write_json(out / "coverage-guidance.json", data)
    md = [f"# Coverage Guidance: {manifest.name}", "", f"Run: `{rel_to(run_dir, workspace)}`", ""]
    if coverage:
        md.extend([
            f"- Region coverage: `{coverage['region']}%`",
            f"- Function coverage: `{coverage['function']}%`",
            f"- Line coverage: `{coverage['line']}%`",
            f"- Summary mode: `{coverage.get('mode', 'single_report')}` across `{coverage.get('reports', 1)}` reports",
            f"- Report: `{rel_to(Path(coverage['report']), workspace)}`",
            ""
        ])
    md.append("## Recommendations")
    md.append("")
    md.extend(f"- {item}" for item in recommendations)
    (out / "coverage-guidance.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"coverage guidance: {rel_to(out, workspace)}")
    return out
