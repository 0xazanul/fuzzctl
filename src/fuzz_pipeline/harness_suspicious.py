from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .build_context import load_build_context
from .harness_candidates import _enrich_candidates_with_context
from .harness_discovery import _ai_plan_data
from .harness_metrics import (
    _best_file_rows,
    _coverage_reports,
    _is_harness_source_path,
    _latest_fuzz_run,
    _parse_llvm_coverage_report,
)
from .manifest import TargetManifest
from .util import ensure_dir, now_id, rel_to, write_json


def _candidate_coverage_evidence(
    candidate: dict[str, Any],
    file_rows: dict[str, dict[str, Any]],
) -> tuple[int, list[str], dict[str, Any] | None]:
    rel_file = candidate.get("relative_file", "")
    row = file_rows.get(rel_file) or file_rows.get(Path(rel_file).name)
    reasons: list[str] = []
    score = 0
    if row is None:
        score += 26
        reasons.append("candidate file is absent from coverage reports")
    elif float(row.get("line", 0)) < 20:
        score += 18
        reasons.append(f"candidate file has very low line coverage ({row['line']}%)")
    elif float(row.get("line", 0)) < 45:
        score += 10
        reasons.append(f"candidate file has shallow line coverage ({row['line']}%)")
    if row and float(row.get("function", 0)) < 50:
        score += 8
        reasons.append(f"candidate file has low function coverage ({row['function']}%)")
    return score, reasons, row


def _markdown(manifest: TargetManifest, run_dir: Path | None, workspace: Path, selected: list[dict[str, Any]]) -> str:
    md = [f"# Suspicious Points: {manifest.name}", "", f"Run: `{rel_to(run_dir, workspace) if run_dir else 'none'}`", ""]
    if selected:
        for item in selected:
            md.append(
                f"- score `{item['score']}` `{item['id']}` `{item['file']}:{item['line']}` "
                f"`{item['function']}({item['params']})`"
            )
            for reason in item["reasons"][:5]:
                md.append(f"  - {reason}")
    else:
        md.append("- No parser/decoder suspicious points found by the static scanner.")
    return "\n".join(md) + "\n"


def suspicious_points(
    workspace: Path,
    manifest: TargetManifest,
    *,
    run_id: str | None = None,
    limit: int = 12,
    as_json: bool = False,
) -> dict[str, Any]:
    source_dir = manifest.source_dir(workspace)
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else _latest_fuzz_run(workspace, manifest.name)
    reports = [_parse_llvm_coverage_report(path) for path in _coverage_reports(run_dir)]
    file_rows = _best_file_rows(reports, source_dir) if reports else {}
    build_context = load_build_context(workspace, manifest)
    data = _ai_plan_data(source_dir)
    candidates = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    ranked: list[dict[str, Any]] = []

    for candidate in candidates:
        if _is_harness_source_path(candidate["relative_file"]):
            continue
        score = int(candidate.get("score", 0))
        reasons = list(candidate.get("reasons", []))
        risk_tags = list(candidate.get("risk_tags", []))
        score += len(risk_tags) * 4
        if candidate.get("usage_refs"):
            score += 4
            reasons.append("existing call-site usage found")
        if candidate.get("header_refs"):
            score += 3
            reasons.append("public/header declaration found")
        if candidate.get("build_context", {}).get("has_compile_unit"):
            score += 5
            reasons.append("compile database unit exists")
        cov_score, cov_reasons, row = _candidate_coverage_evidence(candidate, file_rows)
        score += cov_score
        reasons.extend(cov_reasons)
        ranked.append(
            {
                "id": candidate["id"],
                "function": candidate["function"],
                "params": candidate.get("params", ""),
                "file": candidate["relative_file"],
                "line": candidate["line"],
                "score": score,
                "risk_tags": risk_tags,
                "coverage": row,
                "reasons": reasons[:12],
                "recommended_harness_type": candidate.get("recommended_harness_type"),
                "input_strategy": candidate.get("input_strategy"),
            }
        )

    ranked.sort(key=lambda item: (-int(item["score"]), item["file"], int(item["line"])))
    selected = ranked[: max(1, limit)]
    result = {
        "target": manifest.name,
        "run": str(run_dir) if run_dir else None,
        "reports": len(reports),
        "suspicious_points": selected,
        "recommendations": [
            "Author or repair harnesses for the highest-scoring uncovered parser/decoder points first.",
            "Use `fuzzctl harness knowledge <target> --candidate <id>` before writing code.",
            "Run coverage again after adding a harness; a point should leave this list only after target-source coverage appears.",
        ],
    }

    out = ensure_dir(workspace / "workorders" / manifest.name / f"{now_id()}-suspicious-points")
    write_json(out / "suspicious-points.json", result)
    md = _markdown(manifest, run_dir, workspace, selected)
    (out / "README.md").write_text(md, encoding="utf-8")

    if run_dir:
        guidance = ensure_dir(run_dir / "guidance")
        write_json(guidance / "suspicious-points.json", result)
        (guidance / "suspicious-points.md").write_text(md, encoding="utf-8")

    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"suspicious points: {rel_to(out, workspace)}")
        for item in selected[:10]:
            print(f"- {item['score']}: {item['id']} {item['file']}:{item['line']} {item['function']}")
    return result
