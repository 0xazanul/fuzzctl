from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .build_context import load_build_context
from .harness_candidates import _candidate_by_id, _enrich_candidates_with_context
from .harness_discovery import _ai_plan_data
from .harness_metrics import (
    BANNED_PATTERNS,
    _best_file_rows,
    _build_artifacts,
    _coverage_reports,
    _is_harness_source_path,
    _is_header_coverage_row,
    _latest_fuzz_run,
    _parse_llvm_coverage_report,
    _review_data,
    _seed_count,
)
from .manifest import TargetManifest
from .util import ensure_dir, now_id, rel_to, write_json


def _harness_source_text(workspace: Path, manifest: TargetManifest, harness: Any) -> tuple[Path | None, str, str | None]:
    if not harness.source:
        return None, "", "manifest harness has no source file"
    source = (manifest.source_dir(workspace) / harness.source).resolve()
    if not source.exists():
        return source, "", f"source missing: {harness.source}"
    return source, source.read_text(encoding="utf-8", errors="replace"), None


def _principle_result(name: str, ok: bool, evidence: list[str], issues: list[str]) -> dict[str, Any]:
    return {
        "name": name,
        "ok": ok,
        "evidence": evidence,
        "issues": issues,
    }


def _qa_entrypoint_coverage(
    workspace: Path,
    manifest: TargetManifest,
    harness_name: str,
    run_dir: Path | None,
) -> dict[str, Any] | None:
    if run_dir is None:
        return None
    reports = [
        parsed
        for parsed in (_parse_llvm_coverage_report(path) for path in _coverage_reports(run_dir))
        if Path(str(parsed.get("report", ""))).name.startswith(f"{harness_name}.")
    ]
    if not reports:
        return None
    source_dir = manifest.source_dir(workspace)
    rows = _best_file_rows(reports, source_dir)
    target_rows = [
        row
        for row in rows.values()
        if not _is_header_coverage_row(row) and not _is_harness_source_path(str(row.get("file", "")))
    ]
    if not target_rows:
        return {"target_rows": 0, "best": None}
    best = max(target_rows, key=lambda row: (float(row["line"]), float(row["function"]), float(row["region"])))
    return {"target_rows": len({row["file"] for row in target_rows}), "best": best}


def _qa_for_harness(
    workspace: Path,
    manifest: TargetManifest,
    harness: Any,
    *,
    run_dir: Path | None,
    review: dict[str, Any],
    builds: dict[str, int],
    seed_count: int,
) -> dict[str, Any]:
    source, text, source_issue = _harness_source_text(workspace, manifest, harness)
    harness_errors = [item["message"] for item in review["errors"] if item.get("harness") == harness.name]
    harness_warnings = [item["message"] for item in review["warnings"] if item.get("harness") == harness.name]

    logic_evidence: list[str] = []
    logic_issues: list[str] = []
    if source:
        logic_evidence.append(f"source: {rel_to(source, workspace)}")
    if source_issue:
        logic_issues.append(source_issue)
    if harness.type == "libfuzzer":
        if "LLVMFuzzerTestOneInput" in text:
            logic_evidence.append("libFuzzer entrypoint present")
        else:
            logic_issues.append("missing LLVMFuzzerTestOneInput")
    elif harness.type == "fuzztest":
        if "FUZZ_TEST" in text:
            logic_evidence.append("FuzzTest property macro present")
        else:
            logic_issues.append("missing FUZZ_TEST property macro")
    elif harness.type in {"file", "stdin"}:
        if re.search(r"\bint\s+main\s*\(", text):
            logic_evidence.append("process entrypoint main() present")
        else:
            logic_issues.append("no obvious main() entrypoint")
    else:
        logic_issues.append(f"unsupported harness type: {harness.type}")
    if "data" in text and "size" in text:
        logic_evidence.append("fuzz bytes and size are both referenced")
    elif harness.type in {"libfuzzer", "fuzztest"}:
        logic_issues.append("input byte/size use is not obvious")

    protocol_evidence: list[str] = []
    protocol_issues: list[str] = []
    if "#include" in text:
        protocol_evidence.append("includes target headers or local declarations")
    else:
        protocol_issues.append("no include/declaration evidence; confirm the API protocol manually")
    if any(token in text for token in ("Init", "init", "Create", "create", "Reset", "reset", "Free", "free", "Destroy", "destroy")):
        protocol_evidence.append("setup/teardown calls are visible")
    else:
        protocol_issues.append("setup/teardown/reset is not visible; acceptable only for pure byte parsers")
    if harness.compile_flags or harness.link_flags:
        protocol_evidence.append("harness-specific compile/link flags configured")
    if builds.get("libfuzzer_asan_ubsan", 0) and harness.type == "libfuzzer":
        protocol_evidence.append("libFuzzer sanitizer build artifact exists")
    if builds.get("afl_asan_ubsan", 0) and harness.type in {"file", "stdin"}:
        protocol_evidence.append("AFL++ sanitizer build artifact exists")
    if builds.get("fuzztest_asan_ubsan", 0) and harness.type == "fuzztest":
        protocol_evidence.append("FuzzTest sanitizer build artifact exists")

    boundary_evidence: list[str] = []
    boundary_issues: list[str] = []
    for severity, pattern, message in BANNED_PATTERNS:
        if pattern.search(text):
            boundary_issues.append(f"{severity}: {message}")
    if not boundary_issues:
        boundary_evidence.append("no banned shell/network/sleep/abort patterns found")
    if harness.type == "file":
        if "@@" in " ".join(harness.argv):
            boundary_evidence.append("file input is explicitly supplied through @@")
        else:
            boundary_issues.append("file harness argv does not include @@")
    if seed_count > 0:
        boundary_evidence.append("non-empty seed corpus available")

    coverage = _qa_entrypoint_coverage(workspace, manifest, harness.name, run_dir)
    adequacy_evidence: list[str] = []
    adequacy_issues: list[str] = []
    coverage_proven = False
    if coverage and coverage.get("best"):
        best = coverage["best"]
        coverage_proven = True
        adequacy_evidence.append(
            f"coverage reaches target file {best['file']} line={best['line']}% function={best['function']}%"
        )
    elif run_dir is not None:
        adequacy_issues.append("no target-source coverage evidence for this harness in the selected run")
    else:
        adequacy_issues.append("no run selected; coverage adequacy is unproven")
    if source and not _is_harness_source_path(rel_to(source, manifest.source_dir(workspace))):
        adequacy_issues.append("harness source is outside fuzz_harnesses; confirm this is intentional")

    principles = [
        _principle_result("logic_correctness", bool(logic_evidence) and not any("missing" in issue or "unsupported" in issue for issue in logic_issues), logic_evidence, logic_issues),
        _principle_result("api_protocol_compliance", bool(protocol_evidence) and not harness_errors, protocol_evidence, protocol_issues),
        _principle_result("security_boundary_respect", not boundary_issues, boundary_evidence, boundary_issues),
        _principle_result("entry_point_adequacy", coverage_proven, adequacy_evidence, adequacy_issues),
    ]
    score = sum(25 for item in principles if item["ok"])
    if harness_warnings:
        score = max(0, score - min(15, len(harness_warnings) * 3))
    passing = all(item["ok"] for item in principles) and not harness_errors
    return {
        "harness": harness.name,
        "type": harness.type,
        "source": str(source) if source else None,
        "score": score,
        "status": "pass" if passing else "needs_work",
        "principles": principles,
        "review_errors": harness_errors,
        "review_warnings": harness_warnings,
    }


def harness_qa(
    workspace: Path,
    manifest: TargetManifest,
    *,
    candidate_id: str | None = None,
    run_id: str | None = None,
    as_json: bool = False,
) -> dict[str, Any]:
    review = _review_data(workspace, manifest)
    builds = _build_artifacts(workspace, manifest)
    seed_count = _seed_count(workspace, manifest)
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else _latest_fuzz_run(workspace, manifest.name)
    harnesses = [
        _qa_for_harness(
            workspace,
            manifest,
            harness,
            run_dir=run_dir,
            review=review,
            builds=builds,
            seed_count=seed_count,
        )
        for harness in manifest.harnesses
    ]
    candidate: dict[str, Any] | None = None
    if candidate_id:
        source_dir = manifest.source_dir(workspace)
        data = _ai_plan_data(source_dir)
        build_context = load_build_context(workspace, manifest)
        data["candidate_entrypoints"] = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
        candidate = _candidate_by_id(data, candidate_id)

    result = {
        "target": manifest.name,
        "run": str(run_dir) if run_dir else None,
        "candidate": candidate,
        "summary": {
            "harnesses": len(harnesses),
            "passing": sum(1 for item in harnesses if item["status"] == "pass"),
            "needs_work": sum(1 for item in harnesses if item["status"] != "pass"),
            "seed_count": seed_count,
            "build_artifacts": builds,
        },
        "four_principles": [
            "logic_correctness",
            "api_protocol_compliance",
            "security_boundary_respect",
            "entry_point_adequacy",
        ],
        "harnesses": harnesses,
        "review": review,
        "recommendations": [
            "Do not start long campaigns until every production harness passes security-boundary and entrypoint checks.",
            "Treat coverage absence as a harness problem first, not a reason to add more workers.",
            "Use FuzzTest for invariant/roundtrip properties; keep AFL++ as the long-running crash-discovery engine.",
        ],
    }
    out = ensure_dir(workspace / "workorders" / manifest.name / f"{now_id()}-harness-qa")
    write_json(out / "harness-qa.json", result)
    md = [f"# Harness QA: {manifest.name}", "", "## Four Principles", ""]
    for principle in result["four_principles"]:
        md.append(f"- `{principle}`")
    md.extend(["", "## Harnesses", ""])
    for item in harnesses:
        md.append(f"- `{item['harness']}` `{item['type']}` score `{item['score']}/100` status `{item['status']}`")
        for principle in item["principles"]:
            mark = "pass" if principle["ok"] else "needs work"
            md.append(f"  - `{principle['name']}`: {mark}")
            for issue in principle["issues"][:3]:
                md.append(f"    - {issue}")
    (out / "README.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"harness QA: {rel_to(out, workspace)}")
        print(f"passing={result['summary']['passing']} needs_work={result['summary']['needs_work']}")
        for item in harnesses:
            print(f"- {item['harness']}: {item['score']}/100 {item['status']}")
    return result
