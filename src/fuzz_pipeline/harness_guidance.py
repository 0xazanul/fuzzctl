from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .build_context import load_build_context
from .harness_candidates import _candidate_by_id, _enrich_candidates_with_context
from .harness_discovery import _ai_plan_data
from .harness_metrics import (
    _best_file_rows,
    _coverage_reports,
    _is_harness_coverage_row,
    _is_harness_source_path,
    _is_header_coverage_row,
    _latest_fuzz_run,
    _parse_llvm_coverage_report,
)
from .harness_workorders import _candidate_prompt
from .manifest import TargetManifest
from .util import FuzzCtlError, ensure_dir, now_id, rel_to, write_json


def _classification_values(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, list):
        return {str(item) for item in value}
    return {str(value)}


def _normalized_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").strip("/")


def _blocker_classification_matches(rule: dict[str, Any], blocker: dict[str, Any]) -> bool:
    has_selector = False

    candidates = _classification_values(rule.get("candidate"))
    if candidates:
        has_selector = True
        if str(blocker.get("candidate", "")) not in candidates:
            return False

    kinds = _classification_values(rule.get("kind"))
    if kinds:
        has_selector = True
        if str(blocker.get("kind", "")) not in kinds:
            return False

    functions = _classification_values(rule.get("function"))
    if functions:
        has_selector = True
        if str(blocker.get("function", "")) not in functions:
            return False

    files = {_normalized_path(item) for item in _classification_values(rule.get("file"))}
    if files:
        has_selector = True
        blocker_file = _normalized_path(blocker.get("file"))
        blocker_name = Path(blocker_file).name
        if blocker_file not in files and blocker_name not in files:
            return False

    return has_selector


def _blocker_classification(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        key: rule.get(key)
        for key in ["status", "reason", "action", "owner", "expires"]
        if rule.get(key) is not None
    }


def _apply_blocker_classifications(
    blockers: list[dict[str, Any]],
    classifications: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    unresolved: list[dict[str, Any]] = []
    classified: list[dict[str, Any]] = []
    for blocker in blockers:
        rule = next((item for item in classifications if _blocker_classification_matches(item, blocker)), None)
        if rule is None:
            unresolved.append(blocker)
            continue
        annotated = dict(blocker)
        annotated["classification"] = _blocker_classification(rule)
        classified.append(annotated)
    return unresolved, classified


def harness_blockers(
    workspace: Path,
    manifest: TargetManifest,
    *,
    run_id: str | None = None,
    as_json: bool = False,
) -> dict[str, Any]:
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else _latest_fuzz_run(workspace, manifest.name)
    if run_dir is None:
        raise FuzzCtlError(f"no fuzz or coverage run found for {manifest.name}")
    reports = [_parse_llvm_coverage_report(path) for path in _coverage_reports(run_dir)]
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    candidates = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)

    file_rows = _best_file_rows(reports, source_dir)

    blockers: list[dict[str, Any]] = []
    if not file_rows:
        blockers.append(
            {
                "kind": "coverage_report_missing",
                "file": None,
                "reason": "no llvm-cov text reports found for this run; run `fuzzctl coverage <target>` before blocker analysis",
            }
        )
    seen_rows: set[str] = set()
    for row in file_rows.values():
        if row["file"] in seen_rows:
            continue
        seen_rows.add(row["file"])
        if _is_header_coverage_row(row) or _is_harness_coverage_row(row):
            continue
        if row["line"] < 40 or row["function"] < 50:
            blockers.append({"kind": "low_coverage_file", **row})
    if file_rows:
        for candidate in candidates[:50]:
            if _is_harness_source_path(candidate["relative_file"]):
                continue
            row = file_rows.get(candidate["relative_file"]) or file_rows.get(Path(candidate["relative_file"]).name)
            if row is None:
                blockers.append(
                    {
                        "kind": "candidate_file_unreported",
                        "candidate": candidate["id"],
                        "file": candidate["relative_file"],
                        "function": candidate["function"],
                        "reason": "candidate file not present in llvm-cov report; harness may not link or execute it",
                    }
                )
            elif row["line"] < 40:
                blockers.append(
                    {
                        "kind": "candidate_shallow_coverage",
                        "candidate": candidate["id"],
                        "file": candidate["relative_file"],
                        "function": candidate["function"],
                        "line_coverage": row["line"],
                    }
                )

    unresolved_blockers, classified_blockers = _apply_blocker_classifications(
        blockers,
        manifest.blocker_classifications,
    )

    result = {
        "target": manifest.name,
        "run": str(run_dir),
        "reports": reports,
        "summary": {
            "reports": len(reports),
            "covered_files": len({row["file"] for row in file_rows.values()}),
            "blockers": len(unresolved_blockers),
            "classified_blockers": len(classified_blockers),
            "raw_blockers": len(blockers),
            "best_file_rows": True,
        },
        "blockers": unresolved_blockers[:100],
        "classified": classified_blockers[:100],
        "recommendations": [
            "Prefer candidates whose compile database unit exists and whose file has low or absent coverage.",
            "Add valid seeds/dictionaries before increasing campaign duration.",
            "Split broad harnesses when one entrypoint reaches too many unrelated APIs with shallow coverage.",
        ],
    }
    out = ensure_dir(run_dir / "guidance")
    write_json(out / "harness-blockers.json", result)
    md = [f"# Harness Blockers: {manifest.name}", "", f"Run: `{rel_to(run_dir, workspace)}`", ""]
    md.append("## Unresolved")
    md.append("")
    for blocker in result["blockers"][:40]:
        subject = blocker.get("file") or "-"
        detail = blocker.get("function") or blocker.get("reason", "")
        md.append(f"- `{blocker['kind']}`: `{subject}` {detail}")
    if not result["blockers"]:
        md.append("- No unresolved blocker rows found.")
    if result["classified"]:
        md.extend(["", "## Classified", ""])
        for blocker in result["classified"][:40]:
            subject = blocker.get("file") or "-"
            detail = blocker.get("function") or blocker.get("reason", "")
            classification = blocker.get("classification", {})
            status = classification.get("status", "classified")
            reason = classification.get("reason", "documented in target manifest")
            md.append(f"- `{status}` `{blocker['kind']}`: `{subject}` {detail} - {reason}")
    (out / "harness-blockers.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"harness blockers: {rel_to(out / 'harness-blockers.md', workspace)}")
        for blocker in result["blockers"][:20]:
            subject = blocker.get("file") or "-"
            detail = blocker.get("function") or blocker.get("reason", "")
            print(f"- {blocker['kind']}: {subject} {detail}")
        if result["classified"]:
            print(f"classified blockers: {len(result['classified'])}")
    return result


def iterate_harness(
    workspace: Path,
    manifest: TargetManifest,
    *,
    candidate_id: str | None = None,
    run_id: str | None = None,
) -> Path:
    blockers = harness_blockers(workspace, manifest, run_id=run_id, as_json=False)
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    data["candidate_entrypoints"] = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    candidate = _candidate_by_id(data, candidate_id) if candidate_id else (data["candidate_entrypoints"][0] if data["candidate_entrypoints"] else None)
    out = ensure_dir(workspace / "workorders" / manifest.name / f"{now_id()}-iteration")
    write_json(out / "blockers.json", blockers)
    if candidate:
        prompt = _candidate_prompt(workspace, manifest, data, candidate, build_context)
        (out / f"{candidate['id']}-iteration-prompt.md").write_text(prompt, encoding="utf-8")
    (out / "README.md").write_text(
        f"# Harness Iteration: {manifest.name}\n\n"
        "Use `blockers.json` to decide whether to improve seeds/dictionary, split the harness, or target another API.\n",
        encoding="utf-8",
    )
    print(f"iteration packet: {rel_to(out, workspace)}")
    return out
