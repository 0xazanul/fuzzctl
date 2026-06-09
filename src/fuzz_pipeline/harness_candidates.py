from __future__ import annotations

from pathlib import Path
from typing import Any

from .util import FuzzCtlError


def _candidate_by_id(data: dict[str, Any], candidate_id: str | None) -> dict[str, Any] | None:
    if candidate_id is None:
        return None
    for item in data["candidate_entrypoints"]:
        if item["id"] == candidate_id or item["function"] == candidate_id:
            return item
    raise FuzzCtlError(f"candidate not found: {candidate_id}")


def _candidate_context(build_context: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    rel_file = candidate.get("relative_file")
    abs_file = Path(candidate.get("file", "")).resolve()
    for unit in build_context.get("units", []):
        unit_file = Path(unit.get("file", "")).resolve()
        if unit_file == abs_file or unit.get("relative_file") == rel_file:
            return {
                "compile_unit": unit,
                "include_dirs": unit.get("include_dirs", []),
                "defines": unit.get("defines", []),
                "compile_flags": unit.get("compile_flags", []),
                "link_artifacts": build_context.get("link_artifacts", []),
            }
    return {
        "compile_unit": None,
        "include_dirs": build_context.get("include_dirs", []),
        "defines": build_context.get("defines", []),
        "compile_flags": build_context.get("compile_flags", []),
        "link_artifacts": build_context.get("link_artifacts", []),
    }


def _enrich_candidates_with_context(candidates: list[dict[str, Any]], build_context: dict[str, Any]) -> list[dict[str, Any]]:
    if not build_context:
        return candidates
    out: list[dict[str, Any]] = []
    for candidate in candidates:
        item = dict(candidate)
        context = _candidate_context(build_context, item)
        item["build_context"] = {
            "has_compile_unit": bool(context["compile_unit"]),
            "include_dirs": context["include_dirs"][:20],
            "defines": context["defines"][:40],
            "compile_flags": context["compile_flags"][:40],
            "link_artifacts": context["link_artifacts"][:20],
        }
        if context["compile_unit"]:
            item["score"] += 2
            item.setdefault("reasons", []).append("has matching compile database unit")
        out.append(item)
    out.sort(key=lambda x: (-x["score"], x["relative_file"], x["line"]))
    return out
