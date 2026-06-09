from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .build_context import load_build_context
from .harness_candidates import _candidate_by_id, _candidate_context, _enrich_candidates_with_context
from .harness_discovery import _ai_plan_data
from .harness_workorder_prompts import _candidate_prompt, _target_prompt, _work_order_markdown
from .manifest import TargetManifest
from .util import ensure_dir, now_id, rel_to, write_json


def harness_prompt(workspace: Path, manifest: TargetManifest, *, candidate_id: str | None = None) -> str:
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    data["candidate_entrypoints"] = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    candidate = _candidate_by_id(data, candidate_id)
    prompt = _candidate_prompt(workspace, manifest, data, candidate, build_context) if candidate else _target_prompt(workspace, manifest, data)
    print(prompt)
    return prompt


def index_harness_candidates(workspace: Path, manifest: TargetManifest, *, as_json: bool = False) -> list[dict[str, Any]]:
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    candidates = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    index = {
        "target": manifest.name,
        "source_dir": str(source_dir),
        "build_context": {
            "available": bool(build_context),
            "compile_commands": build_context.get("compile_commands"),
            "unit_count": build_context.get("unit_count", 0),
        },
        "candidates": candidates,
    }
    out_dir = ensure_dir(workspace / "workorders" / manifest.name / "indexes")
    write_json(out_dir / "latest-index.json", index)
    if as_json:
        print(json.dumps(index, indent=2, sort_keys=True))
    else:
        print(f"harness index: {rel_to(out_dir / 'latest-index.json', workspace)}")
        for item in candidates[:50]:
            ctx = "compile-db" if item.get("build_context", {}).get("has_compile_unit") else "heuristic"
            print(f"{item['score']} {ctx} {item['id']} {item['relative_file']}:{item['line']} {item['function']}({item['params']})")
    return candidates


def write_harness_work_order(
    workspace: Path,
    manifest: TargetManifest,
    *,
    limit: int = 8,
    as_json: bool = False,
) -> Path:
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    data["candidate_entrypoints"] = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    candidates = data["candidate_entrypoints"][:limit]
    run_dir = ensure_dir(workspace / "workorders" / manifest.name / f"{now_id()}-harness-work-order")
    prompts_dir = ensure_dir(run_dir / "prompts")

    work_order = {
        "target": manifest.name,
        "source_dir": str(source_dir),
        "created": run_dir.name,
        "manifest": manifest.to_dict(),
        "analysis": {
            "detection": data["detection"],
            "build_markers": data["build_markers"],
            "build_context": {
                "available": bool(build_context),
                "compile_commands": build_context.get("compile_commands"),
                "unit_count": build_context.get("unit_count", 0),
            },
            "public_headers": data["public_headers"],
            "sample_inputs": data["sample_inputs"],
            "dictionary_token_candidates": data["dictionary_token_candidates"],
        },
        "candidates": candidates,
        "validation_commands": [
            f"bin/fuzzctl --runtime native harness review {manifest.name}",
            f"bin/fuzzctl --runtime native harness validate {manifest.name} --build",
            f"bin/fuzzctl --runtime native smoke {manifest.name} --seconds 300",
            f"bin/fuzzctl --runtime native coverage {manifest.name}",
            f"bin/fuzzctl --runtime native harness blockers {manifest.name}",
            f"bin/fuzzctl --runtime native guide coverage {manifest.name}",
            f"bin/fuzzctl --runtime native harness score {manifest.name}",
        ],
        "rules": [
            "One narrow harness per parser/API surface.",
            "Do not hide crashes with signal handlers, catch-all handlers, or broad error swallowing.",
            "Do not use network, sleeps, shell commands, or nondeterminism inside the fuzz loop.",
            "Treat coverage as a harness-quality gate before long campaigns.",
            "Report only minimized reproducible sanitizer-backed crashes.",
        ],
    }

    for candidate in candidates:
        prompt = _candidate_prompt(workspace, manifest, data, candidate, build_context)
        (prompts_dir / f"{candidate['id']}.md").write_text(prompt, encoding="utf-8")

    write_json(run_dir / "harness-work-order.json", work_order)
    (run_dir / "README.md").write_text(_work_order_markdown(workspace, manifest, work_order), encoding="utf-8")
    index = "\n".join(f"- [{c['id']}]({c['id']}.md)" for c in candidates)
    (prompts_dir / "INDEX.md").write_text(f"# Candidate Prompts\n\n{index}\n", encoding="utf-8")

    if as_json:
        print(json.dumps(work_order, indent=2, sort_keys=True))
    else:
        print(f"harness work order: {rel_to(run_dir, workspace)}")
        if candidates:
            print("candidate prompts:")
            for candidate in candidates:
                print(f"- {candidate['id']}: {rel_to(prompts_dir / (candidate['id'] + '.md'), workspace)}")
        else:
            print("no candidates found; inspect public headers, tests, and sample inputs manually")
    return run_dir


def write_candidate_knowledge(
    workspace: Path,
    manifest: TargetManifest,
    *,
    candidate_id: str,
    as_json: bool = False,
    quiet: bool = False,
) -> Path:
    source_dir = manifest.source_dir(workspace)
    data = _ai_plan_data(source_dir)
    build_context = load_build_context(workspace, manifest)
    data["candidate_entrypoints"] = _enrich_candidates_with_context(data["candidate_entrypoints"], build_context)
    candidate = _candidate_by_id(data, candidate_id)
    assert candidate is not None
    context = _candidate_context(build_context, candidate)
    out_dir = ensure_dir(workspace / "workorders" / manifest.name / f"{now_id()}-knowledge-{candidate['id']}")
    knowledge = {
        "target": manifest.name,
        "candidate": candidate,
        "manifest": manifest.to_dict(),
        "source_dir": str(source_dir),
        "build_context": {
            "compile_commands": build_context.get("compile_commands"),
            "unit_count": build_context.get("unit_count", 0),
            "candidate_context": context,
        },
        "samples": data["sample_inputs"],
        "dictionary_token_candidates": data["dictionary_token_candidates"],
        "instructions": [
            "Write one narrow harness for this candidate only.",
            "Use the matching compile unit flags/includes when adding headers or build args.",
            "If compile fails, fix the harness or manifest/build args; do not weaken sanitizer flags.",
            "Validate with review, ASan+UBSan build, smoke, coverage, and blocker analysis.",
        ],
    }
    prompt = _candidate_prompt(workspace, manifest, data, candidate, build_context)
    write_json(out_dir / "knowledge.json", knowledge)
    (out_dir / "prompt.md").write_text(prompt, encoding="utf-8")
    if quiet:
        return out_dir
    if as_json:
        print(json.dumps(knowledge, indent=2, sort_keys=True))
    else:
        print(f"knowledge packet: {rel_to(out_dir, workspace)}")
        print(f"prompt: {rel_to(out_dir / 'prompt.md', workspace)}")
    return out_dir
