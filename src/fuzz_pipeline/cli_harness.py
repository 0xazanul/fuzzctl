from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from .fuzztest import write_fuzztest_plan, write_fuzztest_template
from .harness import (
    harness_ai_plan,
    harness_blockers,
    harness_prompt,
    harness_qa,
    index_harness_candidates,
    iterate_harness,
    review_harnesses,
    scan_harness_points,
    scaffold_harness,
    score_harnesses,
    synthesize_harness_attempt,
    suspicious_points,
    validate_harnesses,
    write_candidate_knowledge,
    write_harness_work_order,
)
from .manifest import load_manifest
from .oss_fuzz_gen import write_llm_gen_workorder


def dispatch_harness_command(args: Namespace, workspace: Path) -> int:
    if args.harness_command == "ai-plan":
        harness_ai_plan(Path(args.path), as_json=args.json)
        return 0
    if args.harness_command == "index":
        manifest = load_manifest(workspace, args.target)
        index_harness_candidates(workspace, manifest, as_json=args.json)
        return 0
    if args.harness_command == "knowledge":
        manifest = load_manifest(workspace, args.target)
        write_candidate_knowledge(workspace, manifest, candidate_id=args.candidate, as_json=args.json)
        return 0
    if args.harness_command == "prompt":
        manifest = load_manifest(workspace, args.target)
        harness_prompt(workspace, manifest, candidate_id=args.candidate)
        return 0
    if args.harness_command == "synthesize":
        manifest = load_manifest(workspace, args.target)
        source = Path(args.source) if args.source else None
        synthesize_harness_attempt(
            workspace,
            manifest,
            candidate_id=args.candidate,
            source=source,
            attempts=args.attempts,
            as_json=args.json,
        )
        return 0
    if args.harness_command == "llm-gen":
        manifest = load_manifest(workspace, args.target)
        write_llm_gen_workorder(
            workspace,
            manifest,
            candidate_id=args.candidate,
            backend=args.backend,
            as_json=args.json,
        )
        return 0
    if args.harness_command == "blockers":
        manifest = load_manifest(workspace, args.target)
        harness_blockers(workspace, manifest, run_id=args.run, as_json=args.json)
        return 0
    if args.harness_command == "suspicious-points":
        manifest = load_manifest(workspace, args.target)
        suspicious_points(workspace, manifest, run_id=args.run, limit=args.limit, as_json=args.json)
        return 0
    if args.harness_command == "qa":
        manifest = load_manifest(workspace, args.target)
        harness_qa(workspace, manifest, candidate_id=args.candidate, run_id=args.run, as_json=args.json)
        return 0
    if args.harness_command == "iterate":
        manifest = load_manifest(workspace, args.target)
        iterate_harness(workspace, manifest, candidate_id=args.candidate, run_id=args.run)
        return 0
    if args.harness_command == "fuzztest-plan":
        manifest = load_manifest(workspace, args.target)
        write_fuzztest_plan(workspace, manifest, as_json=args.json)
        return 0
    if args.harness_command == "fuzztest-generate":
        manifest = load_manifest(workspace, args.target)
        write_fuzztest_template(
            workspace,
            manifest,
            candidate_id=args.candidate,
            property_kind=args.property,
            as_json=args.json,
        )
        return 0
    if args.harness_command == "work-order":
        manifest = load_manifest(workspace, args.target)
        write_harness_work_order(workspace, manifest, limit=args.limit, as_json=args.json)
        return 0
    if args.harness_command == "review":
        manifest = load_manifest(workspace, args.target)
        return review_harnesses(workspace, manifest, as_json=args.json)
    if args.harness_command == "score":
        manifest = load_manifest(workspace, args.target)
        score_harnesses(workspace, manifest, run_id=args.run, as_json=args.json)
        return 0
    if args.harness_command == "scan":
        scan_harness_points(Path(args.path), as_json=args.json)
        return 0
    if args.harness_command == "scaffold":
        manifest = load_manifest(workspace, args.target)
        scaffold_harness(
            workspace,
            manifest,
            harness_type=args.type,
            name=args.harness_name,
            function=args.function,
        )
        return 0
    if args.harness_command == "validate":
        manifest = load_manifest(workspace, args.target)
        return validate_harnesses(workspace, manifest, build=args.build)
    return 0
