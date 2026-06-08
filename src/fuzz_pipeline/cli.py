from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .build_context import collect_build_context, print_build_context
from .builder import build_profile
from .campaign import run_campaign, smoke, status
from .coverage import coverage_run
from .coverage_guidance import coverage_guidance
from .corpus import corpus_enrich, corpus_prune_crashers, corpus_sync
from .alerts import test_alert
from .dashboard import serve_dashboard
from .detect import detect_target
from .docker_runtime import image_build, run_in_docker
from .doctor import doctor
from .harness import (
    harness_blockers,
    harness_ai_plan,
    harness_prompt,
    index_harness_candidates,
    iterate_harness,
    review_harnesses,
    scan_harness_points,
    scaffold_harness,
    score_harnesses,
    synthesize_harness_attempt,
    validate_harnesses,
    write_candidate_knowledge,
    write_harness_work_order,
)
from .launch import launch_repo
from .manifest import create_manifest_from_path, load_manifest, save_manifest
from .monitor import monitor_loop, monitor_once
from .reporting import report_run
from .supervisor import campaign_loop, supervisor_status
from .tools import install_core, tools_doctor
from .triage import minimize_run, triage_run
from .util import FuzzCtlError, default_workspace, rel_to


RUNTIME_COMMANDS = {"build", "smoke", "run", "triage", "minimize", "coverage", "monitor", "corpus"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fuzzctl")
    parser.add_argument("--workspace", default=str(default_workspace()), help="fuzz-pipeline workspace")
    default_runtime = "native" if os.environ.get("FUZZ_PIPELINE_INSIDE_DOCKER") else "docker"
    parser.add_argument("--runtime", choices=["docker", "native"], default=default_runtime)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("doctor", help="verify host and toolchain readiness")
    p.add_argument("--json", action="store_true")
    p.add_argument("--fix-hints", action="store_true", help="print explicit root commands for host fuzzing tunables")

    sub.add_parser("image-build", help="build the local Docker image")

    p = sub.add_parser("dashboard", help="serve the browser dashboard")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8088)
    p.add_argument("--token", help="require this dashboard token")
    p.add_argument("--token-env", default="FUZZ_DASHBOARD_TOKEN", help="environment variable for dashboard token")

    p = sub.add_parser("launch", help="clone/onboard a repo and run what is safely possible")
    p.add_argument("source", help="Git URL or local path")
    p.add_argument("--name")
    p.add_argument("--update", action="store_true")
    p.add_argument("--force-manifest", action="store_true")
    p.add_argument("--smoke-seconds", type=int, default=0)
    p.add_argument("--campaign-hours", type=float, default=0.0)
    p.add_argument("--workers", type=int)

    p = sub.add_parser("alerts", help="Discord webhook alerts")
    alerts_sub = p.add_subparsers(dest="alerts_command", required=True)
    p_alert = alerts_sub.add_parser("test", help="send or print a test Discord alert")
    p_alert.add_argument("--webhook-url")
    p_alert.add_argument("--dry-run", action="store_true")

    p = sub.add_parser("tools", help="toolchain inventory and installation")
    tools_sub = p.add_subparsers(dest="tools_command", required=True)
    p_tools = tools_sub.add_parser("doctor", help="verify curated core fuzzing tools")
    p_tools.add_argument("--json", action="store_true")
    p_tools.add_argument("--deep", action="store_true")
    p_tools = tools_sub.add_parser("install-core", help="install missing apt-backed core tools")
    p_tools.add_argument("--dry-run", action="store_true")

    p = sub.add_parser("detect", help="detect language and build system")
    p.add_argument("path")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("init-target", help="create a starter target manifest")
    p.add_argument("path")
    p.add_argument("--name", required=True)
    p.add_argument("--force", action="store_true")

    p = sub.add_parser("build", help="build an instrumented target profile")
    p.add_argument("name")
    p.add_argument("--profile", required=True, choices=["afl_asan_ubsan", "afl_lto_cmplog", "libfuzzer_asan_ubsan", "coverage"])

    p = sub.add_parser("build-context", help="discover or generate compile database context")
    p.add_argument("name")
    p.add_argument("--generate", action="store_true")
    p.add_argument("--method", choices=["auto", "cmake", "bear", "synthetic"], default="auto")
    p.add_argument("--refresh", action="store_true", help="regenerate context instead of reusing an existing compile database")
    p.add_argument("--no-update-manifest", action="store_true")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("smoke", help="run a short harness/sanitizer validation")
    p.add_argument("name")
    p.add_argument("--seconds", type=int, default=300)
    p.add_argument("--leak-check", action="store_true", help="force ASan leak detection for libFuzzer smoke runs")

    p = sub.add_parser("run", help="run a fuzzing campaign")
    p.add_argument("name")
    p.add_argument("--engine", choices=["aflpp", "libfuzzer", "all"], default="aflpp")
    p.add_argument("--hours", type=float, default=1.0)
    p.add_argument("--workers", type=int)

    p = sub.add_parser("status", help="show run status")
    p.add_argument("name")
    p.add_argument("--run")

    p = sub.add_parser("monitor", help="monitor a fuzzing run and emit actionable alerts")
    p.add_argument("name")
    p.add_argument("--run")
    p.add_argument("--once", action="store_true")
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--max-loops", type=int)
    p.add_argument("--webhook-url")
    p.add_argument("--no-alerts", action="store_true")
    p.add_argument("--no-triage", action="store_true")

    p = sub.add_parser("triage", help="deduplicate and classify crashes")
    p.add_argument("name")
    p.add_argument("--run")

    p = sub.add_parser("minimize", help="minimize unique crashes")
    p.add_argument("name")
    p.add_argument("--run")

    p = sub.add_parser("report", help="write Markdown reports")
    p.add_argument("name")
    p.add_argument("--run")

    p = sub.add_parser("coverage", help="generate LLVM coverage for seeds, queues, corpora, and minimized reproducers")
    p.add_argument("name")
    p.add_argument("--run")
    p.add_argument("--max-inputs", type=int, default=5000)

    p = sub.add_parser("corpus", help="corpus collection, minimization, and promotion")
    corpus_sub = p.add_subparsers(dest="corpus_command", required=True)
    p_corpus = corpus_sub.add_parser("sync", help="dedupe and minimize seed/queue/libFuzzer corpora")
    p_corpus.add_argument("name")
    p_corpus.add_argument("--run")
    p_corpus.add_argument("--max-inputs", type=int, default=20000)
    p_corpus = corpus_sub.add_parser("enrich", help="write per-harness deterministic seeds and optional Radamsa mutations")
    p_corpus.add_argument("name")
    p_corpus.add_argument("--mutations-per-input", type=int, default=0)
    p_corpus.add_argument("--overwrite", action="store_true")
    p_corpus.add_argument("--prune-crashers", action="store_true", help="quarantine seeds that crash ASan/UBSan file harnesses")
    p_corpus.add_argument("--prune-timeout", type=float, default=2.0, help="seconds allowed per seed when pruning crashers")
    p_corpus = corpus_sub.add_parser("prune-crashers", help="quarantine curated seeds that crash ASan/UBSan file harnesses")
    p_corpus.add_argument("name")
    p_corpus.add_argument("--harness", action="append", dest="harnesses", help="file harness name to check; may be repeated")
    p_corpus.add_argument("--timeout", type=float, default=2.0, help="seconds allowed per seed")

    p = sub.add_parser("supervisor", help="reboot-safe campaign supervision")
    supervisor_sub = p.add_subparsers(dest="supervisor_command", required=True)
    p_sup = supervisor_sub.add_parser("status", help="show active campaign and supervisor state")
    p_sup.add_argument("name", nargs="?")
    p_sup.add_argument("--json", action="store_true")
    p_sup = supervisor_sub.add_parser("campaign-loop", help="wait for existing fuzzing, then run continuous campaigns")
    p_sup.add_argument("name")
    p_sup.add_argument("--engine", choices=["aflpp", "libfuzzer", "all"], default="aflpp")
    p_sup.add_argument("--hours", type=float, default=24.0)
    p_sup.add_argument("--workers", type=int)
    p_sup.add_argument("--wait-interval", type=int, default=60)
    p_sup.add_argument("--max-cycles", type=int)
    p_sup.add_argument("--no-post-cycle", action="store_true")
    p_sup.add_argument("--coverage-inputs", type=int, default=5000)
    p_sup.add_argument("--replace-mismatched", action="store_true", help="gracefully replace active AFL++ runs whose worker plan no longer matches the manifest")
    p_sup.add_argument("--replace-timeout", type=int, default=90, help="seconds to wait after SIGTERM before forcing stale fuzzing processes down")
    p_sup.add_argument("--leak-smoke-seconds", type=int, default=0, help="run leak-enabled libFuzzer smoke before each supervised campaign cycle")

    p = sub.add_parser("guide", help="generate campaign guidance")
    guide_sub = p.add_subparsers(dest="guide_command", required=True)
    p_guide = guide_sub.add_parser("coverage", help="recommend coverage and harness improvements")
    p_guide.add_argument("name")
    p_guide.add_argument("--run")

    p = sub.add_parser("harness", help="scan, scaffold, and validate fuzz harnesses")
    harness_sub = p.add_subparsers(dest="harness_command", required=True)
    p_h = harness_sub.add_parser("ai-plan", help="emit an AI-ready harness plan for a repo")
    p_h.add_argument("path")
    p_h.add_argument("--json", action="store_true")
    p_h = harness_sub.add_parser("index", help="write a compile-aware harness candidate index")
    p_h.add_argument("target")
    p_h.add_argument("--json", action="store_true")
    p_h = harness_sub.add_parser("knowledge", help="write a single-candidate knowledge packet")
    p_h.add_argument("target")
    p_h.add_argument("--candidate", required=True)
    p_h.add_argument("--json", action="store_true")
    p_h = harness_sub.add_parser("prompt", help="print a Codex-ready harness authoring prompt for a target")
    p_h.add_argument("target")
    p_h.add_argument("--candidate", help="candidate id or function name from ai-plan/work-order")
    p_h = harness_sub.add_parser("synthesize", help="create and compile an AI harness attempt packet")
    p_h.add_argument("target")
    p_h.add_argument("--candidate", required=True)
    p_h.add_argument("--source", help="existing harness source to compile instead of the generated draft")
    p_h.add_argument("--attempts", type=int, default=5, help="repair attempts to allow in the generated prompt")
    p_h.add_argument("--json", action="store_true")
    p_h = harness_sub.add_parser("blockers", help="derive harness blockers from LLVM coverage")
    p_h.add_argument("target")
    p_h.add_argument("--run")
    p_h.add_argument("--json", action="store_true")
    p_h = harness_sub.add_parser("iterate", help="write a coverage-guided harness iteration packet")
    p_h.add_argument("target")
    p_h.add_argument("--candidate", help="candidate id or function name")
    p_h.add_argument("--run")
    p_h = harness_sub.add_parser("work-order", help="write a full AI harness work-order packet")
    p_h.add_argument("target")
    p_h.add_argument("--limit", type=int, default=8)
    p_h.add_argument("--json", action="store_true")
    p_h = harness_sub.add_parser("review", help="review harness code for fuzz-loop safety")
    p_h.add_argument("target")
    p_h.add_argument("--json", action="store_true")
    p_h = harness_sub.add_parser("score", help="score harness readiness from review, builds, seeds, and coverage")
    p_h.add_argument("target")
    p_h.add_argument("--run")
    p_h.add_argument("--json", action="store_true")
    p_h = harness_sub.add_parser("scan", help="scan a repo for likely harness entrypoints")
    p_h.add_argument("path")
    p_h.add_argument("--json", action="store_true")
    p_h = harness_sub.add_parser("scaffold", help="create a reviewed harness template")
    p_h.add_argument("target")
    p_h.add_argument("--type", choices=["libfuzzer", "file", "stdin"], required=True)
    p_h.add_argument("--harness-name", default="candidate")
    p_h.add_argument("--function")
    p_h = harness_sub.add_parser("validate", help="validate harness manifest shape")
    p_h.add_argument("target")
    p_h.add_argument("--build", action="store_true")

    return parser


def _maybe_docker(args: argparse.Namespace, argv: list[str], workspace: Path) -> int | None:
    if args.command not in RUNTIME_COMMANDS:
        return None
    if args.runtime != "docker":
        return None
    if os.environ.get("FUZZ_PIPELINE_INSIDE_DOCKER"):
        return None
    return run_in_docker(workspace, argv)


def _cmd_detect(args: argparse.Namespace) -> int:
    detection = detect_target(Path(args.path))
    if args.json:
        print(json.dumps(detection.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"path: {detection.path}")
        print(f"supported: {detection.supported}")
        print(f"language: {detection.language}")
        print(f"build_system: {detection.build_system}")
        print(f"c_files: {detection.c_files}")
        print(f"cpp_files: {detection.cpp_files}")
        print(f"reason: {detection.reason}")
    return 0 if detection.supported else 2


def _cmd_init_target(args: argparse.Namespace, workspace: Path) -> int:
    manifest, detection = create_manifest_from_path(workspace, Path(args.path), args.name)
    path = workspace / "targets" / manifest.name / "target.json"
    if path.exists() and not args.force:
        raise FuzzCtlError(f"manifest already exists: {path}; pass --force to replace")
    saved = save_manifest(workspace, manifest)
    print(f"created {rel_to(saved, workspace)}")
    print(f"detected {detection.language} with {detection.build_system}; edit harness source before building if needed")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _parser()
    args = parser.parse_args(argv)
    workspace = Path(args.workspace).expanduser().resolve()

    try:
        docker_rc = _maybe_docker(args, argv, workspace)
        if docker_rc is not None:
            return docker_rc

        if args.command == "doctor":
            return doctor(workspace, as_json=args.json, fix_hints=args.fix_hints)
        if args.command == "image-build":
            return image_build(workspace)
        if args.command == "dashboard":
            serve_dashboard(workspace, args.host, args.port, token=args.token, token_env=args.token_env)
            return 0
        if args.command == "launch":
            launch_repo(
                workspace,
                args.source,
                name=args.name,
                update=args.update,
                force_manifest=args.force_manifest,
                smoke_seconds=args.smoke_seconds,
                campaign_hours=args.campaign_hours,
                workers=args.workers,
            )
            return 0
        if args.command == "alerts":
            if args.alerts_command == "test":
                test_alert(url=args.webhook_url, dry_run=args.dry_run)
                return 0
        if args.command == "tools":
            if args.tools_command == "doctor":
                return tools_doctor(workspace, as_json=args.json, deep=args.deep)
            if args.tools_command == "install-core":
                return install_core(workspace, dry_run=args.dry_run)
        if args.command == "detect":
            return _cmd_detect(args)
        if args.command == "init-target":
            return _cmd_init_target(args, workspace)
        if args.command == "build":
            manifest = load_manifest(workspace, args.name)
            build_profile(workspace, manifest, args.profile)
            return 0
        if args.command == "build-context":
            manifest = load_manifest(workspace, args.name)
            context = collect_build_context(
                workspace,
                manifest,
                generate=args.generate,
                method=args.method,
                update_manifest=not args.no_update_manifest,
                print_cmd=not args.json,
                refresh=args.refresh,
            )
            print_build_context(context, as_json=args.json)
            return 0
        if args.command == "smoke":
            manifest = load_manifest(workspace, args.name)
            smoke(workspace, manifest, args.seconds, leak_check=args.leak_check)
            return 0
        if args.command == "run":
            manifest = load_manifest(workspace, args.name)
            run_campaign(workspace, manifest, args.engine, args.hours, args.workers)
            return 0
        if args.command == "status":
            status(workspace, args.name, args.run)
            return 0
        if args.command == "monitor":
            manifest = load_manifest(workspace, args.name)
            if args.once:
                monitor_once(
                    workspace,
                    manifest,
                    run_id=args.run,
                    webhook=args.webhook_url,
                    no_alerts=args.no_alerts,
                    triage=not args.no_triage,
                )
            else:
                monitor_loop(
                    workspace,
                    manifest,
                    run_id=args.run,
                    interval=args.interval,
                    max_loops=args.max_loops,
                    webhook=args.webhook_url,
                    no_alerts=args.no_alerts,
                    triage=not args.no_triage,
                )
            return 0
        if args.command == "triage":
            manifest = load_manifest(workspace, args.name)
            triage_run(workspace, manifest, args.run)
            return 0
        if args.command == "minimize":
            manifest = load_manifest(workspace, args.name)
            minimize_run(workspace, manifest, args.run)
            return 0
        if args.command == "report":
            manifest = load_manifest(workspace, args.name)
            report_run(workspace, manifest, args.run)
            return 0
        if args.command == "coverage":
            manifest = load_manifest(workspace, args.name)
            coverage_run(workspace, manifest, args.run, max_inputs=args.max_inputs)
            return 0
        if args.command == "corpus":
            if args.corpus_command == "sync":
                manifest = load_manifest(workspace, args.name)
                corpus_sync(workspace, manifest, args.run, max_inputs=args.max_inputs)
                return 0
            if args.corpus_command == "enrich":
                manifest = load_manifest(workspace, args.name)
                corpus_enrich(
                    workspace,
                    manifest,
                    mutations_per_input=args.mutations_per_input,
                    overwrite=args.overwrite,
                )
                if args.prune_crashers:
                    corpus_prune_crashers(workspace, manifest, timeout_seconds=args.prune_timeout)
                return 0
            if args.corpus_command == "prune-crashers":
                manifest = load_manifest(workspace, args.name)
                corpus_prune_crashers(workspace, manifest, harness_names=args.harnesses, timeout_seconds=args.timeout)
                return 0
            return 0
        if args.command == "supervisor":
            if args.supervisor_command == "status":
                manifest = load_manifest(workspace, args.name) if args.name else None
                supervisor_status(workspace, manifest, as_json=args.json)
                return 0
            if args.supervisor_command == "campaign-loop":
                manifest = load_manifest(workspace, args.name)
                return campaign_loop(
                    workspace,
                    manifest,
                    engine=args.engine,
                    hours=args.hours,
                    workers=args.workers,
                    wait_interval=args.wait_interval,
                    max_cycles=args.max_cycles,
                    post_cycle=not args.no_post_cycle,
                    coverage_inputs=args.coverage_inputs,
                    replace_mismatched=args.replace_mismatched,
                    replace_timeout=args.replace_timeout,
                    leak_smoke_seconds=args.leak_smoke_seconds,
                )
        if args.command == "guide":
            if args.guide_command == "coverage":
                manifest = load_manifest(workspace, args.name)
                coverage_guidance(workspace, manifest, args.run)
                return 0
        if args.command == "harness":
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
            if args.harness_command == "blockers":
                manifest = load_manifest(workspace, args.target)
                harness_blockers(workspace, manifest, run_id=args.run, as_json=args.json)
                return 0
            if args.harness_command == "iterate":
                manifest = load_manifest(workspace, args.target)
                iterate_harness(workspace, manifest, candidate_id=args.candidate, run_id=args.run)
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
    except FuzzCtlError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    parser.error(f"unhandled command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
