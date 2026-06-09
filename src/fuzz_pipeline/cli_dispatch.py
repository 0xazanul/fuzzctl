from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

from .advanced_triage import advanced_triage_run
from .alerts import test_alert
from .build_context import collect_build_context, print_build_context
from .builder import build_profile
from .campaign import run_campaign, run_fuzztest, smoke, status
from .cli_corpus import dispatch_corpus_command
from .cli_harness import dispatch_harness_command
from .coverage import coverage_run
from .coverage_guidance import coverage_guidance
from .crash_value import analyze_target_crash_value, print_crash_value
from .dashboard import serve_dashboard
from .detect import detect_target
from .docker_runtime import image_build
from .doctor import doctor
from .hybrid import symcc_hybrid_run
from .launch import launch_repo
from .manifest import create_manifest_from_path, load_manifest, save_manifest
from .monitor import monitor_loop, monitor_once
from .post_cycle import post_cycle_run
from .readiness import target_readiness
from .reporting import report_run
from .supervisor import campaign_loop, supervisor_status
from .tools import install_advanced, install_core, tools_advanced, tools_doctor, tools_symcc_self_test
from .triage import minimize_run, triage_run
from .util import FuzzCtlError, rel_to
from .verification import verify_pipeline


def _cmd_detect(args: Namespace) -> int:
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


def _cmd_init_target(args: Namespace, workspace: Path) -> int:
    manifest, detection = create_manifest_from_path(workspace, Path(args.path), args.name)
    path = workspace / "targets" / manifest.name / "target.json"
    if path.exists() and not args.force:
        raise FuzzCtlError(f"manifest already exists: {path}; pass --force to replace")
    saved = save_manifest(workspace, manifest)
    print(f"created {rel_to(saved, workspace)}")
    print(f"detected {detection.language} with {detection.build_system}; edit harness source before building if needed")
    return 0


def _dispatch_workspace_command(args: Namespace, workspace: Path) -> int | None:
    if args.command == "doctor":
        return doctor(workspace, as_json=args.json, fix_hints=args.fix_hints)
    if args.command == "image-build":
        return image_build(workspace)
    if args.command == "dashboard":
        serve_dashboard(workspace, args.host, args.port, token=args.token, token_env=args.token_env)
        return 0
    if args.command == "detect":
        return _cmd_detect(args)
    if args.command == "init-target":
        return _cmd_init_target(args, workspace)
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
    return None


def _dispatch_tools_command(args: Namespace, workspace: Path) -> int | None:
    if args.command == "alerts" and args.alerts_command == "test":
        test_alert(url=args.webhook_url, dry_run=args.dry_run)
        return 0
    if args.command != "tools":
        return None
    if args.tools_command == "doctor":
        return tools_doctor(workspace, as_json=args.json, deep=args.deep)
    if args.tools_command == "install-core":
        return install_core(workspace, dry_run=args.dry_run)
    if args.tools_command == "advanced":
        return tools_advanced(workspace, as_json=args.json)
    if args.tools_command == "symcc-self-test":
        return tools_symcc_self_test(workspace, as_json=args.json)
    if args.tools_command == "install-advanced":
        return install_advanced(workspace, tool=args.tool, dry_run=args.dry_run)
    return None


def _dispatch_build_and_run_command(args: Namespace, workspace: Path) -> int | None:
    if args.command == "build":
        build_profile(workspace, load_manifest(workspace, args.name), args.profile)
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
        smoke(workspace, load_manifest(workspace, args.name), args.seconds, leak_check=args.leak_check)
        return 0
    if args.command == "run":
        run_campaign(workspace, load_manifest(workspace, args.name), args.engine, args.hours, args.workers)
        return 0
    if args.command == "fuzztest":
        run_fuzztest(
            workspace,
            load_manifest(workspace, args.name),
            args.seconds,
            label="fuzztest",
            test_filter=args.test,
        )
        return 0
    if args.command == "status":
        status(workspace, args.name, args.run)
        return 0
    return None


def _dispatch_monitoring_command(args: Namespace, workspace: Path) -> int | None:
    if args.command == "monitor":
        manifest = load_manifest(workspace, args.name)
        monitor = monitor_once if args.once else monitor_loop
        kwargs = {
            "workspace": workspace,
            "manifest": manifest,
            "run_id": args.run,
            "webhook": args.webhook_url,
            "no_alerts": args.no_alerts,
            "triage": not args.no_triage,
        }
        if args.once:
            monitor(**kwargs)
        else:
            monitor(interval=args.interval, max_loops=args.max_loops, **kwargs)
        return 0
    if args.command == "supervisor" and args.supervisor_command == "status":
        manifest = load_manifest(workspace, args.name) if args.name else None
        supervisor_status(workspace, manifest, as_json=args.json)
        return 0
    if args.command == "supervisor" and args.supervisor_command == "campaign-loop":
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
    return None


def _dispatch_analysis_command(args: Namespace, workspace: Path) -> int | None:
    if args.command == "triage":
        triage_run(workspace, load_manifest(workspace, args.name), args.run)
        return 0
    if args.command == "advanced-triage":
        advanced_triage_run(
            workspace,
            load_manifest(workspace, args.name),
            run_id=args.run,
            use_exploitable=not args.no_exploitable,
            as_json=args.json,
        )
        return 0
    if args.command == "minimize":
        minimize_run(workspace, load_manifest(workspace, args.name), args.run)
        return 0
    if args.command == "report":
        report_run(workspace, load_manifest(workspace, args.name), args.run)
        return 0
    if args.command == "crash-value":
        manifest = load_manifest(workspace, args.name)
        result = analyze_target_crash_value(workspace, manifest, run_id=args.run, write=not args.no_write)
        print_crash_value(result, as_json=args.json)
        return 0
    if args.command == "readiness":
        target_readiness(
            workspace,
            load_manifest(workspace, args.name),
            run_id=args.run,
            as_json=args.json,
            write=not args.no_write,
        )
        return 0
    if args.command == "verify":
        result = verify_pipeline(
            workspace,
            load_manifest(workspace, args.name),
            run_id=args.run,
            deep=args.deep,
            fuzztest_seconds=args.fuzztest_seconds,
            symcc_seconds=args.symcc_seconds,
            send_alert=args.send_alert,
            as_json=args.json,
        )
        return 0 if result.get("status") in {"pass", "warn"} else 2
    return None


def _dispatch_followup_command(args: Namespace, workspace: Path) -> int | None:
    if args.command == "post-cycle":
        result = post_cycle_run(
            workspace,
            load_manifest(workspace, args.name),
            args.run,
            coverage_inputs=args.coverage_inputs,
            corpus_inputs=args.corpus_inputs,
            webhook=args.webhook_url,
            no_alerts=args.no_alerts,
            continue_on_error=not args.fail_fast,
        )
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("status") == "ok" else 1
    if args.command == "coverage":
        coverage_run(workspace, load_manifest(workspace, args.name), args.run, max_inputs=args.max_inputs)
        return 0
    if args.command == "corpus":
        return dispatch_corpus_command(args, workspace)
    if args.command == "guide" and args.guide_command == "coverage":
        coverage_guidance(workspace, load_manifest(workspace, args.name), args.run)
        return 0
    if args.command == "harness":
        return dispatch_harness_command(args, workspace)
    return None


def _dispatch_hybrid_command(args: Namespace, workspace: Path) -> int | None:
    if args.command != "hybrid" or args.hybrid_command != "symcc":
        return None
    result = symcc_hybrid_run(
        workspace,
        load_manifest(workspace, args.name),
        run_id=args.run,
        seconds=args.seconds,
        harness_name=args.harness,
        afl_instance=args.afl_instance,
        all_harnesses=args.all_harnesses,
        dry_run=args.dry_run,
    )
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") != "error" else 2


def dispatch_command(args: Namespace, workspace: Path) -> int | None:
    for dispatcher in (
        _dispatch_workspace_command,
        _dispatch_tools_command,
        _dispatch_build_and_run_command,
        _dispatch_monitoring_command,
        _dispatch_analysis_command,
        _dispatch_followup_command,
        _dispatch_hybrid_command,
    ):
        result = dispatcher(args, workspace)
        if result is not None:
            return result
    return None
