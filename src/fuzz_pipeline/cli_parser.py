from __future__ import annotations

import argparse
import os

from .cli_parser_corpus import add_corpus_parser
from .cli_parser_harness import add_harness_parser
from .util import default_workspace


RUNTIME_COMMANDS = {
    "build",
    "smoke",
    "run",
    "fuzztest",
    "triage",
    "advanced-triage",
    "minimize",
    "coverage",
    "monitor",
    "corpus",
    "crash-value",
    "readiness",
    "post-cycle",
    "hybrid",
    "verify",
}


def _add_workspace_parsers(sub: argparse._SubParsersAction) -> None:
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

    p = sub.add_parser("detect", help="detect language and build system")
    p.add_argument("path")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("init-target", help="create a starter target manifest")
    p.add_argument("path")
    p.add_argument("--name", required=True)
    p.add_argument("--force", action="store_true")


def _add_tools_parsers(sub: argparse._SubParsersAction) -> None:
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
    p_tools = tools_sub.add_parser("advanced", help="show optional advanced fuzzing tool readiness")
    p_tools.add_argument("--json", action="store_true")
    p_tools = tools_sub.add_parser("symcc-self-test", help="compile and run a tiny SymCC generation probe")
    p_tools.add_argument("--json", action="store_true")
    p_tools = tools_sub.add_parser("install-advanced", help="clone/install optional advanced fuzzing tools")
    p_tools.add_argument(
        "--tool",
        choices=["plan", "oss-fuzz-gen", "grammar-mutator", "symcc", "casr", "exploitable"],
        default="plan",
    )
    p_tools.add_argument("--dry-run", action="store_true")


def _add_build_run_parsers(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("build", help="build an instrumented target profile")
    p.add_argument("name")
    p.add_argument(
        "--profile",
        required=True,
        choices=[
            "afl_asan_ubsan",
            "afl_lto_cmplog",
            "libfuzzer_asan_ubsan",
            "fuzztest_asan_ubsan",
            "symcc",
            "coverage",
        ],
    )

    p = sub.add_parser("build-context", help="discover or generate compile database context")
    p.add_argument("name")
    p.add_argument("--generate", action="store_true")
    p.add_argument("--method", choices=["auto", "cmake", "bear", "synthetic"], default="auto")
    p.add_argument(
        "--refresh",
        action="store_true",
        help="regenerate context instead of reusing an existing compile database",
    )
    p.add_argument("--no-update-manifest", action="store_true")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("smoke", help="run a short harness/sanitizer validation")
    p.add_argument("name")
    p.add_argument("--seconds", type=int, default=300)
    p.add_argument("--leak-check", action="store_true", help="force ASan leak detection for libFuzzer smoke runs")

    p = sub.add_parser("run", help="run a fuzzing campaign")
    p.add_argument("name")
    p.add_argument("--engine", choices=["aflpp", "libfuzzer", "fuzztest", "all"], default="aflpp")
    p.add_argument("--hours", type=float, default=1.0)
    p.add_argument("--workers", type=int)

    p = sub.add_parser("fuzztest", help="run optional FuzzTest property harnesses")
    p.add_argument("name")
    p.add_argument("--seconds", type=int, default=300)
    p.add_argument("--test", help="FuzzTest --fuzz value, for example Suite.Property")

    p = sub.add_parser("status", help="show run status")
    p.add_argument("name")
    p.add_argument("--run")


def _add_monitoring_parsers(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("monitor", help="monitor a fuzzing run and emit actionable alerts")
    p.add_argument("name")
    p.add_argument("--run")
    p.add_argument("--once", action="store_true")
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--max-loops", type=int)
    p.add_argument("--webhook-url")
    p.add_argument("--no-alerts", action="store_true")
    p.add_argument("--no-triage", action="store_true")

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
    p_sup.add_argument(
        "--replace-mismatched",
        action="store_true",
        help="gracefully replace active AFL++ runs whose worker plan no longer matches the manifest",
    )
    p_sup.add_argument(
        "--replace-timeout",
        type=int,
        default=90,
        help="seconds to wait after SIGTERM before forcing stale fuzzing processes down",
    )
    p_sup.add_argument(
        "--leak-smoke-seconds",
        type=int,
        default=0,
        help="run leak-enabled libFuzzer smoke before each supervised campaign cycle",
    )


def _add_analysis_parsers(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("triage", help="deduplicate and classify crashes")
    p.add_argument("name")
    p.add_argument("--run")

    p = sub.add_parser("advanced-triage", help="run optional CASR/exploitable crash analysis")
    p.add_argument("name")
    p.add_argument("--run")
    p.add_argument("--no-exploitable", action="store_true")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("minimize", help="minimize unique crashes")
    p.add_argument("name")
    p.add_argument("--run")

    p = sub.add_parser("report", help="write Markdown reports")
    p.add_argument("name")
    p.add_argument("--run")

    p = sub.add_parser("crash-value", help="rank crashes by evidence, reachability, and reportability")
    p.add_argument("name")
    p.add_argument("--run")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-write", action="store_true", help="do not persist state/crash_value/<target>.json")

    p = sub.add_parser("readiness", help="audit target readiness without running new fuzzing work")
    p.add_argument("name")
    p.add_argument("--run")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-write", action="store_true", help="do not persist workorders/<target>/readiness")

    p = sub.add_parser("verify", help="run an A-to-Z production-readiness verifier")
    p.add_argument("name")
    p.add_argument("--run")
    p.add_argument("--deep", action="store_true", help="execute short FuzzTest and SymCC integration passes")
    p.add_argument("--fuzztest-seconds", type=int, default=10)
    p.add_argument("--symcc-seconds", type=int, default=10)
    p.add_argument("--send-alert", action="store_true", help="send a Discord verification result alert")
    p.add_argument("--json", action="store_true")


def _add_followup_parsers(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("post-cycle", help="run the full triage/corpus/coverage/guidance cleanup for one campaign")
    p.add_argument("name")
    p.add_argument("--run")
    p.add_argument("--coverage-inputs", type=int, default=5000)
    p.add_argument("--corpus-inputs", type=int, default=20000)
    p.add_argument("--webhook-url")
    p.add_argument("--no-alerts", action="store_true")
    p.add_argument("--fail-fast", action="store_true")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("coverage", help="generate LLVM coverage for seeds, queues, corpora, and minimized reproducers")
    p.add_argument("name")
    p.add_argument("--run")
    p.add_argument("--max-inputs", type=int, default=5000)

    p = sub.add_parser("guide", help="generate campaign guidance")
    guide_sub = p.add_subparsers(dest="guide_command", required=True)
    p_guide = guide_sub.add_parser("coverage", help="recommend coverage and harness improvements")
    p_guide.add_argument("name")
    p_guide.add_argument("--run")


def _add_hybrid_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("hybrid", help="hybrid fuzzing integrations")
    hybrid_sub = p.add_subparsers(dest="hybrid_command", required=True)
    p_hybrid = hybrid_sub.add_parser("symcc", help="run a SymCC helper pass against an AFL++ run")
    p_hybrid.add_argument("name")
    p_hybrid.add_argument("--run")
    p_hybrid.add_argument("--seconds", type=int, default=1800)
    p_hybrid.add_argument("--harness")
    p_hybrid.add_argument("--afl-instance")
    p_hybrid.add_argument("--all-harnesses", action="store_true")
    p_hybrid.add_argument(
        "--dry-run",
        action="store_true",
        help="write a target-aware SymCC plan without building or executing",
    )
    p_hybrid.add_argument("--json", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fuzzctl")
    parser.add_argument("--workspace", default=str(default_workspace()), help="fuzz-pipeline workspace")
    default_runtime = "native" if os.environ.get("FUZZ_PIPELINE_INSIDE_DOCKER") else "docker"
    parser.add_argument("--runtime", choices=["docker", "native"], default=default_runtime)
    sub = parser.add_subparsers(dest="command", required=True)

    _add_workspace_parsers(sub)
    _add_tools_parsers(sub)
    _add_build_run_parsers(sub)
    _add_monitoring_parsers(sub)
    _add_analysis_parsers(sub)
    _add_followup_parsers(sub)
    add_corpus_parser(sub)
    _add_hybrid_parser(sub)
    add_harness_parser(sub)

    return parser
