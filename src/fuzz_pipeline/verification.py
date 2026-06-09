from __future__ import annotations

import json
import os
import stat
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from .advanced_tools import advanced_tool_status
from .alerts import AlertEvent, _clean_env_value, send_discord
from .builder import build_profile
from .campaign_engines import run_fuzztest
from .grammar import _mutator_for
from .hybrid import symcc_hybrid_run
from .manifest import TargetManifest
from .symcc_tools import symcc_self_test
from .util import FuzzCtlError, ensure_dir, find_latest_run, now_id, read_json, rel_to, run_cmd, write_json


CheckFn = Callable[[], tuple[str, str, str]]


def _check(name: str, status: str, evidence: str, action: str = "") -> dict[str, str]:
    return {"name": name, "status": status, "evidence": evidence, "action": action}


def _run_check(name: str, fn: CheckFn) -> dict[str, str]:
    try:
        status, evidence, action = fn()
        return _check(name, status, evidence, action)
    except Exception as exc:
        return _check(name, "fail", f"{type(exc).__name__}: {exc}", "Inspect the command log and fix this gate.")


def _artifact_count(workspace: Path, manifest: TargetManifest, profile: str) -> int:
    path = workspace / "build" / manifest.name / profile / "build.json"
    if not path.exists():
        return 0
    try:
        data = read_json(path)
    except Exception:
        return 0
    return len(data.get("artifacts", []))


def _env_file_check() -> tuple[str, str, str]:
    path = Path.home() / ".config" / "fuzz-pipeline" / "env"
    if not path.exists():
        return "fail", f"missing {path}", "Create the permanent env file with DISCORD_WEBHOOK_URL and FUZZ_DASHBOARD_TOKEN."
    mode = stat.S_IMODE(path.stat().st_mode)
    text = path.read_text(encoding="utf-8", errors="replace")
    has_discord = any(line.startswith("DISCORD_WEBHOOK_URL=") and len(line.split("=", 1)[1].strip()) > 0 for line in text.splitlines())
    has_token = any(line.startswith("FUZZ_DASHBOARD_TOKEN=") and len(line.split("=", 1)[1].strip()) > 0 for line in text.splitlines())
    if mode != 0o600:
        return "fail", f"{path} mode={oct(mode)} discord={has_discord} dashboard_token={has_token}", f"Run `chmod 600 {path}`."
    if not has_discord or not has_token:
        return "fail", f"{path} mode={oct(mode)} discord={has_discord} dashboard_token={has_token}", "Persist both required env vars."
    return "pass", f"{path} mode={oct(mode)} discord=true dashboard_token=true", ""


def _dashboard_check() -> tuple[str, str, str]:
    url = "http://127.0.0.1:8089/healthz"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            body = response.read(256).decode("utf-8", errors="replace").strip()
            if response.status == 200:
                return "pass", f"{url} HTTP 200 {body}", ""
            return "fail", f"{url} HTTP {response.status}", "Restart fuzz-dashboard-lan.service."
    except urllib.error.URLError as exc:
        return "fail", f"{url} unavailable: {exc}", "Restart fuzz-dashboard-lan.service and check firewall only after local health passes."


def _advanced_tools_check(workspace: Path) -> tuple[str, str, str]:
    status = advanced_tool_status(workspace)
    ready = status.get("ready", {})
    failed = [name for name, value in ready.items() if not value]
    evidence = ", ".join(f"{name}={bool(value)}" for name, value in sorted(ready.items()))
    if failed:
        return "fail", evidence, f"Fix advanced tool gates: {', '.join(failed)}."
    return "pass", evidence, ""


def _oss_fuzz_gen_check(workspace: Path) -> tuple[str, str, str]:
    status = advanced_tool_status(workspace)["oss_fuzz_gen"]
    py = status.get("venv_python")
    marker = status.get("marker")
    if not py or not marker:
        return "fail", f"venv_python={py} marker={marker}", "Install OSS-Fuzz-Gen dependencies into its .venv."
    result = run_cmd([py, "-m", "py_compile", marker], timeout=30)
    if result.returncode != 0:
        return "fail", result.output[-1000:], "Repair the OSS-Fuzz-Gen local Python environment."
    return "pass", f"{py} can compile {marker}", ""


def _grammar_check(workspace: Path, manifest: TargetManifest) -> tuple[str, str, str]:
    configured = []
    for harness in manifest.harnesses:
        library = harness.env.get("AFL_CUSTOM_MUTATOR_LIBRARY")
        if not library:
            continue
        tree_dir = harness.env.get("AFL_GRAMMAR_TREE_DIR")
        only = harness.env.get("AFL_CUSTOM_MUTATOR_ONLY")
        configured.append((harness.name, library, tree_dir, only))
    mutator = _mutator_for(workspace, "json")
    if not configured:
        return "fail", f"json_mutator={mutator}", "Run `fuzzctl corpus grammar-configure <target> --format json --harness <file-harness>`."
    bad = [item for item in configured if not Path(item[1]).exists()]
    if bad:
        return "fail", f"missing_mutators={bad}", "Rebuild Grammar-Mutator and reconfigure the harness."
    only_enabled = [item[0] for item in configured if item[3] == "1"]
    if only_enabled:
        return "warn", f"configured={configured}", "AFL_CUSTOM_MUTATOR_ONLY is enabled; only use it for formats where grammar-only is intentional."
    return "pass", f"configured={configured}", ""


def _fuzztest_check(workspace: Path, manifest: TargetManifest, *, deep: bool, seconds: int) -> tuple[str, str, str]:
    harnesses = [h.name for h in manifest.harnesses if h.type == "fuzztest"]
    if not harnesses:
        return "fail", "harnesses=0", "Add a real FuzzTest harness and manifest entry."
    if deep:
        run_dir = run_fuzztest(
            workspace,
            manifest,
            seconds,
            label="verify-fuzztest",
            test_filter="CbMpcPublicApiBlobs.PublicApiBlobsNeverCrashes" if manifest.name == "cb-mpc" else None,
        )
        run_data = read_json(run_dir / "run.json")
        if run_data.get("status") != "complete":
            return "fail", f"{rel_to(run_dir, workspace)} status={run_data.get('status')}", "Inspect the FuzzTest run log."
        return "pass", f"{rel_to(run_dir, workspace)} harnesses={harnesses}", ""
    artifacts = _artifact_count(workspace, manifest, "fuzztest_asan_ubsan")
    if artifacts == 0:
        return "fail", f"harnesses={harnesses} artifacts=0", "Run `fuzzctl build <target> --profile fuzztest_asan_ubsan`."
    return "pass", f"harnesses={harnesses} artifacts={artifacts}", ""


def _symcc_check(workspace: Path, manifest: TargetManifest, *, deep: bool, seconds: int) -> tuple[str, str, str]:
    self_test = symcc_self_test(workspace, as_json=False)
    if self_test.get("status") != "ok":
        return "fail", json.dumps(self_test, sort_keys=True)[-1000:], "Fix SymCC before enabling hybrid deep dives."
    if deep:
        build_profile(workspace, manifest, "symcc")
        try:
            run_dir = find_latest_run(workspace, manifest.name)
        except FuzzCtlError:
            return "warn", "SymCC self-test passed, but no AFL++ run exists for helper integration.", "Start an AFL++ campaign before hybrid queue solving."
        result = symcc_hybrid_run(
            workspace,
            manifest,
            run_id=run_dir.name,
            seconds=seconds,
            harness_name="public_api_blobs_file" if manifest.name == "cb-mpc" else None,
            dry_run=False,
        )
        if result.get("status") in {"ok", "timeout_complete"}:
            return "pass", f"self_test=ok hybrid={result.get('status')} run={rel_to(run_dir, workspace)}", ""
        return "fail", json.dumps(result, sort_keys=True)[-1200:], "Inspect the SymCC hybrid packet and build log."
    artifacts = _artifact_count(workspace, manifest, "symcc")
    if artifacts == 0:
        return "fail", "self_test=ok artifacts=0", "Run `fuzzctl build <target> --profile symcc`."
    return "pass", f"self_test=ok artifacts={artifacts}", ""


def _build_artifact_check(workspace: Path, manifest: TargetManifest) -> tuple[str, str, str]:
    required = ["afl_asan_ubsan", "libfuzzer_asan_ubsan", "symcc", "fuzztest_asan_ubsan"]
    counts = {profile: _artifact_count(workspace, manifest, profile) for profile in required}
    missing = [profile for profile, count in counts.items() if count == 0]
    if missing:
        return "fail", json.dumps(counts, sort_keys=True), f"Build missing profiles: {', '.join(missing)}."
    return "pass", json.dumps(counts, sort_keys=True), ""


def _send_verification_alert(target: str, status: str, out_dir: Path, workspace: Path) -> tuple[str, str, str]:
    if not os.environ.get("DISCORD_WEBHOOK_URL"):
        env_file = Path.home() / ".config" / "fuzz-pipeline" / "env"
        if env_file.exists():
            for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("DISCORD_WEBHOOK_URL="):
                    os.environ["DISCORD_WEBHOOK_URL"] = _clean_env_value(line.split("=", 1)[1]) or ""
                    break
    sent = send_discord(
        AlertEvent(
            key=f"verification:{target}:{out_dir.name}",
            title=f"fuzz-pipeline verification: {target}",
            description=f"A-to-Z verification finished with status `{status}`.",
            severity="INFO" if status == "pass" else "ERROR",
            fields={"target": target, "packet": rel_to(out_dir, workspace)},
        )
    )
    return ("pass" if sent else "warn", f"sent={sent}", "Check DISCORD_WEBHOOK_URL if alert delivery was skipped.")


def verify_pipeline(
    workspace: Path,
    manifest: TargetManifest,
    *,
    run_id: str | None = None,
    deep: bool = False,
    fuzztest_seconds: int = 10,
    symcc_seconds: int = 10,
    send_alert: bool = False,
    as_json: bool = False,
) -> dict[str, Any]:
    del run_id
    out_dir = ensure_dir(workspace / "workorders" / manifest.name / "verification" / f"{now_id()}-a2z")
    checks: list[dict[str, str]] = []
    checks.append(_run_check("permanent env", _env_file_check))
    checks.append(_run_check("dashboard health", _dashboard_check))
    checks.append(_run_check("advanced tool readiness", lambda: _advanced_tools_check(workspace)))
    checks.append(_run_check("OSS-Fuzz-Gen local execution", lambda: _oss_fuzz_gen_check(workspace)))
    checks.append(_run_check("Grammar-Mutator campaign config", lambda: _grammar_check(workspace, manifest)))
    checks.append(_run_check("build artifacts", lambda: _build_artifact_check(workspace, manifest)))
    checks.append(_run_check("FuzzTest execution" if deep else "FuzzTest build", lambda: _fuzztest_check(workspace, manifest, deep=deep, seconds=fuzztest_seconds)))
    checks.append(_run_check("SymCC hybrid execution" if deep else "SymCC build", lambda: _symcc_check(workspace, manifest, deep=deep, seconds=symcc_seconds)))

    status = "pass"
    if any(item["status"] == "fail" for item in checks):
        status = "fail"
    elif any(item["status"] == "warn" for item in checks):
        status = "warn"
    if send_alert:
        checks.append(_run_check("Discord verification alert", lambda: _send_verification_alert(manifest.name, status, out_dir, workspace)))
        if checks[-1]["status"] == "fail":
            status = "fail"
        elif status == "pass" and checks[-1]["status"] == "warn":
            status = "warn"

    result: dict[str, Any] = {
        "target": manifest.name,
        "status": status,
        "mode": "deep" if deep else "shallow",
        "checks": checks,
        "packet": str(out_dir),
    }
    write_json(out_dir / "a2z-verification.json", result)
    lines = [f"# A-to-Z Verification: {manifest.name}", "", f"- Status: `{status}`", f"- Mode: `{'deep' if deep else 'shallow'}`", ""]
    lines.append("| Check | Status | Evidence | Action |")
    lines.append("| --- | --- | --- | --- |")
    for item in checks:
        evidence = item["evidence"].replace("|", "\\|").replace("\n", " ")
        action = item["action"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {item['name']} | `{item['status']}` | {evidence} | {action} |")
    (out_dir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"A-to-Z verification {manifest.name}: {status} -> {rel_to(out_dir, workspace)}")
        for item in checks:
            print(f"  {item['status']:4} {item['name']}: {item['evidence']}")
    return result
