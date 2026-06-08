from __future__ import annotations

import base64
import re
import shutil
from pathlib import Path
from typing import Any

from .builder import build_profile, harness_binary
from .campaign import _file_target_argv
from .manifest import Harness, TargetManifest
from .util import FuzzCtlError, ensure_dir, find_latest_run, read_json, rel_to, run_cmd, short_hash, write_json


ASAN_RE = re.compile(r"ERROR: AddressSanitizer: ([a-zA-Z0-9_-]+)")
LSAN_RE = re.compile(r"ERROR: LeakSanitizer: detected memory leaks")
UBSAN_RE = re.compile(r"runtime error: ([^\n]+)")
STACK_RE = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+\s+(?:in\s+)?(.+)$", re.MULTILINE)


def _asan_env() -> dict[str, str]:
    return {
        "AFL_SKIP_CPUFREQ": "1",
        "ASAN_OPTIONS": (
            "abort_on_error=1:detect_leaks=1:detect_stack_use_after_return=1:"
            "strict_string_checks=1:symbolize=1:dedup_token=1"
        ),
        "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:print_stacktrace=1",
    }


def _crash_files(run_dir: Path) -> list[Path]:
    files: list[Path] = []
    for p in run_dir.rglob("*"):
        if not p.is_file():
            continue
        if p.name.startswith("id:") and "/crashes/" in p.as_posix():
            files.append(p)
        elif p.name.startswith(("crash-", "leak-", "oom-", "timeout-")):
            files.append(p)
    return sorted(files)


def _choose_harness(workspace: Path, manifest: TargetManifest, crash: Path) -> tuple[Harness, Path, str]:
    parts = crash.parts
    if "libfuzzer" in crash.parts:
        try:
            harness_name = parts[parts.index("libfuzzer") + 1]
        except (ValueError, IndexError):
            harness_name = None
        if harness_name:
            for h in manifest.harnesses:
                if h.type == "libfuzzer" and h.name == harness_name:
                    binary = harness_binary(workspace, manifest, "libfuzzer_asan_ubsan", h)
                    if binary.exists():
                        return h, binary, "libfuzzer_asan_ubsan"
        for h in manifest.harnesses:
            if h.type == "libfuzzer":
                binary = harness_binary(workspace, manifest, "libfuzzer_asan_ubsan", h)
                if binary.exists():
                    return h, binary, "libfuzzer_asan_ubsan"
    if "aflpp" in crash.parts:
        try:
            harness_name = parts[parts.index("aflpp") + 1]
        except (ValueError, IndexError):
            harness_name = None
        if harness_name:
            for h in manifest.harnesses:
                if h.type == "file" and h.name == harness_name:
                    binary = harness_binary(workspace, manifest, "afl_asan_ubsan", h)
                    if binary.exists():
                        return h, binary, "afl_asan_ubsan"
    for h in manifest.harnesses:
        if h.type == "file":
            binary = harness_binary(workspace, manifest, "afl_asan_ubsan", h)
            if binary.exists():
                return h, binary, "afl_asan_ubsan"
    for h in manifest.harnesses:
        if h.type == "libfuzzer":
            binary = harness_binary(workspace, manifest, "libfuzzer_asan_ubsan", h)
            if binary.exists():
                return h, binary, "libfuzzer_asan_ubsan"
    raise FuzzCtlError("no built harness binary found for crash reproduction")


def _repro_cmd(harness: Harness, binary: Path, testcase: Path) -> list[str]:
    if harness.type == "libfuzzer":
        return [str(binary), str(testcase)]
    return _file_target_argv(binary, harness, str(testcase))


def _profile_has_binaries(workspace: Path, manifest: TargetManifest, profile: str, harness_type: str) -> bool:
    harnesses = [h for h in manifest.harnesses if h.type == harness_type]
    return bool(harnesses) and all(harness_binary(workspace, manifest, profile, h).exists() for h in harnesses)


def _matching_libfuzzer_harness(
    workspace: Path,
    manifest: TargetManifest,
    file_harness: Harness,
) -> tuple[Harness, Path, str] | None:
    for harness in manifest.harnesses:
        if harness.type != "libfuzzer":
            continue
        if harness.source != file_harness.source:
            continue
        binary = harness_binary(workspace, manifest, "libfuzzer_asan_ubsan", harness)
        if binary.exists():
            return harness, binary, "libfuzzer_asan_ubsan"
    return None


def _better_sanitizer_repro(
    workspace: Path,
    manifest: TargetManifest,
    harness: Harness,
    crash: Path,
    result: Any,
) -> tuple[Harness, Path, str, list[str], Any]:
    if harness.type == "libfuzzer":
        binary = harness_binary(workspace, manifest, "libfuzzer_asan_ubsan", harness)
        return harness, binary, "libfuzzer_asan_ubsan", _repro_cmd(harness, binary, crash), result

    ctype = _crash_type(result.output, result.returncode)
    if ctype != "unknown-crash" and result.output.strip():
        binary = harness_binary(workspace, manifest, "afl_asan_ubsan", harness)
        return harness, binary, "afl_asan_ubsan", _repro_cmd(harness, binary, crash), result

    twin = _matching_libfuzzer_harness(workspace, manifest, harness)
    if twin is None:
        binary = harness_binary(workspace, manifest, "afl_asan_ubsan", harness)
        return harness, binary, "afl_asan_ubsan", _repro_cmd(harness, binary, crash), result

    twin_harness, twin_binary, twin_profile = twin
    cmd = _repro_cmd(twin_harness, twin_binary, crash)
    twin_result = run_cmd(cmd, cwd=manifest.source_dir(workspace), env=_asan_env(), timeout=max(5, manifest.timeout_ms // 1000 + 5))
    twin_type = _crash_type(twin_result.output, twin_result.returncode)
    if twin_result.returncode != 0 and (twin_type != "unknown-crash" or twin_result.output.strip()):
        return twin_harness, twin_binary, twin_profile, cmd, twin_result

    binary = harness_binary(workspace, manifest, "afl_asan_ubsan", harness)
    return harness, binary, "afl_asan_ubsan", _repro_cmd(harness, binary, crash), result


def _crash_type(output: str, returncode: int) -> str:
    m = ASAN_RE.search(output)
    if m:
        return m.group(1).lower()
    if LSAN_RE.search(output):
        return "memory-leak"
    m = UBSAN_RE.search(output)
    if m:
        text = m.group(1).lower()
        if "null pointer" in text or "null" in text:
            return "null-pointer-undefined-behavior"
        if "signed integer overflow" in text:
            return "signed-integer-overflow"
        return "undefined-behavior"
    if "SEGV" in output or returncode in {-11, 139}:
        return "segv"
    if returncode == 124:
        return "timeout"
    return "unknown-crash"


def _access(output: str) -> str:
    if re.search(r"\bWRITE of size\b|\bWRITE memory access\b", output):
        return "write"
    if re.search(r"\bREAD of size\b|\bREAD memory access\b", output):
        return "read"
    return "unknown"


def _severity(crash_type: str, access: str, output: str) -> tuple[str, str]:
    crash_type = crash_type.lower()
    critical = {
        "heap-use-after-free",
        "double-free",
        "bad-free",
        "attempting-free-on-address-which-was-not-malloc()-ed",
        "alloc-dealloc-mismatch",
    }
    if crash_type in critical:
        return "CRITICAL", "memory lifetime corruption with realistic exploitation potential"
    if "buffer-overflow" in crash_type and access == "write":
        return "CRITICAL", "attacker-controlled out-of-bounds write"
    if crash_type in {"heap-use-after-free", "stack-use-after-return"} and access == "write":
        return "CRITICAL", "attacker-controlled write through invalid lifetime"
    if "buffer-overflow" in crash_type and access == "read":
        return "HIGH", "out-of-bounds read may disclose memory or drive later corruption"
    if "use-after" in crash_type:
        return "HIGH", "use-after-free/read requires exploitability analysis"
    if crash_type == "signed-integer-overflow" and re.search(r"alloc|malloc|calloc|realloc|new", output, re.I):
        return "HIGH", "integer overflow appears near allocation or sizing logic"
    if crash_type == "memory-leak":
        return "LOW", "memory leak; security impact needs proof of attacker-amplified resource exhaustion"
    if "null" in crash_type or crash_type == "segv":
        return "MEDIUM", "crash/DoS by default; stronger impact needs boundary analysis"
    if crash_type == "timeout":
        return "MEDIUM", "potential denial of service through excessive processing"
    return "LOW", "stability issue unless impact analysis proves memory safety risk"


def _stack_state(output: str, crash_type: str) -> str:
    frames = []
    for match in STACK_RE.finditer(output):
        frame = re.sub(r"\s+at\s+.*", "", match.group(1)).strip()
        frame = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", frame)
        frames.append(frame)
        if len(frames) == 3:
            break
    if not frames:
        token = re.search(r"dedup_token:\s*([0-9a-fA-F]+)", output)
        if token:
            return f"{crash_type}:{token.group(1)}"
        return crash_type
    return crash_type + ":" + "|".join(frames)


def _preserve_reproducer_metadata(item: dict[str, Any], previous: dict[str, Any] | None) -> None:
    if not previous:
        return
    for key in ("minimized_path", "minimized_size", "reproducer_base64"):
        if key in previous:
            item[key] = previous[key]


def triage_run(workspace: Path, manifest: TargetManifest, run_id: str | None = None) -> Path:
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else find_latest_run(workspace, manifest.name)
    crashes = _crash_files(run_dir)
    if not crashes:
        print(f"no crashes found in {rel_to(run_dir, workspace)}")
        out = ensure_dir(run_dir / "triage")
        write_json(
            out / "unique_crashes.json",
            {
                "target": manifest.name,
                "run": str(run_dir),
                "raw_crashes": 0,
                "unique_crashes": 0,
                "duplicate_crashes": 0,
                "crashes": [],
            },
        )
        return out

    if any("aflpp" in c.parts for c in crashes) and not _profile_has_binaries(workspace, manifest, "afl_asan_ubsan", "file"):
        build_profile(workspace, manifest, "afl_asan_ubsan")
    if any("libfuzzer" in c.parts for c in crashes) and not _profile_has_binaries(workspace, manifest, "libfuzzer_asan_ubsan", "libfuzzer"):
        try:
            build_profile(workspace, manifest, "libfuzzer_asan_ubsan")
        except FuzzCtlError:
            pass

    out = ensure_dir(run_dir / "triage")
    previous_by_id: dict[str, dict[str, Any]] = {}
    previous_path = out / "unique_crashes.json"
    if previous_path.exists():
        try:
            previous_by_id = {
                str(item.get("id")): item
                for item in read_json(previous_path).get("crashes", [])
                if item.get("id")
            }
        except Exception:
            previous_by_id = {}
    traces = ensure_dir(out / "traces")
    by_state: dict[str, dict[str, Any]] = {}

    for crash in crashes:
        harness, binary, profile = _choose_harness(workspace, manifest, crash)
        cmd = _repro_cmd(harness, binary, crash)
        result = run_cmd(cmd, cwd=manifest.source_dir(workspace), env=_asan_env(), timeout=max(5, manifest.timeout_ms // 1000 + 5))
        harness, binary, profile, cmd, result = _better_sanitizer_repro(workspace, manifest, harness, crash, result)
        output = result.output
        ctype = _crash_type(output, result.returncode)
        access = _access(output)
        severity, impact = _severity(ctype, access, output)
        state = _stack_state(output, ctype)
        crash_id = short_hash(state)
        trace_path = traces / f"{crash_id}.txt"
        if not trace_path.exists() or trace_path.stat().st_size == 0:
            trace_path.write_text(output, encoding="utf-8", errors="replace")
        item = by_state.get(crash_id)
        if item is None:
            by_state[crash_id] = {
                "id": crash_id,
                "state": state,
                "type": ctype,
                "access": access,
                "severity": severity,
                "impact": impact,
                "reproducible": result.returncode != 0,
                "original_path": str(crash),
                "original_size": crash.stat().st_size,
                "harness": harness.name,
                "profile": profile,
                "binary": str(binary),
                "repro_cmd": cmd,
                "trace_path": str(trace_path),
                "duplicates": 0,
                "raw_artifacts": 1,
                "duplicate_artifacts": 0,
            }
            _preserve_reproducer_metadata(by_state[crash_id], previous_by_id.get(crash_id))
        else:
            item["duplicates"] = int(item["duplicates"]) + 1
            item["raw_artifacts"] = int(item["duplicates"]) + 1
            item["duplicate_artifacts"] = int(item["duplicates"])
            if crash.stat().st_size < int(item["original_size"]):
                item["original_path"] = str(crash)
                item["original_size"] = crash.stat().st_size
                item["harness"] = harness.name
                item["profile"] = profile
                item["binary"] = str(binary)
                item["repro_cmd"] = cmd

    result = {
        "target": manifest.name,
        "run": str(run_dir),
        "raw_crashes": len(crashes),
        "unique_crashes": len(by_state),
        "duplicate_crashes": max(0, len(crashes) - len(by_state)),
        "crashes": sorted(by_state.values(), key=lambda x: ("CRITICAL HIGH MEDIUM LOW".find(x["severity"]), x["type"])),
    }
    write_json(out / "unique_crashes.json", result)
    print(f"triaged {len(crashes)} crash files into {len(by_state)} unique states ({max(0, len(crashes) - len(by_state))} duplicates)")
    print(f"triage output: {rel_to(out, workspace)}")
    return out


def minimize_run(workspace: Path, manifest: TargetManifest, run_id: str | None = None) -> Path:
    run_dir = workspace / "runs" / manifest.name / run_id if run_id else find_latest_run(workspace, manifest.name)
    triage_file = run_dir / "triage" / "unique_crashes.json"
    if not triage_file.exists():
        triage_run(workspace, manifest, run_id)
    data = __import__("json").loads(triage_file.read_text(encoding="utf-8"))
    out = ensure_dir(run_dir / "minimized")
    for item in data.get("crashes", []):
        original = Path(item["original_path"])
        min_path = out / f"{item['id']}.bin"
        harness = next((h for h in manifest.harnesses if h.name == item["harness"]), None)
        binary = Path(item["binary"])
        minimized = False
        if harness and harness.type == "file" and shutil.which("afl-tmin"):
            cmd = ["afl-tmin", "-i", str(original), "-o", str(min_path), "--", *_file_target_argv(binary, harness)]
            result = run_cmd(cmd, cwd=manifest.source_dir(workspace), env=_asan_env(), timeout=120, print_cmd=True)
            minimized = result.returncode == 0 and min_path.exists()
        elif harness and harness.type == "libfuzzer":
            prefix = ensure_dir(out / f"{item['id']}-libfuzzer")
            cmd = [
                str(binary),
                "-minimize_crash=1",
                "-runs=10000",
                f"-artifact_prefix={prefix}/",
                str(original),
            ]
            result = run_cmd(cmd, cwd=manifest.source_dir(workspace), env=_asan_env(), timeout=30, print_cmd=True)
            candidates = sorted(
                p for p in prefix.iterdir()
                if p.is_file() and p.name.startswith(("crash-", "leak-", "oom-", "timeout-"))
            )
            if candidates:
                shutil.copy2(candidates[0], min_path)
                minimized = True
        if not minimized:
            shutil.copy2(original, min_path)
        item["minimized_path"] = str(min_path)
        item["minimized_size"] = min_path.stat().st_size
        item["reproducer_base64"] = base64.b64encode(min_path.read_bytes()).decode("ascii")
    write_json(triage_file, data)
    print(f"minimized reproducers: {rel_to(out, workspace)}")
    return out
