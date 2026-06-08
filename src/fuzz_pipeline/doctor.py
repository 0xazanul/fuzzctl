from __future__ import annotations

import json
import os
from pathlib import Path

from .docker_runtime import IMAGE, docker_access, image_exists
from .util import free_disk_bytes, human_bytes, which, which_any


REQUIRED_HOST = ["python3", "docker"]
REQUIRED_NATIVE = [
    "clang",
    "clang++",
    "afl-fuzz",
    "afl-clang-fast",
    "afl-clang-lto",
    "afl-cmin",
    "afl-tmin",
]
LLVM_TOOLS = ["llvm-symbolizer", "llvm-cov", "llvm-profdata"]


def _tool_path(cmd: str) -> str | None:
    if cmd.startswith("llvm-"):
        return which_any([cmd, f"{cmd}-18", f"{cmd}-17", f"{cmd}-16", f"{cmd}-15"])
    return which(cmd)


def _core_pattern_fix_hints() -> list[str]:
    return [
        "sudo sysctl -w kernel.core_pattern=core",
        "sudo sysctl -w kernel.core_uses_pid=0",
        "printf 'kernel.core_pattern=core\\nkernel.core_uses_pid=0\\n' | sudo tee /etc/sysctl.d/zz-fuzz-pipeline-core.conf",
        "sudo sysctl --system",
    ]


def doctor(workspace: Path, *, as_json: bool = False, fix_hints: bool = False) -> int:
    checks: list[dict[str, object]] = []
    ok = True

    for cmd in REQUIRED_HOST:
        path = _tool_path(cmd)
        checks.append({"name": cmd, "ok": bool(path), "path": path})
        ok = ok and bool(path)

    for cmd in REQUIRED_NATIVE:
        path = _tool_path(cmd)
        checks.append({"name": cmd, "ok": bool(path), "path": path, "scope": "native"})

    for cmd in LLVM_TOOLS:
        path = _tool_path(cmd)
        checks.append({"name": cmd, "ok": bool(path), "path": path, "scope": "llvm"})

    disk_free = free_disk_bytes(workspace)
    disk_ok = disk_free >= 3 * 1024 * 1024 * 1024
    ok = ok and disk_ok
    docker_ok, docker_error = docker_access() if which("docker") else (False, "docker binary missing")
    ok = ok and docker_ok
    docker_image = image_exists() if docker_ok else False
    core_pattern = None
    core_pattern_warning = False
    core_path = Path("/proc/sys/kernel/core_pattern")
    if core_path.exists():
        core_pattern = core_path.read_text(encoding="utf-8", errors="replace").strip()
        core_pattern_warning = core_pattern.startswith("|")

    result = {
        "workspace": str(workspace),
        "cpu_count": os.cpu_count() or 1,
        "disk_free": disk_free,
        "disk_free_human": human_bytes(disk_free),
        "disk_ok": disk_ok,
        "docker_image": IMAGE,
        "docker_access_ok": docker_ok,
        "docker_access_error": docker_error,
        "docker_image_exists": docker_image,
        "core_pattern": core_pattern,
        "core_pattern_warning": core_pattern_warning,
        "core_pattern_fix_hints": _core_pattern_fix_hints() if core_pattern_warning else [],
        "checks": checks,
        "ok": ok,
    }

    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"workspace: {workspace}")
        print(f"cpu: {result['cpu_count']}")
        print(f"free disk: {result['disk_free_human']} ({'ok' if disk_ok else 'low'})")
        print(f"docker access: {'ok' if docker_ok else 'not usable'}")
        if not docker_ok:
            print(f"docker error: {docker_error}")
        print(f"docker image: {IMAGE} ({'present' if docker_image else 'missing'})")
        if core_pattern is not None:
            state = "piped, AFL++ will use compatibility bypass" if core_pattern_warning else "ok"
            print(f"core_pattern: {core_pattern} ({state})")
            if core_pattern_warning and fix_hints:
                print("core_pattern fix hints:")
                for command in _core_pattern_fix_hints():
                    print(f"  {command}")
        print("")
        print("tools:")
        for check in checks:
            mark = "ok" if check["ok"] else "missing"
            print(f"  {mark:7} {check['name']}: {check.get('path') or '-'}")
        if not docker_image:
            print("")
            print("build the Docker image with: bin/fuzzctl image-build")
        if not docker_ok:
            print("fix Docker socket access or run commands with --runtime native")
        if not disk_ok:
            print("free at least 3 GiB before long campaigns")
    return 0 if ok else 2
