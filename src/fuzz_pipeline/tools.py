from __future__ import annotations

import getpass
import json
import os
from pathlib import Path

from .docker_runtime import docker_access, image_exists
from .util import FuzzCtlError, run_cmd, which_any


CORE_TOOLS = [
    {"name": "AFL++ fuzzer", "commands": ["afl-fuzz"], "apt": "afl++", "required": True},
    {"name": "AFL++ fast clang", "commands": ["afl-clang-fast"], "apt": "afl++", "required": True},
    {"name": "AFL++ LTO clang", "commands": ["afl-clang-lto"], "apt": "afl++", "required": True},
    {"name": "AFL++ showmap", "commands": ["afl-showmap"], "apt": "afl++", "required": True},
    {"name": "AFL++ cmin", "commands": ["afl-cmin"], "apt": "afl++", "required": True},
    {"name": "AFL++ tmin", "commands": ["afl-tmin"], "apt": "afl++", "required": True},
    {"name": "AFL++ plot", "commands": ["afl-plot"], "apt": "afl++", "required": False},
    {"name": "AFL++ whatsup", "commands": ["afl-whatsup"], "apt": "afl++", "required": False},
    {"name": "clang", "commands": ["clang"], "apt": "clang", "required": True},
    {"name": "clang++", "commands": ["clang++"], "apt": "clang", "required": True},
    {"name": "llvm-symbolizer", "commands": ["llvm-symbolizer", "llvm-symbolizer-18", "llvm-symbolizer-17"], "apt": "llvm", "required": True},
    {"name": "llvm-cov", "commands": ["llvm-cov", "llvm-cov-18", "llvm-cov-17"], "apt": "llvm", "required": True},
    {"name": "llvm-profdata", "commands": ["llvm-profdata", "llvm-profdata-18", "llvm-profdata-17"], "apt": "llvm", "required": True},
    {"name": "lld", "commands": ["lld", "ld.lld", "ld.lld-18"], "apt": "lld", "required": False},
    {"name": "honggfuzz", "commands": ["honggfuzz"], "apt": None, "required": False},
    {"name": "hfuzz-clang", "commands": ["hfuzz-clang"], "apt": None, "required": False},
    {"name": "radamsa", "commands": ["radamsa"], "apt": None, "required": False, "manual": "Install from upstream source if corpus enrichment is needed."},
    {"name": "gdb", "commands": ["gdb"], "apt": "gdb", "required": False},
    {"name": "valgrind", "commands": ["valgrind"], "apt": "valgrind", "required": False},
    {"name": "cmake", "commands": ["cmake"], "apt": "cmake", "required": True},
    {"name": "ninja", "commands": ["ninja"], "apt": "ninja-build", "required": True},
    {"name": "make", "commands": ["make"], "apt": "make", "required": True},
    {"name": "pkg-config", "commands": ["pkg-config"], "apt": "pkg-config", "required": False},
    {"name": "git", "commands": ["git"], "apt": "git", "required": True},
    {"name": "curl", "commands": ["curl"], "apt": "curl", "required": False}
]


def collect_tool_status(workspace: Path) -> dict:
    tools = []
    missing_required = []
    missing_optional = []
    for tool in CORE_TOOLS:
        path = which_any(tool["commands"])
        item = {
            "name": tool["name"],
            "commands": tool["commands"],
            "path": path,
            "installed": bool(path),
            "required": bool(tool.get("required")),
            "apt": tool.get("apt"),
            "manual": tool.get("manual")
        }
        tools.append(item)
        if not path:
            if tool.get("required"):
                missing_required.append(item)
            else:
                missing_optional.append(item)

    docker_ok, docker_error = docker_access() if which_any(["docker"]) else (False, "docker binary missing")
    core_pattern = None
    core_pattern_warning = False
    core_path = Path("/proc/sys/kernel/core_pattern")
    if core_path.exists():
        core_pattern = core_path.read_text(encoding="utf-8", errors="replace").strip()
        core_pattern_warning = core_pattern.startswith("|")
    core_uses_pid = None
    core_uses_pid_path = Path("/proc/sys/kernel/core_uses_pid")
    if core_uses_pid_path.exists():
        core_uses_pid = core_uses_pid_path.read_text(encoding="utf-8", errors="replace").strip()

    return {
        "workspace": str(workspace),
        "tools": tools,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "docker_access_ok": docker_ok,
        "docker_access_error": docker_error,
        "docker_image_exists": image_exists() if docker_ok else False,
        "core_pattern": core_pattern,
        "core_pattern_warning": core_pattern_warning,
        "core_uses_pid": core_uses_pid,
        "core_pattern_fix_hints": [
            "sudo sysctl -w kernel.core_pattern=core",
            "sudo sysctl -w kernel.core_uses_pid=0",
            "printf 'kernel.core_pattern=core\\nkernel.core_uses_pid=0\\n' | sudo tee /etc/sysctl.d/zz-fuzz-pipeline-core.conf",
            "sudo sysctl --system",
        ] if core_pattern_warning else [],
        "user": getpass.getuser(),
        "groups": os.getgroups()
    }


def tools_doctor(workspace: Path, *, as_json: bool = False, deep: bool = False) -> int:
    status = collect_tool_status(workspace)
    if as_json:
        print(json.dumps(status, indent=2, sort_keys=True))
        return 0 if not status["missing_required"] and status["docker_access_ok"] else 2

    print(f"workspace: {workspace}")
    print(f"docker: {'ok' if status['docker_access_ok'] else 'not usable'}")
    if not status["docker_access_ok"]:
        print(f"docker error: {status['docker_access_error']}")
    if status.get("core_pattern"):
        cp = status["core_pattern"]
        suffix = " (piped; AFL++ compatibility bypass needed)" if cp.startswith("|") else ""
        print(f"core_pattern: {cp}{suffix}")
    print("")
    print("curated core tools:")
    for item in status["tools"]:
        mark = "ok" if item["installed"] else ("missing!" if item["required"] else "missing")
        req = "required" if item["required"] else "optional"
        print(f"  {mark:9} {req:8} {item['name']}: {item['path'] or '-'}")
        if deep and not item["installed"] and item.get("manual"):
            print(f"             note: {item['manual']}")
    if status["missing_required"]:
        print("")
        print("missing required tools must be installed before reliable campaigns")
    if not status["docker_access_ok"]:
        print("fix Docker group/session access or use --runtime native")
    return 0 if not status["missing_required"] and status["docker_access_ok"] else 2


def install_core(workspace: Path, *, dry_run: bool = False) -> int:
    status = collect_tool_status(workspace)
    packages = sorted({
        item["apt"]
        for item in [*status["missing_required"], *status["missing_optional"]]
        if item.get("apt")
    })
    manual = [item for item in [*status["missing_required"], *status["missing_optional"]] if not item.get("apt")]

    if packages:
        cmd = ["sudo", "apt-get", "install", "-y", *packages]
        print("$ " + " ".join(cmd))
        if not dry_run:
            run_cmd(["sudo", "apt-get", "update"], check=True, print_cmd=True)
            run_cmd(cmd, check=True, print_cmd=True)
    else:
        print("apt packages: already satisfied")

    if manual:
        print("")
        print("manual/source tools:")
        for item in manual:
            print(f"  {item['name']}: {item.get('manual') or 'not available from apt in this pipeline'}")

    docker_ok, docker_error = docker_access()
    if not docker_ok:
        user = getpass.getuser()
        docker_group = run_cmd(["getent", "group", "docker"])
        if docker_group.returncode == 0:
            cmd = ["sudo", "usermod", "-aG", "docker", user]
            print("")
            print("$ " + " ".join(cmd))
            if not dry_run:
                run_cmd(cmd, check=True, print_cmd=True)
                print("Docker group updated; start a new login/session before Docker runtime will work.")
        else:
            print(f"Docker access still not usable: {docker_error}")

    return tools_doctor(workspace, deep=True)
