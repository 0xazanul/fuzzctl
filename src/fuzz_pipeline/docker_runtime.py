from __future__ import annotations

import os
import sys
from pathlib import Path

from .util import FuzzCtlError, run_cmd


IMAGE = "fuzz-pipeline:local"


def docker_access() -> tuple[bool, str]:
    result = run_cmd(["docker", "ps"])
    if result.returncode == 0:
        return True, ""
    return False, result.output.strip()


def image_build(workspace: Path) -> int:
    ok, error = docker_access()
    if not ok:
        raise FuzzCtlError(f"Docker is not usable by this user: {error}")
    result = run_cmd(["docker", "build", "-t", IMAGE, "."], cwd=workspace, print_cmd=True)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result.returncode


def image_exists() -> bool:
    ok, _ = docker_access()
    if not ok:
        return False
    result = run_cmd(["docker", "image", "inspect", IMAGE])
    return result.returncode == 0


def dockerize_args(argv: list[str]) -> list[str]:
    out: list[str] = []
    skip_next = False
    replaced = False
    for i, arg in enumerate(argv):
        if skip_next:
            skip_next = False
            continue
        if arg == "--runtime":
            out.extend(["--runtime", "native"])
            skip_next = True
            replaced = True
        elif arg.startswith("--runtime="):
            out.append("--runtime=native")
            replaced = True
        else:
            out.append(arg)
    if not replaced:
        out = ["--runtime", "native"] + out
    return out


def run_in_docker(workspace: Path, argv: list[str]) -> int:
    ok, error = docker_access()
    if not ok:
        raise FuzzCtlError(f"Docker is not usable by this user: {error}")
    if not image_exists():
        raise FuzzCtlError(
            f"Docker image {IMAGE!r} is missing. Run: bin/fuzzctl image-build"
        )
    parent = workspace.parent.resolve()
    uid = str(os.getuid()) if hasattr(os, "getuid") else "1000"
    gid = str(os.getgid()) if hasattr(os, "getgid") else "1000"
    inner_argv = dockerize_args(argv)
    cmd = [
        "docker",
        "run",
        "--rm",
        "--user",
        f"{uid}:{gid}",
        "-e",
        "FUZZ_PIPELINE_INSIDE_DOCKER=1",
        "-v",
        f"{parent}:{parent}",
        "-w",
        str(workspace),
        IMAGE,
        "python3",
        "-m",
        "fuzz_pipeline",
        "--workspace",
        str(workspace),
        *inner_argv,
    ]
    return run_cmd(cmd, cwd=workspace, print_cmd=True).returncode
