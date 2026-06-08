from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

from .util import FuzzCtlError, run_cmd


IMAGE = "fuzz-pipeline:local"


def _docker_cmd(args: list[str]) -> list[str]:
    direct = run_cmd(["docker", "ps"])
    if direct.returncode == 0:
        return args
    via_group = run_cmd(["sg", "docker", "-c", "docker ps"])
    if via_group.returncode == 0:
        return ["sg", "docker", "-c", shlex.join(args)]
    return args


def run_docker(args: list[str], *, workspace: Path | None = None, print_cmd: bool = False):
    return run_cmd(_docker_cmd(args), cwd=workspace, print_cmd=print_cmd)


def docker_access() -> tuple[bool, str]:
    result = run_docker(["docker", "ps"])
    if result.returncode == 0:
        return True, ""
    return False, result.output.strip()


def image_build(workspace: Path) -> int:
    ok, error = docker_access()
    if not ok:
        raise FuzzCtlError(f"Docker is not usable by this user: {error}")
    result = run_docker(["docker", "build", "-t", IMAGE, "."], workspace=workspace, print_cmd=True)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result.returncode


def image_exists() -> bool:
    ok, _ = docker_access()
    if not ok:
        return False
    result = run_docker(["docker", "image", "inspect", IMAGE])
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


def docker_run_command(workspace: Path, argv: list[str], *, image: str = IMAGE) -> list[str]:
    parent = workspace.parent.resolve()
    uid = str(os.getuid()) if hasattr(os, "getuid") else "1000"
    gid = str(os.getgid()) if hasattr(os, "getgid") else "1000"
    inner_argv = dockerize_args(argv)
    return [
        "docker",
        "run",
        "--rm",
        "--user",
        f"{uid}:{gid}",
        "-e",
        "FUZZ_PIPELINE_INSIDE_DOCKER=1",
        "-e",
        f"PYTHONPATH={workspace / 'src'}",
        "-v",
        f"{parent}:{parent}",
        "-w",
        str(workspace),
        image,
        "python3",
        "-m",
        "fuzz_pipeline",
        "--workspace",
        str(workspace),
        *inner_argv,
    ]


def run_in_docker(workspace: Path, argv: list[str]) -> int:
    ok, error = docker_access()
    if not ok:
        raise FuzzCtlError(f"Docker is not usable by this user: {error}")
    if not image_exists():
        raise FuzzCtlError(
            f"Docker image {IMAGE!r} is missing. Run: bin/fuzzctl image-build"
        )
    cmd = docker_run_command(workspace, argv)
    return run_docker(cmd, workspace=workspace, print_cmd=True).returncode
