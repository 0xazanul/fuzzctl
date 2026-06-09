from __future__ import annotations

import os
import sys
from argparse import Namespace
from pathlib import Path

from .cli_dispatch import dispatch_command
from .cli_parser import RUNTIME_COMMANDS, build_parser
from .docker_runtime import run_in_docker
from .util import FuzzCtlError


def _parser():
    return build_parser()


def _maybe_docker(args: Namespace, argv: list[str], workspace: Path) -> int | None:
    if args.command not in RUNTIME_COMMANDS:
        return None
    if args.runtime != "docker":
        return None
    if os.environ.get("FUZZ_PIPELINE_INSIDE_DOCKER"):
        return None
    return run_in_docker(workspace, argv)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _parser()
    args = parser.parse_args(argv)
    workspace = Path(args.workspace).expanduser().resolve()

    try:
        docker_rc = _maybe_docker(args, argv, workspace)
        if docker_rc is not None:
            return docker_rc

        handled = dispatch_command(args, workspace)
        if handled is not None:
            return handled
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
