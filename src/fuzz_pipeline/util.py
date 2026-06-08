from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence


class FuzzCtlError(RuntimeError):
    """Expected CLI failure with a user-facing message."""


@dataclass
class CmdResult:
    argv: list[str]
    cwd: Path | None
    returncode: int
    stdout: str
    stderr: str
    duration_s: float

    @property
    def output(self) -> str:
        return self.stdout + self.stderr


def default_workspace() -> Path:
    env = os.environ.get("FUZZ_PIPELINE_HOME")
    if env:
        return Path(env).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: object) -> None:
    ensure_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    tmp.replace(path)


def now_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


def which(name: str) -> str | None:
    return shutil.which(name)


def which_any(names: Iterable[str]) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def short_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def resolve_under_workspace(workspace: Path, value: str | None) -> Path | None:
    if not value:
        return None
    p = Path(value).expanduser()
    if p.is_absolute():
        return p.resolve()
    return (workspace / p).resolve()


def rel_to(path: Path, base: Path) -> str:
    try:
        return str(path.resolve().relative_to(base.resolve()))
    except ValueError:
        return str(path.resolve())


def run_cmd(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: int | float | None = None,
    check: bool = False,
    print_cmd: bool = False,
) -> CmdResult:
    if print_cmd:
        where = f" (cwd={cwd})" if cwd else ""
        print("$ " + " ".join(argv) + where)
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    started = time.monotonic()
    try:
        proc = subprocess.run(
            list(argv),
            cwd=str(cwd) if cwd else None,
            env=merged_env,
            timeout=timeout,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        result = CmdResult(
            argv=list(argv),
            cwd=cwd,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_s=time.monotonic() - started,
        )
    except subprocess.TimeoutExpired as exc:
        def _timeout_text(value: str | bytes | None) -> str:
            if value is None:
                return ""
            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return value

        result = CmdResult(
            argv=list(argv),
            cwd=cwd,
            returncode=124,
            stdout=_timeout_text(exc.stdout),
            stderr=_timeout_text(exc.stderr) + f"\nTIMEOUT after {timeout}s\n",
            duration_s=time.monotonic() - started,
        )
    if check and result.returncode != 0:
        raise FuzzCtlError(
            f"command failed ({result.returncode}): {' '.join(result.argv)}\n"
            f"{result.output[-4000:]}"
        )
    return result


def stream_process(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout_s: int | None = None,
) -> int:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    proc = subprocess.Popen(list(argv), cwd=str(cwd) if cwd else None, env=merged_env)
    try:
        proc.wait(timeout=timeout_s)
        return int(proc.returncode or 0)
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait(timeout=10)
        raise
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        return 124


def free_disk_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free


def human_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    n = float(value)
    for unit in units:
        if n < 1024 or unit == units[-1]:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{value} B"


def cpu_default_workers() -> int:
    cpus = os.cpu_count() or 1
    return max(1, min(6, cpus - 2 if cpus > 2 else 1))


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def find_latest_run(workspace: Path, name: str) -> Path:
    run_root = workspace / "runs" / name
    if not run_root.exists():
        raise FuzzCtlError(f"no runs found for target {name!r}")
    runs = sorted([p for p in run_root.iterdir() if p.is_dir()])
    if not runs:
        raise FuzzCtlError(f"no runs found for target {name!r}")

    campaign_runs = [p for p in runs if p.name != "background"]

    def _mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    def _is_timestamped(path: Path) -> bool:
        value = path.name
        return len(value) >= 15 and value[:8].isdigit() and value[8] == "-" and value[9:15].isdigit()

    running: list[Path] = []
    for run in campaign_runs:
        run_json = run / "run.json"
        if run_json.exists():
            try:
                if read_json(run_json).get("status") == "running":
                    running.append(run)
            except Exception:
                pass
    if running:
        return max(running, key=_mtime)

    stats_mtimes: list[tuple[float, Path]] = []
    for run in campaign_runs:
        mtimes = [_mtime(path) for path in run.rglob("fuzzer_stats")]
        if mtimes:
            stats_mtimes.append((max(mtimes), run))
    if stats_mtimes:
        return max(stats_mtimes, key=lambda item: item[0])[1]

    timestamped = [p for p in campaign_runs if _is_timestamped(p)]
    if timestamped:
        return sorted(timestamped)[-1]

    return runs[-1]


def iter_files(paths: Iterable[Path]) -> list[Path]:
    out: list[Path] = []
    for path in paths:
        if path.is_file():
            out.append(path)
        elif path.is_dir():
            out.extend([p for p in sorted(path.rglob("*")) if p.is_file()])
    return out
