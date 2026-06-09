from __future__ import annotations

import fcntl
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .util import ensure_dir, write_json


@contextmanager
def target_lock(workspace: Path, target: str) -> Iterator[bool]:
    lock_dir = ensure_dir(workspace / "state" / "locks")
    lock_path = lock_dir / f"{target}.campaign.lock"
    with lock_path.open("w", encoding="utf-8") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        lock_file.write(f"{os.getpid()}\n")
        lock_file.flush()
        try:
            yield True
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def state_path(workspace: Path, target: str) -> Path:
    return ensure_dir(workspace / "state" / "supervisor") / f"{target}.json"


def write_state(workspace: Path, target: str, data: dict[str, object]) -> None:
    payload = {
        "target": target,
        "updated_at": int(time.time()),
        **data,
    }
    write_json(state_path(workspace, target), payload)
