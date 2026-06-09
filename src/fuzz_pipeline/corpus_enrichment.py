from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from .corpus_seed_cases import (
    _builtin_seed_cases,
    _config_seed_cases,
    _ddns_settings_seed_cases,
    _dnssd_proxy_config_seed_cases,
    _dnssd_relay_config_seed_cases,
    _dns_name,
    _dns_query,
    _dns_response_a,
    _dns_rdata_seed_cases,
    _dns_wire_seed_cases,
    _dnssec_rdata_seed_cases,
    _generic_seed_cases,
    _responder_readline_seed_cases,
    _srp_filedata_seed_cases,
    _srp_key_config_seed_cases,
    _srp_replication_seed_cases,
    _srp_replication_tlv,
)
from .manifest import TargetManifest
from .util import ensure_dir, iter_files, rel_to, which, write_json


def _write_seed(path: Path, data: bytes) -> bool:
    if path.exists() and path.read_bytes() == data:
        return False
    ensure_dir(path.parent)
    path.write_bytes(data)
    return True


def _run_radamsa(inputs: list[Path], out_dir: Path, *, mutations_per_input: int) -> dict[str, Any]:
    radamsa = which("radamsa")
    if not radamsa:
        return {"used": False, "reason": "radamsa not installed", "generated": 0}
    generated = 0
    for source in inputs:
        for index in range(mutations_per_input):
            out = out_dir / f"radamsa-{source.stem}-{index:03d}.bin"
            with source.open("rb") as src, out.open("wb") as dst:
                result = subprocess.run([radamsa], stdin=src, stdout=dst, stderr=subprocess.PIPE, timeout=10)
            if result.returncode == 0 and out.exists():
                generated += 1
            elif out.exists():
                out.unlink()
    return {"used": True, "generated": generated}


def corpus_enrich(
    workspace: Path,
    manifest: TargetManifest,
    *,
    mutations_per_input: int = 0,
    overwrite: bool = False,
) -> Path:
    out = ensure_dir(workspace / "corpora" / manifest.name)
    report: dict[str, Any] = {"target": manifest.name, "harnesses": [], "mutations_per_input": mutations_per_input}
    base_seed_dir = manifest.seed_dir(workspace)
    base_inputs = iter_files([base_seed_dir]) if base_seed_dir.exists() else []

    for harness in manifest.harnesses:
        current = ensure_dir(out / harness.name / "current")
        if overwrite:
            shutil.rmtree(current)
            ensure_dir(current)
        written = 0
        for name, data in _builtin_seed_cases(harness).items():
            if _write_seed(current / name, data):
                written += 1
        for source in base_inputs:
            target = current / f"base-{source.name}"
            if not target.exists():
                shutil.copy2(source, target)
                written += 1
        inputs = iter_files([current])
        radamsa = _run_radamsa(inputs, current, mutations_per_input=mutations_per_input) if mutations_per_input > 0 else {"used": False, "reason": "disabled", "generated": 0}
        files = iter_files([current])
        report["harnesses"].append(
            {
                "harness": harness.name,
                "output": rel_to(current, workspace),
                "files": len(files),
                "written": written,
                "radamsa": radamsa,
            }
        )

    write_json(out / "enrichment.json", report)
    print(f"corpus enrichment output: {rel_to(out, workspace)}")
    return out
