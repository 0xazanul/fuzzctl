from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from .advanced_tools import advanced_tool_status
from .util import ensure_dir, rel_to, run_cmd, write_json


PROBE_SOURCE = """#include <stdint.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 3;
    uint8_t b[4] = {0, 0, 0, 0};
    size_t n = fread(b, 1, sizeof(b), f);
    fclose(f);
    if (n != sizeof(b)) return 0;
    if (memcmp(b, "FUZZ", 4) == 0) return 7;
    return 0;
}
"""


def _write_result(out: Path, result: dict[str, Any], *, as_json: bool, message: str | None = None) -> None:
    write_json(out / "symcc-self-test.json", result)
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif message:
        print(message)


def symcc_self_test(workspace: Path, *, as_json: bool = False) -> dict[str, Any]:
    status = advanced_tool_status(workspace)
    symcc = status["symcc"]
    out = ensure_dir(workspace / "state" / "self-tests" / "symcc")
    result: dict[str, Any] = {
        "tool": "symcc",
        "status": "skipped",
        "reason": None,
        "compiler": symcc.get("compiler_c"),
        "compiler_version": symcc.get("compiler_version"),
        "compiler_realpath": symcc.get("compiler_c_realpath"),
        "helper": symcc.get("helper"),
        "generated_inputs": 0,
        "output_dir": str(out),
    }
    if not symcc.get("installed"):
        result["reason"] = "symcc, sym++, or symcc_fuzzing_helper is missing"
        _write_result(out, result, as_json=as_json, message=f"SymCC self-test skipped: {result['reason']}")
        return result

    source = out / "symcc_probe.c"
    binary = out / "symcc_probe"
    seed = out / "seed.bin"
    generated = out / "generated"
    if generated.exists():
        shutil.rmtree(generated)
    generated.mkdir()
    source.write_text(PROBE_SOURCE, encoding="utf-8")
    seed.write_bytes(b"AAAA")

    compile_result = run_cmd([str(symcc["compiler_c"]), str(source), "-o", str(binary)], cwd=out, timeout=30)
    result["compile_returncode"] = compile_result.returncode
    result["compile_log"] = compile_result.output
    if compile_result.returncode != 0:
        result["status"] = "failed"
        result["reason"] = "probe compile failed"
        _write_result(out, result, as_json=as_json, message=f"SymCC self-test failed: {result['reason']}")
        return result

    env = {
        "SYMCC_OUTPUT_DIR": str(generated),
        "SYMCC_INPUT_FILE": str(seed),
    }
    run_result = run_cmd([str(binary), str(seed)], cwd=out, env=env, timeout=30)
    files = sorted(path for path in generated.iterdir() if path.is_file())
    result.update(
        {
            "status": "ok" if files else "failed",
            "reason": None if files else "probe ran but SymCC generated no new inputs",
            "run_returncode": run_result.returncode,
            "run_log": run_result.output,
            "generated_inputs": len(files),
            "generated_files": [str(path) for path in files[:10]],
        }
    )
    message = f"SymCC self-test: {result['status']} generated_inputs={result['generated_inputs']} output={rel_to(out, workspace)}"
    if result.get("reason"):
        message = f"{message}\nreason: {result['reason']}"
    _write_result(out, result, as_json=as_json, message=message)
    return result
