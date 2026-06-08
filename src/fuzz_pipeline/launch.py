from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse

from .campaign import run_campaign, smoke
from .detect import detect_target
from .harness import scan_harness_points, validate_harnesses, write_harness_work_order
from .manifest import create_manifest_from_path, load_manifest, manifest_path, save_manifest
from .util import FuzzCtlError, ensure_dir, now_id, rel_to, run_cmd, write_json


URL_RE = re.compile(r"^(https?://|git@|ssh://)")


def _default_name(source: str) -> str:
    if URL_RE.match(source):
        parsed = urlparse(source)
        raw = Path(parsed.path).name
    else:
        raw = Path(source).expanduser().resolve().name
    if raw.endswith(".git"):
        raw = raw[:-4]
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip("-._").lower()
    return name or "target"


def _clone_or_resolve(workspace: Path, source: str, name: str, *, update: bool = False) -> Path:
    if URL_RE.match(source):
        repo_dir = workspace / "repos" / name
        if repo_dir.exists():
            if update:
                run_cmd(["git", "-C", str(repo_dir), "pull", "--ff-only"], check=False, print_cmd=True)
                run_cmd(["git", "-C", str(repo_dir), "submodule", "update", "--init", "--recursive"], check=False, print_cmd=True)
            return repo_dir.resolve()
        ensure_dir(repo_dir.parent)
        run_cmd(["git", "clone", "--recursive", source, str(repo_dir)], check=True, print_cmd=True)
        return repo_dir.resolve()
    path = Path(source).expanduser().resolve()
    if not path.exists():
        raise FuzzCtlError(f"repo/path does not exist: {path}")
    return path


def _manifest_ready(workspace: Path, name: str) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    manifest = load_manifest(workspace, name)
    source_dir = manifest.source_dir(workspace)
    if not manifest.harnesses:
        return False, ["manifest has no harnesses"]
    ready = False
    for harness in manifest.harnesses:
        if not harness.source:
            reasons.append(f"{harness.name}: source is not set")
            continue
        if not (source_dir / harness.source).exists():
            reasons.append(f"{harness.name}: source file missing: {harness.source}")
            continue
        ready = True
    return ready, reasons


def _write_launch_report(workspace: Path, run_dir: Path, data: dict) -> Path:
    lines = [
        f"# Launch Report: {data['name']}",
        "",
        f"Source: `{data['source']}`",
        f"Resolved path: `{data['repo_path']}`",
        f"Detection: `{data['detection']['language']}` / `{data['detection']['build_system']}`",
        f"Status: **{data['status']}**",
        "",
        "## Harness Readiness",
        ""
    ]
    if data["ready"]:
        lines.append("- At least one buildable harness source is configured.")
    else:
        lines.extend(f"- {reason}" for reason in data["readiness_reasons"])
        if data.get("work_order"):
            lines.append(f"- AI harness work order: `{data['work_order']}`")
    lines.extend(["", "## Candidate Entry Points", ""])
    for item in data["candidates"][:20]:
        candidate_id = item.get("id", item["function"])
        lines.append(
            f"- `{candidate_id}` score {item['score']}: "
            f"`{item.get('relative_file', item['file'])}:{item['line']}` `{item['function']}({item['params']})`"
        )
    if not data["candidates"]:
        lines.append("- No obvious parser/decoder functions found by heuristic scan.")
    lines.extend(["", "## Next Commands", ""])
    lines.append("```bash")
    lines.append("cd /home/azanul/fuzz-pipeline")
    lines.append(f"bin/fuzzctl --runtime native harness scan {data['repo_path']}")
    lines.append(f"bin/fuzzctl --runtime native harness ai-plan {data['repo_path']}")
    if data["ready"]:
        lines.append(f"bin/fuzzctl --runtime native harness validate {data['name']} --build")
        lines.append(f"bin/fuzzctl --runtime native smoke {data['name']} --seconds 300")
        lines.append(f"bin/fuzzctl --runtime native run {data['name']} --engine aflpp --hours 1 --workers 6")
        lines.append(f"bin/fuzzctl --runtime native monitor {data['name']} --once")
    else:
        lines.append(f"bin/fuzzctl --runtime native harness work-order {data['name']}")
        lines.append(f"bin/fuzzctl --runtime native harness prompt {data['name']} --candidate <candidate-id>")
        lines.append(f"bin/fuzzctl --runtime native harness scaffold {data['name']} --type libfuzzer --harness-name parser --function <candidate_function>")
        lines.append("# Wire the scaffolded harness, update target.json, then validate/build/smoke.")
        lines.append(f"bin/fuzzctl --runtime native harness review {data['name']}")
        lines.append(f"bin/fuzzctl --runtime native harness validate {data['name']} --build")
    lines.append("```")
    report = run_dir / "launch-report.md"
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report


def launch_repo(
    workspace: Path,
    source: str,
    *,
    name: str | None = None,
    update: bool = False,
    force_manifest: bool = False,
    smoke_seconds: int = 0,
    campaign_hours: float = 0.0,
    workers: int | None = None
) -> Path:
    name = name or _default_name(source)
    repo_path = _clone_or_resolve(workspace, source, name, update=update)
    detection = detect_target(repo_path)
    run_dir = ensure_dir(workspace / "runs" / name / f"{now_id()}-launch")
    if not detection.supported:
        data = {
            "name": name,
            "source": source,
            "repo_path": str(repo_path),
            "status": "unsupported",
            "detection": detection.to_dict(),
            "ready": False,
            "readiness_reasons": [detection.reason],
            "candidates": []
        }
        write_json(run_dir / "launch.json", data)
        _write_launch_report(workspace, run_dir, data)
        raise FuzzCtlError(f"unsupported repo: {detection.reason}; report: {run_dir / 'launch-report.md'}")

    mpath = manifest_path(workspace, name)
    if force_manifest or not mpath.exists():
        manifest, _ = create_manifest_from_path(workspace, repo_path, name)
        save_manifest(workspace, manifest)
    manifest = load_manifest(workspace, name)

    candidates = scan_harness_points(repo_path, as_json=False)
    ready, reasons = _manifest_ready(workspace, name)
    status = "ready"
    if not ready:
        status = "needs_harness"
    work_order_path: Path | None = None
    if not ready:
        work_order_path = write_harness_work_order(workspace, manifest, limit=8, as_json=False)

    data = {
        "name": name,
        "source": source,
        "repo_path": str(repo_path),
        "manifest": str(mpath),
        "status": status,
        "detection": detection.to_dict(),
        "ready": ready,
        "readiness_reasons": reasons,
        "candidates": candidates,
        "work_order": rel_to(work_order_path, workspace) if work_order_path else None,
    }
    write_json(run_dir / "launch.json", data)
    report = _write_launch_report(workspace, run_dir, data)

    if ready:
        rc = validate_harnesses(workspace, manifest, build=True)
        if rc != 0:
            raise FuzzCtlError(f"harness validation failed; report: {report}")
        if smoke_seconds > 0:
            smoke(workspace, manifest, smoke_seconds)
        if campaign_hours > 0:
            run_campaign(workspace, manifest, "aflpp", campaign_hours, workers)
    else:
        print("repo onboarded, but fuzzing is blocked until a real harness is wired")
    print(f"launch report: {rel_to(report, workspace)}")
    return run_dir
