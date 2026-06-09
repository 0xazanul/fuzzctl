from __future__ import annotations

import html
import json
from pathlib import Path

from .dashboard_state import _target_crash_value, _target_findings
from .dashboard_ui import badge, crash_tone, profile_badges, table_wrap, tier_tone
from .manifest import load_manifest
from .util import find_latest_run


def _finding_rows(findings: dict, target_name: str) -> str:
    rows = []
    for finding in findings.get("findings", [])[:10]:
        severity = str(finding.get("severity", "INFO"))
        report = finding.get("report")
        finding_id = str(finding.get("id", "unknown"))
        artifacts = int(finding.get("raw_artifacts", 1) or 1)
        occurrences = int(finding.get("occurrences", 1) or 1)
        report_link = (
            f"<a href='/file/{html.escape(str(report))}'><code>{html.escape(finding_id)}</code></a>"
            if report else f"<code>{html.escape(finding_id)}</code>"
        )
        rows.append(
            "<tr>"
            f"<td>{badge(severity, crash_tone(severity))}</td>"
            f"<td>{html.escape(str(finding.get('type', 'unknown')))}</td>"
            f"<td>{html.escape(str(finding.get('harness', 'unknown')))}</td>"
            f"<td>{artifacts}</td>"
            f"<td>{occurrences}</td>"
            f"<td>{report_link}</td>"
            f"<td><a href='/run/{html.escape(target_name)}/{html.escape(str(finding.get('run_id', '')))}'>{html.escape(str(finding.get('run_id', '')))}</a></td>"
            "</tr>"
        )
    return "".join(rows)


def _harness_rows(manifest) -> str:
    rows = []
    for harness in manifest.harnesses:
        rows.append(
            f"<tr><td><b>{html.escape(harness.name)}</b></td><td>{badge(harness.type, 'info')}</td>"
            f"<td>{profile_badges(harness.profiles)}</td><td><code>{html.escape(str(harness.source))}</code></td>"
            f"<td><code>{html.escape(' '.join(harness.argv))}</code></td></tr>"
        )
    return "".join(rows)


def _run_items(target_name: str, runs: list[str], current_run: str | None) -> str:
    ordered_runs = []
    if current_run:
        ordered_runs.append(current_run)
    ordered_runs.extend([run for run in reversed(runs[-30:]) if run != current_run])
    items = ""
    for run_id in ordered_runs:
        is_current = run_id == current_run
        items += (
            "<div class='item target-item'>"
            f"<div><a class='target-name' href='/run/{html.escape(target_name)}/{html.escape(run_id)}'>{html.escape(run_id)}</a>"
            f"<div class='target-meta'>{'current active/latest run' if is_current else 'campaign artifacts, monitor state, coverage, and reports'}</div></div>"
            f"{badge('current' if is_current else 'open', 'ok' if is_current else 'info')}"
            "</div>"
        )
    return items


def _crash_value_rows(crash_value: dict, target_name: str) -> str:
    rows = []
    for record in crash_value.get("records", [])[:20]:
        root = record.get("root_cause") or {}
        root_text = str(root.get("file") or "unknown")
        if root.get("line"):
            root_text += f":{root.get('line')}"
        crash_id = str(record.get("id") or "unknown")
        rows.append(
            "<tr>"
            f"<td>{badge(record.get('tier_label') or record.get('tier'), tier_tone(record.get('tier')))}</td>"
            f"<td>{html.escape(str(record.get('score', 0)))}</td>"
            f"<td>{html.escape(str(record.get('crash_class', 'unknown')))}</td>"
            f"<td>{html.escape(str(record.get('harness', 'unknown')))}</td>"
            f"<td><code>{html.escape(root_text)}</code></td>"
            f"<td><a href='/crash/{html.escape(target_name)}/{html.escape(crash_id)}'><code>{html.escape(crash_id)}</code></a></td>"
            f"<td>{html.escape(str(record.get('next_required_proof', '')))}</td>"
            "</tr>"
        )
    return "".join(rows)


def render_target_body(workspace: Path, name: str) -> str:
    manifest = load_manifest(workspace, name)
    runs_dir = workspace / "runs" / name
    runs = sorted([p.name for p in runs_dir.iterdir() if p.is_dir() and p.name != "background"]) if runs_dir.exists() else []
    current_run = find_latest_run(workspace, name).name if runs else None
    findings = _target_findings(workspace, name)
    crash_value = _target_crash_value(workspace, manifest)
    value_summary = crash_value.get("summary") or {}
    tier_counts = value_summary.get("tier_counts") or {}
    value_rows = _crash_value_rows(crash_value, name)
    finding_rows = _finding_rows(findings, name)
    harness_rows = _harness_rows(manifest)
    run_items = _run_items(name, runs, current_run)

    return f"""
<p class="breadcrumb"><a href="/">Dashboard</a> / {html.escape(name)}</p>
<div class="grid">
<section class="card metric-card span3"><div class="section-head"><h2>Harnesses</h2></div><div class="metric">{len(manifest.harnesses)}</div><div class="metric-label">configured fuzz entrypoints</div></section>
<section class="card metric-card span3"><div class="section-head"><h2>Runs</h2></div><div class="metric">{len(runs)}</div><div class="metric-label">stored run directories</div></section>
<section class="card metric-card span3"><div class="section-head"><h2>Product Plausible</h2></div><div class="metric {'warn' if tier_counts.get('product_plausible') else ''}">{tier_counts.get('product_plausible', 0)}</div><div class="metric-label">{tier_counts.get('report_candidate', 0)} report candidates</div></section>
<section class="card metric-card span3"><div class="section-head"><h2>Noise</h2></div><div class="metric {'warn' if tier_counts.get('noise') else ''}">{tier_counts.get('noise', 0)}</div><div class="metric-label">{findings.get('duplicate_artifacts', 0)} duplicate artifacts collapsed</div></section>
<section class="card span12"><div class="section-head"><div><h2>Crash Value Inbox</h2><p>Evidence-ranked records. Promote only after the next proof is satisfied.</p></div></div>{table_wrap('<table><tr><th>Tier</th><th>Score</th><th>Class</th><th>Harness</th><th>Root Cause</th><th>ID</th><th>Next Proof</th></tr>' + (value_rows or '<tr><td colspan="7" class="muted">No crash value records.</td></tr>') + '</table>')}</section>
<section class="card span12"><div class="section-head"><div><h2>Confirmed Findings</h2><p>Deduped by sanitizer state across all runs for this target.</p></div></div>{table_wrap('<table><tr><th>Severity</th><th>Type</th><th>Harness</th><th>Artifacts</th><th>Runs</th><th>ID / Report</th><th>Latest Run</th></tr>' + (finding_rows or '<tr><td colspan="7" class="muted">No confirmed findings.</td></tr>') + '</table>')}</section>
<section class="card span6"><div class="section-head"><div><h2>Manifest</h2><p>Source of truth for build and harness orchestration.</p></div></div><pre>{html.escape(json.dumps(manifest.to_dict(), indent=2))}</pre></section>
<section class="card span6"><div class="section-head"><div><h2>Harnesses</h2><p>Each file harness can feed AFL++; libFuzzer harnesses run sanitizer smoke campaigns.</p></div></div>{table_wrap('<table><tr><th>Name</th><th>Type</th><th>Profiles</th><th>Source</th><th>Argv</th></tr>' + harness_rows + '</table>')}</section>
<section class="card span12"><div class="section-head"><div><h2>Runs</h2><p>Latest campaigns and smoke runs for this target.</p></div></div><div class="list">{run_items or '<div class="empty">No runs.</div>'}</div></section>
</div>
"""
