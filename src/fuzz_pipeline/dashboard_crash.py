from __future__ import annotations

import html
import json
from pathlib import Path

from .crash_value import rel_record_paths
from .dashboard_state import _safe, _target_crash_value
from .dashboard_ui import badge, crash_tone, table_wrap, tier_tone
from .manifest import load_manifest
from .util import FuzzCtlError


def _crash_value_record(workspace: Path, target: str, crash_id: str) -> tuple[dict, dict]:
    manifest = load_manifest(workspace, target)
    value = _target_crash_value(workspace, manifest)
    for record in value.get("records", []):
        if str(record.get("id")) == crash_id:
            return value, record
    raise FuzzCtlError(f"crash value record not found: {target}/{crash_id}")


def render_crash_value_detail_body(workspace: Path, target: str, crash_id: str) -> str:
    _, record = _crash_value_record(workspace, target, crash_id)
    root = record.get("root_cause") or {}
    product = record.get("product_mapping") or {}
    harness = record.get("harness_assessment") or {}
    exploitability = record.get("exploitability") or {}
    paths = rel_record_paths(record, workspace)
    trace = _safe(Path(str(record.get("trace_path"))), 50000) if record.get("trace_path") else ""

    rows = [
        ("Tier", badge(record.get("tier_label") or record.get("tier"), tier_tone(record.get("tier")))),
        ("Score", html.escape(str(record.get("score", 0)))),
        ("Class", html.escape(str(record.get("crash_class", "unknown")))),
        ("Type", html.escape(str(record.get("type", "unknown")))),
        ("Severity", badge(record.get("severity", "INFO"), crash_tone(record.get("severity")))),
        ("Harness", html.escape(str(record.get("harness", "unknown")))),
        ("Next proof", html.escape(str(record.get("next_required_proof", "")))),
    ]
    evidence_rows = "".join(f"<tr><td>{html.escape(key)}</td><td>{value}</td></tr>" for key, value in rows)
    path_rows = "".join(
        f"<tr><td>{html.escape(key)}</td><td><a href='/file/{html.escape(value)}'>{html.escape(value)}</a></td></tr>"
        for key, value in paths.items()
    )
    frame_rows = ""
    for frame in record.get("frames", []):
        location = str(frame.get("rel_file") or frame.get("file") or "")
        if frame.get("line"):
            location += f":{frame.get('line')}"
        frame_rows += (
            "<tr>"
            f"<td>{html.escape(str(frame.get('index')))}</td>"
            f"<td>{html.escape(str(frame.get('function')))}</td>"
            f"<td><code>{html.escape(location)}</code></td>"
            "</tr>"
        )

    return f"""
<p class="breadcrumb"><a href="/">Dashboard</a> / <a href="/target/{html.escape(target)}">{html.escape(target)}</a> / crash {html.escape(crash_id)}</p>
<div class="grid">
<section class="card metric-card span3"><div class="section-head"><h2>Tier</h2></div><div class="metric small">{html.escape(str(record.get('tier_label')))}</div><div class="metric-label">{html.escape(str(record.get('next_required_proof')))}</div></section>
<section class="card metric-card span3"><div class="section-head"><h2>Score</h2></div><div class="metric">{html.escape(str(record.get('score', 0)))}</div><div class="metric-label">evidence priority, not exploitability proof</div></section>
<section class="card metric-card span3"><div class="section-head"><h2>Artifacts</h2></div><div class="metric">{html.escape(str(record.get('raw_artifacts', 1)))}</div><div class="metric-label">{html.escape(str(record.get('duplicates', 0)))} duplicates</div></section>
<section class="card metric-card span3"><div class="section-head"><h2>Product</h2></div><div class="metric small">{html.escape(str(product.get('status', 'unmapped')))}</div><div class="metric-label">{html.escape(str(product.get('verification', 'not_verified')))}</div></section>
<section class="card span6"><div class="section-head"><div><h2>Evidence</h2><p>Current reportability decision for this unique sanitizer state.</p></div></div>{table_wrap('<table><tr><th>Field</th><th>Value</th></tr>' + evidence_rows + '</table>')}</section>
<section class="card span6"><div class="section-head"><div><h2>Root Cause</h2><p>First non-runtime, non-harness target frame.</p></div></div><pre>{html.escape(json.dumps(root, indent=2))}</pre></section>
<section class="card span6"><div class="section-head"><div><h2>Product Mapping</h2><p>Target product reachability status.</p></div></div><pre>{html.escape(json.dumps(product, indent=2))}</pre></section>
<section class="card span6"><div class="section-head"><div><h2>Exploitability</h2><p>Conservative primitive estimate. This is not an exploit claim.</p></div></div><pre>{html.escape(json.dumps(exploitability, indent=2))}</pre></section>
<section class="card span6"><div class="section-head"><div><h2>Harness Assessment</h2><p>Flags harness-only or harness-biased crash evidence.</p></div></div><pre>{html.escape(json.dumps(harness, indent=2))}</pre></section>
<section class="card span6"><div class="section-head"><div><h2>Artifacts</h2><p>Minimized input, trace, and report links.</p></div></div>{table_wrap('<table><tr><th>Artifact</th><th>Path</th></tr>' + (path_rows or '<tr><td colspan="2" class="muted">No linked artifacts.</td></tr>') + '</table>')}</section>
<section class="card span12"><div class="section-head"><div><h2>Stack Frames</h2><p>Top frames used for root-cause and harness-suspicion decisions.</p></div></div>{table_wrap('<table><tr><th>#</th><th>Function</th><th>Location</th></tr>' + (frame_rows or '<tr><td colspan="3" class="muted">No parsed frames.</td></tr>') + '</table>')}</section>
<section class="card span12"><div class="section-head"><div><h2>Sanitizer Trace</h2><p>Symbolized ASan/UBSan evidence.</p></div></div><pre>{html.escape(trace or 'No trace found.')}</pre></section>
</div>
"""
