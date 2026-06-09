from __future__ import annotations

import html
from pathlib import Path

from .dashboard_state import _run_summary
from .dashboard_ui import badge, crash_tone, render_worker_stats_table, table_wrap
from .findings import normalize_crash_item


def _crash_rows(crashes: list[dict], target: str) -> str:
    rows = []
    for crash in crashes:
        severity = str(crash.get("severity", "INFO"))
        rows.append(
            "<tr>"
            f"<td>{badge(severity, crash_tone(severity))}</td>"
            f"<td>{html.escape(str(crash.get('type')))}</td>"
            f"<td>{html.escape(str(crash.get('harness', 'unknown')))}</td>"
            f"<td>{html.escape(str(crash.get('raw_artifacts', 1)))}</td>"
            f"<td>{html.escape(str(crash.get('duplicates', 0)))}</td>"
            f"<td><a href='/crash/{html.escape(target)}/{html.escape(str(crash.get('id')))}'><code>{html.escape(str(crash.get('id')))}</code></a></td>"
            f"<td>{html.escape(str(crash.get('impact')))}</td>"
            "</tr>"
        )
    return "".join(rows)


def _post_cycle_rows(post_cycle: dict) -> str:
    rows = ""
    post_steps = post_cycle.get("steps", []) if isinstance(post_cycle, dict) else []
    for step in post_steps:
        status = str(step.get("status", "unknown"))
        tone = "ok" if status == "ok" else "warn" if status == "skipped" else "bad"
        detail = step.get("path") or step.get("reason") or step.get("error") or ""
        rows += (
            "<tr>"
            f"<td>{badge(status, tone)}</td>"
            f"<td>{html.escape(str(step.get('name')))}</td>"
            f"<td>{html.escape(str(step.get('seconds', 0)))}</td>"
            f"<td><code>{html.escape(str(detail)[:280])}</code></td>"
            "</tr>"
        )
    return rows


def _advanced_triage_rows(advanced: dict) -> str:
    rows = ""
    if not isinstance(advanced, dict):
        return rows
    for item in advanced.get("casr", []):
        rows += (
            "<tr>"
            f"<td>CASR</td><td>{badge(item.get('status', 'unknown'), 'ok' if item.get('status') == 'ok' else 'warn')}</td>"
            f"<td>{html.escape(str(item.get('id', '-')))}</td>"
            f"<td><code>{html.escape(str(item.get('report') or item.get('reason') or item.get('log') or '')[:260])}</code></td>"
            "</tr>"
        )
    for item in advanced.get("exploitable", []):
        rows += (
            "<tr>"
            f"<td>exploitable</td><td>{badge(item.get('status', 'unknown'), 'ok' if item.get('status') == 'ok' else 'warn')}</td>"
            f"<td>{html.escape(str(item.get('id', '-')))}</td>"
            f"<td><code>{html.escape(str(item.get('reason') or item.get('log') or '')[:260])}</code></td>"
            "</tr>"
        )
    return rows


def _hybrid_rows(hybrid: dict) -> str:
    rows = ""
    if not isinstance(hybrid, dict):
        return rows
    if hybrid.get("status") == "build_failed":
        detail = hybrid.get("reason") or hybrid.get("action") or hybrid.get("build_log") or ""
        return (
            "<tr>"
            "<td>build</td>"
            f"<td>{badge('build_failed', 'bad')}</td>"
            "<td>0</td>"
            f"<td><code>{html.escape(str(detail)[:260])}</code></td>"
            "</tr>"
        )
    for item in hybrid.get("results", []):
        rows += (
            "<tr>"
            f"<td>{html.escape(str(item.get('harness')))}</td>"
            f"<td>{badge(item.get('status', 'unknown'), 'ok' if item.get('status') in {'ok', 'timeout_complete'} else 'warn')}</td>"
            f"<td>{html.escape(str(item.get('generated_inputs', 0)))}</td>"
            f"<td><code>{html.escape(str(item.get('log') or item.get('reason') or '')[:260])}</code></td>"
            "</tr>"
        )
    return rows


def render_run_body(workspace: Path, target: str, run_id: str) -> str:
    summary = _run_summary(workspace, target, run_id)
    triage = summary.get("triage", {})
    crashes = [normalize_crash_item(item) for item in triage.get("crashes", [])]
    snap = summary.get("snapshot", {})
    coverage_inputs = summary.get("coverage_inputs", {})
    corpus_sync = summary.get("corpus_sync", {})
    duplicate_artifacts = sum(int(crash.get("duplicates", 0) or 0) for crash in crashes)
    triaged_raw = int(triage.get("raw_crashes", 0) or snap.get("triaged_raw_crashes", 0) or (len(crashes) + duplicate_artifacts))
    reproducible_count = sum(1 for crash in crashes if crash.get("reproducible"))
    crash_rows = _crash_rows(crashes, target)
    logs = "".join(f"<div class='item'><a href='/file/{html.escape(path)}'>{html.escape(path)}</a></div>" for path in summary.get("logs", []))
    reports = "".join(f"<div class='item'><a href='/file/{html.escape(path)}'>{html.escape(path)}</a></div>" for path in summary.get("reports", []))
    queue_rows = "".join(
        f"<tr><td>{html.escape(name)}</td><td>{count}</td></tr>"
        for name, count in sorted((snap.get("queue_by_harness") or {}).items())
    )
    input_rows = ""
    for harness in coverage_inputs.get("harnesses", []):
        input_rows += f"<tr><td>{html.escape(str(harness.get('harness')))}</td><td>{html.escape(str(harness.get('selected', 0)))}</td><td><code>{html.escape(str(harness.get('sources', {}))[:240])}</code></td></tr>"
    corpus_rows = ""
    for harness in corpus_sync.get("harnesses", []):
        status = str(harness.get("status"))
        corpus_rows += f"<tr><td>{html.escape(str(harness.get('harness')))}</td><td>{badge(status, 'ok' if status == 'ok' else 'warn')}</td><td>{html.escape(str(harness.get('output_files', 0)))}</td><td><code>{html.escape(str(harness.get('output', '-')))}</code></td></tr>"
    worker_tone = "ok" if snap.get("workers_expected") and snap.get("workers_alive") == snap.get("workers_expected") else "warn"
    raw_tone = "bad" if snap.get("raw_crashes") else ""
    post_cycle = summary.get("post_cycle", {})
    post_rows = _post_cycle_rows(post_cycle)
    advanced_rows = _advanced_triage_rows(summary.get("advanced_triage", {}))
    hybrid_rows = _hybrid_rows(summary.get("hybrid_symcc", {}))

    return f"""
<p class="breadcrumb"><a href="/">Dashboard</a> / <a href="/target/{html.escape(target)}">{html.escape(target)}</a> / {html.escape(run_id)}</p>
<div class="grid">
<section class="card span3"><h2>Run Raw</h2><div class="metric {raw_tone}">{html.escape(str(snap.get('raw_crashes', triaged_raw)))}</div><div class="muted">crash artifacts on disk</div></section>
<section class="card span3"><h2>Unique States</h2><div class="metric">{len(crashes)}</div><div class="muted">{reproducible_count} sanitizer-reproducible</div></section>
<section class="card span3"><h2>Duplicates</h2><div class="metric {'warn' if duplicate_artifacts else ''}">{duplicate_artifacts}</div><div class="muted">{triaged_raw} triaged artifacts represented</div></section>
<section class="card span3"><h2>Workers</h2><div class="metric {worker_tone}">{html.escape(str(snap.get('workers_alive', 0)))}/{html.escape(str(snap.get('workers_expected', 0)))}</div><div class="muted">{'active' if snap.get('active') else 'complete'}</div></section>
<section class="card span6"><div class="section-head"><div><h2>Actions</h2><p>Common follow-up commands for this run.</p></div></div><pre>bin/fuzzctl --runtime native monitor {html.escape(target)} --run {html.escape(run_id)} --once
bin/fuzzctl --runtime native crash-value {html.escape(target)}
bin/fuzzctl --runtime native coverage {html.escape(target)} --run {html.escape(run_id)} --max-inputs 5000
bin/fuzzctl --runtime native corpus sync {html.escape(target)} --run {html.escape(run_id)}
bin/fuzzctl --runtime native report {html.escape(target)} --run {html.escape(run_id)}
bin/fuzzctl --runtime native post-cycle {html.escape(target)} --run {html.escape(run_id)}
bin/fuzzctl --runtime native advanced-triage {html.escape(target)} --run {html.escape(run_id)}
bin/fuzzctl --runtime native hybrid symcc {html.escape(target)} --run {html.escape(run_id)} --seconds 1800
bin/fuzzctl --runtime native guide coverage {html.escape(target)} --run {html.escape(run_id)}</pre></section>
<section class="card span6"><div class="section-head"><div><h2>Run</h2><p>Run directory, lifecycle state, and execution counters.</p></div>{badge('active' if snap.get('active') else 'complete', 'ok' if snap.get('active') else 'neutral')}</div><div class="metric small">{html.escape(run_id)}</div><div class="muted">{html.escape(summary['path'])}</div><p class="muted">execs {html.escape(str(snap.get('execs', 0)))}; paths {html.escape(str(snap.get('paths', 0)))}</p></section>
<section class="card span12"><div class="section-head"><div><h2>AFL Workers</h2><p>Per-worker execution rate, queue growth, stability, coverage map, crashes, and hangs.</p></div>{badge(f"{snap.get('workers_alive', 0)}/{snap.get('workers_expected', 0)} live", worker_tone)}</div>{render_worker_stats_table(snap)}</section>
<section class="card span12"><div class="section-head"><div><h2>Unique Crashes</h2><p>One row per sanitizer state; artifact and duplicate columns explain AFL++ crash-file noise.</p></div></div>{table_wrap('<table><tr><th>Severity</th><th>Type</th><th>Harness</th><th>Artifacts</th><th>Duplicates</th><th>ID</th><th>Impact</th></tr>' + (crash_rows or '<tr><td colspan="7" class="muted">No triaged crashes.</td></tr>') + '</table>')}</section>
<section class="card span6"><div class="section-head"><div><h2>AFL Queue</h2><p>Coverage-discovering inputs by harness.</p></div></div>{table_wrap('<table><tr><th>Harness</th><th>Inputs</th></tr>' + (queue_rows or '<tr><td colspan="2" class="muted">No AFL queue found.</td></tr>') + '</table>')}</section>
<section class="card span6"><div class="section-head"><div><h2>Corpus Sync</h2><p>Minimized corpus promotion state.</p></div></div>{table_wrap('<table><tr><th>Harness</th><th>Status</th><th>Files</th><th>Output</th></tr>' + (corpus_rows or '<tr><td colspan="4" class="muted">No corpus sync yet.</td></tr>') + '</table>')}</section>
<section class="card span12"><div class="section-head"><div><h2>Coverage Inputs</h2><p>Input sources used for LLVM coverage generation.</p></div></div>{table_wrap('<table><tr><th>Harness</th><th>Selected</th><th>Sources</th></tr>' + (input_rows or '<tr><td colspan="3" class="muted">No queue-based coverage run yet.</td></tr>') + '</table>')}</section>
<section class="card span12"><div class="section-head"><div><h2>Post-Cycle</h2><p>Full cleanup status: monitor, triage, corpus, coverage, blockers, suspicious points, and QA.</p></div>{badge(post_cycle.get('status', 'not run') if isinstance(post_cycle, dict) and post_cycle else 'not run', 'ok' if isinstance(post_cycle, dict) and post_cycle.get('status') == 'ok' else 'warn')}</div>{table_wrap('<table><tr><th>Status</th><th>Step</th><th>Seconds</th><th>Detail</th></tr>' + (post_rows or '<tr><td colspan="4" class="muted">No post-cycle run yet.</td></tr>') + '</table>')}</section>
<section class="card span6"><div class="section-head"><div><h2>Advanced Triage</h2><p>Optional CASR and exploitable evidence for reproducible crashes.</p></div></div>{table_wrap('<table><tr><th>Tool</th><th>Status</th><th>Crash</th><th>Artifact</th></tr>' + (advanced_rows or '<tr><td colspan="4" class="muted">No advanced triage yet.</td></tr>') + '</table>')}</section>
<section class="card span6"><div class="section-head"><div><h2>Hybrid SymCC</h2><p>Concolic deep-dive results synced with this AFL++ run.</p></div></div>{table_wrap('<table><tr><th>Harness</th><th>Status</th><th>Generated</th><th>Log</th></tr>' + (hybrid_rows or '<tr><td colspan="4" class="muted">No SymCC hybrid pass yet.</td></tr>') + '</table>')}</section>
<section class="card span6"><div class="section-head"><div><h2>Coverage Guidance</h2><p>Coverage-driven next steps.</p></div></div><pre>{html.escape(summary.get('guidance') or 'No guidance yet.')}</pre></section>
<section class="card span6"><div class="section-head"><div><h2>Harness Blockers</h2><p>Coverage-backed reasons a harness may still be shallow.</p></div></div><pre>{html.escape(summary.get('harness_blockers') or 'No blocker analysis yet.')}</pre></section>
<section class="card span6"><div class="section-head"><div><h2>Suspicious Points</h2><p>Next parser/decoder entrypoints to target with fine-grained harnesses.</p></div></div><pre>{html.escape(summary.get('suspicious_points') or 'No suspicious-point workorder yet.')}</pre></section>
<section class="card span6"><div class="section-head"><div><h2>Coverage Report</h2><p>LLVM source coverage summary.</p></div></div><pre>{html.escape(summary.get('coverage_report') or 'No coverage report yet.')}</pre></section>
<section class="card span6"><div class="section-head"><div><h2>Reports</h2><p>Generated Markdown findings and indexes.</p></div></div><div class="list">{reports or '<div class="empty">No reports.</div>'}</div></section>
<section class="card span6"><div class="section-head"><div><h2>Logs</h2><p>Campaign, harness, and build logs.</p></div></div><div class="list">{logs or '<div class="empty">No logs.</div>'}</div></section>
</div>
"""
