from __future__ import annotations

import html
from pathlib import Path

from .dashboard_ui import badge, crash_tone, service_tone, table_wrap, tier_tone
from .findings import severity_value
from .monitor_snapshot import _snapshot


def render_connectivity(conn: dict) -> str:
    rows = [
        ("Recommended access", conn["recommended_access"]),
        ("Browser URL after tunnel", conn["recommended_url"]),
        ("Bind", f"{conn['bind_host']}:{conn['bind_port']}"),
        ("Private URL", conn["private_url"]),
        ("Public URL", conn["public_url"]),
        ("Token auth", conn["token_auth"]),
        ("Local listener", "ok" if conn["listener_ok"] else "not reachable from localhost"),
        ("Firewall hint", conn["firewall_hint"]),
    ]
    body = "<table><tr><th>Check</th><th>Value</th></tr>"
    for label, value in rows:
        if label == "Local listener":
            value_html = badge(value, "ok" if conn["listener_ok"] else "bad")
        elif label == "Token auth":
            value_html = badge(value, "ok" if value == "enabled" else "warn")
        else:
            value_html = html.escape(str(value))
        body += f"<tr><td>{html.escape(label)}</td><td>{value_html}</td></tr>"
    body = table_wrap(body + "</table>")
    body += f"<p class='muted'>{html.escape(conn['note'])}</p>"
    body += f"<h3>SSH Tunnel</h3><pre>{html.escape(conn['ssh_tunnel'])}</pre>"
    return body


def render_tools_table(tools: dict) -> str:
    rows = []
    for tool in tools["tools"]:
        cls = "ok" if tool["installed"] else ("bad" if tool["required"] else "warn")
        status = "ok" if tool["installed"] else "missing"
        need = "required" if tool["required"] else "optional"
        rows.append(
            f"<tr><td>{badge(status, cls)}</td><td>{html.escape(tool['name'])}</td>"
            f"<td>{badge(need, 'bad' if tool['required'] and not tool['installed'] else 'neutral')}</td>"
            f"<td><code>{html.escape(tool.get('path') or '-')}</code></td></tr>"
        )
    return table_wrap("<table><tr><th>Status</th><th>Tool</th><th>Need</th><th>Path</th></tr>" + "".join(rows) + "</table>")


def render_systemd_table(systemd: dict) -> str:
    rows = []
    for name, status in systemd.items():
        rows.append(f"<tr><td><code>{html.escape(name)}</code></td><td>{badge(status, service_tone(status))}</td></tr>")
    return table_wrap("<table><tr><th>Service</th><th>Status</th></tr>" + "".join(rows) + "</table>")


def render_supervisor_table(supervisor: dict) -> str:
    rows = []
    for target, data in sorted(supervisor.items()):
        state = data.get("state") or {}
        status = state.get("status", "unknown")
        active_count = len(data.get("active_processes") or [])
        cls = "ok" if status in {"running_campaign", "waiting_existing_campaign"} else ("warn" if status != "unknown" else "neutral")
        detail = ""
        if state.get("run_ids"):
            detail = ", ".join(str(item) for item in state.get("run_ids", []))
        elif state.get("next_check_seconds"):
            detail = f"next check {state.get('next_check_seconds')}s"
        rows.append(
            f"<tr><td>{html.escape(str(target))}</td><td>{badge(status, cls)}</td>"
            f"<td>{active_count}</td><td>{html.escape(detail)}</td></tr>"
        )
    return table_wrap("<table><tr><th>Target</th><th>Status</th><th>Active Processes</th><th>Detail</th></tr>" + "".join(rows) + "</table>")


def render_findings_panel(targets: list[dict]) -> str:
    all_findings = []
    for target in targets:
        target_name = str(target.get("name"))
        for finding in (target.get("findings") or {}).get("findings", []):
            all_findings.append((target_name, finding))
    all_findings.sort(
        key=lambda item: (
            severity_value(item[1].get("severity")),
            str(item[1].get("last_seen", item[1].get("run_id", ""))),
        ),
        reverse=True,
    )
    rows = []
    for target_name, finding in all_findings[:20]:
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
            f"<td>{html.escape(target_name)}</td>"
            f"<td>{badge(severity, crash_tone(severity))}</td>"
            f"<td>{html.escape(str(finding.get('type', 'unknown')))}</td>"
            f"<td>{html.escape(str(finding.get('harness', 'unknown')))}</td>"
            f"<td>{artifacts}</td>"
            f"<td>{occurrences}</td>"
            f"<td>{report_link}</td>"
            f"<td><a href='/run/{html.escape(target_name)}/{html.escape(str(finding.get('run_id', '')))}'>{html.escape(str(finding.get('run_id', '')))}</a></td>"
            "</tr>"
        )
    if not rows:
        return "<section class='card span12'><div class='section-head'><div><h2>Confirmed Findings</h2><p>No sanitizer-reproducible crashes have been triaged yet.</p></div>{}</div></section>".format(badge("0", "neutral"))
    count_note = "" if len(all_findings) <= len(rows) else f" Showing first {len(rows)}."
    collapsed = sum(int(finding.get("duplicate_artifacts", 0) or 0) for _, finding in all_findings)
    duplicate_note = f" {collapsed} duplicate artifacts are collapsed into these rows." if collapsed else ""
    return (
        "<section class='card span12'>"
        "<div class='section-head'><div><h2>Confirmed Findings</h2>"
        f"<p>Target-wide unique sanitizer states across all runs.{html.escape(duplicate_note + count_note)}</p></div>"
        f"{badge(str(len(all_findings)), 'bad')}"
        "</div>"
        + table_wrap("<table><tr><th>Target</th><th>Severity</th><th>Type</th><th>Harness</th><th>Artifacts</th><th>Runs</th><th>ID / Report</th><th>Latest Run</th></tr>" + "".join(rows) + "</table>")
        + "</section>"
    )


def render_crash_value_panel(targets: list[dict]) -> str:
    records: list[tuple[str, dict]] = []
    totals = {
        "report_candidate": 0,
        "product_plausible": 0,
        "valid_target_bug": 0,
        "noise": 0,
    }
    for target in targets:
        target_name = str(target.get("name"))
        value = target.get("crash_value") or {}
        tier_counts = (value.get("summary") or {}).get("tier_counts") or {}
        for key in totals:
            totals[key] += int(tier_counts.get(key, 0) or 0)
        for record in value.get("records", []):
            records.append((target_name, record))
    records.sort(
        key=lambda item: (
            {"report_candidate": 4, "product_plausible": 3, "valid_target_bug": 2, "needs_repro": 1, "noise": 0}.get(str(item[1].get("tier")), -1),
            int(item[1].get("score", 0) or 0),
        ),
        reverse=True,
    )
    rows = []
    for target_name, record in records[:15]:
        root = record.get("root_cause") or {}
        root_text = str(root.get("file") or "unknown")
        if root.get("line"):
            root_text += f":{root.get('line')}"
        crash_id = str(record.get("id") or "unknown")
        rows.append(
            "<tr>"
            f"<td>{badge(record.get('tier_label') or record.get('tier'), tier_tone(record.get('tier')))}</td>"
            f"<td>{html.escape(str(record.get('score', 0)))}</td>"
            f"<td>{html.escape(target_name)}</td>"
            f"<td>{html.escape(str(record.get('crash_class', 'unknown')))}</td>"
            f"<td><code>{html.escape(root_text)}</code></td>"
            f"<td><a href='/crash/{html.escape(target_name)}/{html.escape(crash_id)}'><code>{html.escape(crash_id)}</code></a></td>"
            f"<td>{html.escape(str(record.get('next_required_proof', '')))}</td>"
            "</tr>"
        )
    summary_badge = (
        f"{totals['report_candidate']} report, {totals['product_plausible']} product-plausible, "
        f"{totals['valid_target_bug']} valid, {totals['noise']} noise"
    )
    if not rows:
        return (
            "<section class='card span12'><div class='section-head'><div><h2>Crash Value Inbox</h2>"
            "<p>No analyzed crash-value records yet. Run triage first.</p></div>"
            f"{badge('empty', 'neutral')}</div></section>"
        )
    return (
        "<section class='card span12'>"
        "<div class='section-head'><div><h2>Crash Value Inbox</h2>"
        "<p>Evidence-ranked crash queue. This is the priority list, not raw AFL++ crash noise.</p></div>"
        f"{badge(summary_badge, 'warn' if totals['product_plausible'] else 'neutral')}"
        "</div>"
        + table_wrap(
            "<table><tr><th>Tier</th><th>Score</th><th>Target</th><th>Class</th><th>Root Cause</th><th>ID</th><th>Next Proof</th></tr>"
            + "".join(rows)
            + "</table>"
        )
        + "</section>"
    )


def render_active_campaigns(workspace: Path, targets: list[dict], supervisor: dict) -> str:
    cards = []
    for target in targets:
        name = str(target.get("name"))
        run_id = target.get("latest_run")
        active = (supervisor.get(name) or {}).get("active_processes") or []
        afl_workers = [process for process in active if process.get("kind") == "afl-fuzz"]
        execs = paths = raw = "0"
        worker_text = f"{len(afl_workers)} AFL++"
        findings = target.get("findings") or {}
        confirmed = int(findings.get("reproducible", 0) or 0)
        high_or_critical = int(findings.get("high_or_critical", 0) or 0)
        collapsed_duplicates = int(findings.get("duplicate_artifacts", 0) or 0)
        raw_label = "current-run crash artifacts"
        if run_id:
            try:
                snap = _snapshot(workspace, workspace / "runs" / name / str(run_id))
                execs = f"{int(snap.get('execs', 0)):,}"
                paths = f"{int(snap.get('paths', 0)):,}"
                raw = str(snap.get("raw_crashes", 0))
                raw_label = f"{int(snap.get('duplicate_crashes', 0) or 0)} duplicates after triage"
                if snap.get("workers_expected"):
                    worker_text = f"{snap.get('workers_alive', 0)}/{snap.get('workers_expected', 0)} AFL++"
            except Exception:
                pass
            run_link = f"<a href='/run/{html.escape(name)}/{html.escape(str(run_id))}'>{html.escape(str(run_id))}</a>"
        else:
            run_link = "<span class='muted'>no runs</span>"
        status = (supervisor.get(name) or {}).get("state", {}).get("status", "unknown")
        cards.append(
            "<section class='campaign-card span12'>"
            "<div class='campaign-title'>"
            f"<div><h2>{html.escape(name)}</h2><p>Active run {run_link}</p></div>"
            f"{badge(status, 'ok' if status in {'running_campaign', 'waiting_existing_campaign'} else 'neutral')}"
            "</div>"
            "<div class='campaign-metrics'>"
            f"<div class='campaign-metric'><h3>Workers</h3><div class='metric'>{html.escape(worker_text)}</div><div class='metric-label'>long-running AFL++ capacity</div></div>"
            f"<div class='campaign-metric'><h3>Execs</h3><div class='metric'>{execs}</div><div class='metric-label'>total AFL++ executions</div></div>"
            f"<div class='campaign-metric'><h3>Paths</h3><div class='metric'>{paths}</div><div class='metric-label'>coverage-discovering queue paths</div></div>"
            f"<div class='campaign-metric'><h3>Unique Findings</h3><div class='metric {'bad' if confirmed else ''}'>{confirmed}</div><div class='metric-label'>{high_or_critical} high/critical, {collapsed_duplicates} duplicates collapsed</div></div>"
            f"<div class='campaign-metric'><h3>Active Raw</h3><div class='metric {'bad' if raw != '0' else ''}'>{html.escape(raw)}</div><div class='metric-label'>{html.escape(raw_label)}</div></div>"
            "</div>"
            "</section>"
        )
    return "".join(cards) if cards else "<section class='card span12'><div class='empty'>No production fuzzing targets configured.</div></section>"
