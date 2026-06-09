from __future__ import annotations

import html
from pathlib import Path


def badge(label: object, tone: str = "neutral") -> str:
    safe_tone = tone if tone in {"ok", "warn", "bad", "info", "neutral"} else "neutral"
    return f"<span class='status {safe_tone}'>{html.escape(str(label))}</span>"


def service_tone(status: object) -> str:
    value = str(status)
    if value == "active":
        return "ok"
    if value in {"failed", "not-found"}:
        return "bad"
    if value in {"inactive", "deactivating", "activating"}:
        return "warn"
    return "neutral"


def crash_tone(severity: object) -> str:
    value = str(severity).upper()
    if value in {"CRITICAL", "HIGH"}:
        return "bad"
    if value == "MEDIUM":
        return "warn"
    if value in {"LOW", "INFO"}:
        return "info"
    return "neutral"


def tier_tone(tier: object) -> str:
    value = str(tier)
    if value == "report_candidate":
        return "bad"
    if value == "product_plausible":
        return "warn"
    if value == "valid_target_bug":
        return "info"
    return "neutral"


def metric_card(title: str, value: object, caption: str, tone: str = "") -> str:
    tone_class = f" {tone}" if tone else ""
    return (
        "<section class='card metric-card span3'>"
        f"<div class='section-head'><h2>{html.escape(title)}</h2></div>"
        f"<div class='metric{tone_class}'>{html.escape(str(value))}</div>"
        f"<div class='metric-label'>{html.escape(caption)}</div>"
        "</section>"
    )


def table_wrap(table: str) -> str:
    return f"<div class='table-wrap'>{table}</div>"


def profile_badges(profiles: list[str]) -> str:
    if not profiles:
        return "<span class='muted'>none</span>"
    parts = []
    for profile in profiles:
        tone = "ok" if profile == "afl_asan_ubsan" else ("warn" if "cmplog" in profile else "info")
        parts.append(badge(profile, tone))
    return "<div class='profile-list'>" + "".join(parts) + "</div>"


def _count(value: object, default: str = "0") -> str:
    try:
        return f"{int(float(str(value).replace('%', '').strip() or 0)):,}"
    except (TypeError, ValueError):
        text = str(value or "").strip()
        return html.escape(text if text else default)


def _rate(value: object) -> str:
    try:
        return f"{float(str(value).strip() or 0):,.1f}"
    except (TypeError, ValueError):
        text = str(value or "").strip()
        return html.escape(text if text else "0.0")


def _percent(value: object) -> tuple[str, float | None]:
    text = str(value or "").strip()
    if not text:
        return "-", None
    try:
        parsed = float(text.replace("%", ""))
    except ValueError:
        return html.escape(text), None
    suffix = "%" if "%" in text else ""
    return f"{parsed:.2f}{suffix}", parsed


def _worker_label(path: object) -> str:
    value = str(path or "")
    parts = Path(value).parts
    if "aflpp" in parts:
        idx = parts.index("aflpp")
        harness = parts[idx + 1] if len(parts) > idx + 1 else "unknown"
        role = parts[idx + 3] if len(parts) > idx + 3 else "worker"
        return f"{harness} / {role}"
    return value or "unknown"


def render_worker_stats_table(snapshot: dict) -> str:
    stats = list(snapshot.get("stats") or [])
    stale = set(str(item) for item in snapshot.get("stale_stats") or [])
    rows = []
    for item in stats:
        path = str(item.get("path", ""))
        label = _worker_label(path)
        stability_text, stability = _percent(item.get("stability"))
        bitmap_text, _ = _percent(item.get("bitmap_cvg"))
        crashes = int(float(item.get("saved_crashes", "0") or 0))
        hangs = int(float(item.get("saved_hangs", "0") or 0))
        if path in stale:
            state = badge("stale", "warn")
        elif stability is not None and stability < 90:
            state = badge("unstable", "warn")
        else:
            state = badge("live", "ok")
        rows.append(
            "<tr>"
            f"<td><b>{html.escape(label)}</b><div class='muted small'><code>{html.escape(path)}</code></div></td>"
            f"<td>{state}</td>"
            f"<td>{_count(item.get('execs_done'))}</td>"
            f"<td>{_rate(item.get('execs_per_sec'))}</td>"
            f"<td>{_count(item.get('corpus_count', item.get('paths_total')))}</td>"
            f"<td>{badge(stability_text, 'warn' if stability is not None and stability < 90 else 'ok')}</td>"
            f"<td>{html.escape(bitmap_text)}</td>"
            f"<td>{badge(crashes, 'bad' if crashes else 'neutral')}</td>"
            f"<td>{badge(hangs, 'warn' if hangs else 'neutral')}</td>"
            "</tr>"
        )
    if not rows:
        rows.append("<tr><td colspan='9' class='muted'>No AFL++ fuzzer_stats files found for this run.</td></tr>")
    return table_wrap(
        "<table class='worker-table'><tr><th>Worker</th><th>State</th><th>Execs</th><th>Exec/s</th>"
        "<th>Corpus</th><th>Stability</th><th>Bitmap</th><th>Crashes</th><th>Hangs</th></tr>"
        + "".join(rows)
        + "</table>"
    )
