from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .util import FuzzCtlError


@dataclass
class AlertEvent:
    key: str
    title: str
    description: str
    severity: str = "INFO"
    fields: dict[str, Any] | None = None


COLORS = {
    "CRITICAL": 0xD00000,
    "HIGH": 0xFF6B00,
    "MEDIUM": 0xE6B800,
    "LOW": 0x6C757D,
    "INFO": 0x2F80ED,
    "ERROR": 0xD00000
}


def webhook_url(explicit: str | None = None) -> str | None:
    return explicit or os.environ.get("DISCORD_WEBHOOK_URL")


def send_discord(event: AlertEvent, *, url: str | None = None, dry_run: bool = False) -> bool:
    target = webhook_url(url)
    payload = {
        "username": "fuzz-pipeline",
        "embeds": [
            {
                "title": event.title[:256],
                "description": event.description[:4096],
                "color": COLORS.get(event.severity.upper(), COLORS["INFO"]),
                "fields": [
                    {"name": str(k)[:256], "value": str(v)[:1024], "inline": False}
                    for k, v in (event.fields or {}).items()
                ][:20]
            }
        ]
    }
    if dry_run or not target:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return False
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        target,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "fuzz-pipeline/0.1"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            if response.status in {200, 204}:
                return True
            raise FuzzCtlError(f"Discord webhook returned HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise FuzzCtlError(f"Discord webhook failed HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise FuzzCtlError(f"Discord webhook failed: {exc}") from exc


def test_alert(*, url: str | None = None, dry_run: bool = False) -> bool:
    return send_discord(
        AlertEvent(
            key="test",
            title="fuzz-pipeline test alert",
            description="Discord webhook delivery is configured.",
            severity="INFO",
            fields={"source": "fuzzctl alerts test"}
        ),
        url=url,
        dry_run=dry_run
    )

