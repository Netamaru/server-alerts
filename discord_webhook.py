"""Discord webhook client using Components V2 (no content/embeds)."""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.request
from typing import Any

log = logging.getLogger("server-alerts.discord")

IS_COMPONENTS_V2 = 1 << 15  # 32768
COLOR_CRITICAL = 0xE74C3C
COLOR_WARNING = 0xF39C12
COLOR_OK = 0x2ECC71
COLOR_SSH_LOGIN = 0x2ECC71
COLOR_SSH_LOGOUT = 0x3498DB
COLOR_ROOT = 0xE74C3C
COLOR_REBOOT = 0x9B59B6

TYPE_SEPARATOR = 14
TYPE_TEXT = 10
TYPE_CONTAINER = 17
SPACING_SMALL = 1
SPACING_LARGE = 2

MAX_RETRIES = 3
TIMEOUT_SEC = 15
RE_FIELD_LINE = re.compile(r"^\*\*(.+?):\*\*\s*(.*)$")


def is_placeholder_url(url: str | None) -> bool:
    if not url:
        return True
    lowered = url.strip().lower()
    return (
        "change_me" in lowered
        or not lowered.startswith("https://")
        or "/api/webhooks/" not in lowered
    )


def redact_url(url: str) -> str:
    if not url:
        return "(empty)"
    parts = url.rstrip("/").split("/")
    if len(parts) >= 2:
        return f"{'/'.join(parts[:-1])}/…"
    return "(redacted)"


def _append_query(url: str, query: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{query}"


def format_discord_time(ts: float | None = None) -> str:
    """Absolute + relative Discord timestamp, rendered in each viewer's timezone."""
    unix = int(ts if ts is not None else time.time())
    return f"<t:{unix}:f> · <t:{unix}:R>"


def parse_body_fields(body: str) -> tuple[list[tuple[str, str]], list[str]]:
    fields: list[tuple[str, str]] = []
    extra: list[str] = []
    for raw in (body or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        match = RE_FIELD_LINE.match(line)
        if match:
            fields.append((match.group(1).strip(), match.group(2).strip()))
        else:
            extra.append(line)
    return fields, extra


def _text(content: str) -> dict[str, Any]:
    return {"type": TYPE_TEXT, "content": content}


def _separator(*, divider: bool = True, spacing: int = SPACING_SMALL) -> dict[str, Any]:
    return {"type": TYPE_SEPARATOR, "divider": divider, "spacing": spacing}


def _field_value(value: str) -> str:
    value = value or "—"
    if value.startswith("`") or value.startswith("<t:") or value.startswith("http"):
        return value
    return f"`{value}`"


def _fields_markdown(fields: list[tuple[str, str]]) -> str:
    lines: list[str] = []
    for name, value in fields:
        lines.append(f"**{name}**  {_field_value(value)}")
    return "\n".join(lines)


def build_payload(
    title: str,
    body: str,
    color: int,
    username: str,
    timestamp: float | None = None,
) -> dict[str, Any]:
    fields, extra = parse_body_fields(body)
    time_text = ""
    visible: list[tuple[str, str]] = []
    for name, value in fields:
        if name.lower() == "time":
            time_text = value
            continue
        visible.append((name, value))

    inner: list[dict[str, Any]] = [_text(f"## {title}")]
    if visible or extra:
        inner.append(_separator(spacing=SPACING_SMALL))
    if visible:
        inner.append(_text(_fields_markdown(visible)))
    if extra:
        inner.append(_text("\n".join(extra)))
    inner.append(_separator(spacing=SPACING_LARGE))
    inner.append(_text(f"-# {time_text or format_discord_time(timestamp)}"))

    return {
        "flags": IS_COMPONENTS_V2,
        "username": (username or "server-alerts")[:80],
        "allowed_mentions": {"parse": []},
        "components": [
            {
                "type": TYPE_CONTAINER,
                "accent_color": int(color) & 0xFFFFFF,
                "components": inner,
            }
        ],
    }


def send(
    url: str,
    *,
    title: str,
    body: str,
    color: int,
    username: str,
    timestamp: float | None = None,
) -> bool:
    if is_placeholder_url(url):
        log.warning("skip send %s: webhook URL is not set", title)
        return False

    payload = build_payload(title, body, color, username, timestamp=timestamp)
    data = json.dumps(payload).encode("utf-8")
    target = _append_query(url.strip(), "with_components=true")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "server-alerts/1.0",
    }

    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        req = urllib.request.Request(target, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as resp:
                if 200 <= resp.status < 300:
                    log.info("sent %s (%s)", title, redact_url(url))
                    return True
                last_error = f"HTTP {resp.status}"
        except urllib.error.HTTPError as exc:
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            body_preview = ""
            try:
                body_preview = exc.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                pass
            last_error = f"HTTP {exc.code} {body_preview}"
            if exc.code == 429:
                wait = float(retry_after or (2 ** attempt))
                log.warning("rate limited, sleep %.1fs", wait)
                time.sleep(wait)
                continue
            if 400 <= exc.code < 500 and exc.code != 429:
                log.error("send failed %s: %s", title, last_error)
                return False
        except Exception as exc:
            last_error = str(exc)

        wait = 2 ** (attempt - 1)
        log.warning(
            "send retry %s/%s for %s after %.0fs: %s",
            attempt,
            MAX_RETRIES,
            title,
            wait,
            last_error,
        )
        time.sleep(wait)

    log.error("give up sending %s: %s", title, last_error)
    return False
