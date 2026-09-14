"""System metric collectors: CPU, RAM, disk, load, reboot, systemd services."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from discord_webhook import COLOR_CRITICAL, COLOR_OK, COLOR_REBOOT, COLOR_WARNING

log = logging.getLogger("server-alerts.checks")


def cpu_count() -> int:
    return os.cpu_count() or 1


def read_boot_id() -> str:
    path = Path("/proc/sys/kernel/random/boot_id")
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def read_uptime_sec() -> float:
    try:
        text = Path("/proc/uptime").read_text(encoding="utf-8")
        return float(text.split()[0])
    except (OSError, ValueError, IndexError):
        return 0.0


def _proc_stat_times() -> tuple[int, int] | None:
    try:
        with open("/proc/stat", encoding="utf-8") as fh:
            line = fh.readline()
    except OSError:
        return None
    parts = line.split()
    if not parts or parts[0] != "cpu" or len(parts) < 5:
        return None
    nums = [int(x) for x in parts[1:]]
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    total = sum(nums)
    return total, idle


def mem_used_percent() -> float | None:
    info: dict[str, int] = {}
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                if not rest:
                    continue
                value = rest.strip().split()[0]
                try:
                    info[key] = int(value)
                except ValueError:
                    continue
    except OSError:
        return None
    total = info.get("MemTotal") or 0
    available = info.get("MemAvailable")
    if total <= 0 or available is None:
        return None
    used = max(total - available, 0)
    return used / total * 100.0


def load_1min() -> float | None:
    try:
        text = Path("/proc/loadavg").read_text(encoding="utf-8")
        return float(text.split()[0])
    except (OSError, ValueError, IndexError):
        return None


def disk_used_percent(mount: str) -> float | None:
    try:
        usage = shutil.disk_usage(mount)
    except OSError:
        return None
    if usage.total <= 0:
        return None
    return usage.used / usage.total * 100.0


def service_active(name: str) -> bool | None:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", name],
            check=False,
            timeout=5,
            capture_output=True,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        log.warning("systemctl is-active %s failed: %s", name, exc)
        return None
    return result.returncode == 0


@dataclass
class CpuSampler:
    prev: tuple[int, int] | None = None

    def percent(self) -> float | None:
        now = _proc_stat_times()
        if now is None:
            return None
        if self.prev is None:
            self.prev = now
            return None
        total_delta = now[0] - self.prev[0]
        idle_delta = now[1] - self.prev[1]
        self.prev = now
        if total_delta <= 0:
            return None
        busy = max(total_delta - idle_delta, 0)
        return busy / total_delta * 100.0


@dataclass
class AlertState:
    firing: bool = False
    last_sent: float = 0.0
    high_since: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "firing": self.firing,
            "last_sent": self.last_sent,
            "high_since": self.high_since,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> AlertState:
        if not data:
            return cls()
        return cls(
            firing=bool(data.get("firing")),
            last_sent=float(data.get("last_sent") or 0),
            high_since=data.get("high_since"),
        )


@dataclass
class AlertEvent:
    key: str
    title: str
    body: str
    color: int
    recovered: bool = False


@dataclass
class Thresholds:
    cpu_percent: float = 85.0
    cpu_duration_sec: float = 120.0
    ram_percent: float = 90.0
    disk_percent: float = 85.0
    load_per_core: float = 1.5
    hysteresis: float = 5.0
    load_hysteresis: float = 0.2


class SystemMonitor:
    def __init__(
        self,
        *,
        thresholds: Thresholds,
        disk_mounts: list[str],
        services: list[str],
        cooldown_sec: float,
        alert_states: dict[str, AlertState] | None = None,
        saved_boot_id: str = "",
    ) -> None:
        self.thresholds = thresholds
        self.disk_mounts = disk_mounts or ["/"]
        self.services = services
        self.cooldown_sec = cooldown_sec
        self.cpu = CpuSampler()
        self.states: dict[str, AlertState] = alert_states or {}
        self.boot_id = read_boot_id()
        self._pending_reboot = bool(
            saved_boot_id and self.boot_id and saved_boot_id != self.boot_id
        )

    def snapshot_states(self) -> dict[str, dict[str, Any]]:
        return {key: state.to_dict() for key, state in self.states.items()}

    def _state(self, key: str) -> AlertState:
        if key not in self.states:
            self.states[key] = AlertState()
        return self.states[key]

    def _transition(
        self,
        key: str,
        high: bool,
        *,
        now: float,
        duration_sec: float = 0.0,
        title_fire: str,
        title_ok: str,
        body_fire: str,
        body_ok: str,
        color_fire: int,
        color_ok: int,
    ) -> AlertEvent | None:
        state = self._state(key)
        if high:
            if state.high_since is None:
                state.high_since = now
            held = now - state.high_since
            if held < duration_sec:
                return None
            if state.firing:
                return None
            if state.last_sent and now - state.last_sent < self.cooldown_sec:
                return None
            state.firing = True
            state.last_sent = now
            return AlertEvent(key, title_fire, body_fire, color_fire, recovered=False)

        state.high_since = None
        if not state.firing:
            return None
        state.firing = False
        state.last_sent = now
        return AlertEvent(key, title_ok, body_ok, color_ok, recovered=True)

    def poll(self, now: float, hostname: str, nproc: int) -> list[AlertEvent]:
        events: list[AlertEvent] = []
        t = self.thresholds

        if self._pending_reboot:
            self._pending_reboot = False
            uptime = read_uptime_sec()
            events.append(
                AlertEvent(
                    key="reboot",
                    title="Server reboot",
                    body=(
                        f"**Host:** `{hostname}`\n"
                        f"**Uptime:** {format_duration(uptime)}\n"
                        f"**Boot ID:** `{self.boot_id or 'unknown'}`"
                    ),
                    color=COLOR_REBOOT,
                )
            )

        cpu = self.cpu.percent()
        if cpu is not None:
            recover_at = max(t.cpu_percent - t.hysteresis, 0)
            high = cpu >= t.cpu_percent if not self._state("cpu").firing else cpu >= recover_at
            color = COLOR_CRITICAL if cpu >= 95 else COLOR_WARNING
            ev = self._transition(
                "cpu",
                high,
                now=now,
                duration_sec=t.cpu_duration_sec,
                title_fire="High CPU usage",
                title_ok="CPU recovered",
                body_fire=(
                    f"**Host:** `{hostname}`\n"
                    f"**CPU:** `{cpu:.1f}%` (threshold {t.cpu_percent:.0f}% "
                    f"for {int(t.cpu_duration_sec)}s)\n"
                    f"**Cores:** `{nproc}`"
                ),
                body_ok=f"**Host:** `{hostname}`\n**CPU:** `{cpu:.1f}%`",
                color_fire=color,
                color_ok=COLOR_OK,
            )
            if ev:
                events.append(ev)

        ram = mem_used_percent()
        if ram is not None:
            recover_at = max(t.ram_percent - t.hysteresis, 0)
            high = ram >= t.ram_percent if not self._state("ram").firing else ram >= recover_at
            color = COLOR_CRITICAL if ram >= 97 else COLOR_WARNING
            ev = self._transition(
                "ram",
                high,
                now=now,
                title_fire="High RAM usage",
                title_ok="RAM recovered",
                body_fire=(
                    f"**Host:** `{hostname}`\n"
                    f"**RAM:** `{ram:.1f}%` (threshold {t.ram_percent:.0f}%)"
                ),
                body_ok=f"**Host:** `{hostname}`\n**RAM:** `{ram:.1f}%`",
                color_fire=color,
                color_ok=COLOR_OK,
            )
            if ev:
                events.append(ev)

        load = load_1min()
        if load is not None:
            limit = t.load_per_core * nproc
            recover_at = max(limit - t.load_hysteresis * nproc, 0)
            high = load >= limit if not self._state("load").firing else load >= recover_at
            color = COLOR_CRITICAL if load >= limit * 1.5 else COLOR_WARNING
            ev = self._transition(
                "load",
                high,
                now=now,
                title_fire="High load average",
                title_ok="Load recovered",
                body_fire=(
                    f"**Host:** `{hostname}`\n"
                    f"**Load 1m:** `{load:.2f}`\n"
                    f"**Threshold:** `{limit:.2f}` "
                    f"({t.load_per_core:.2f} × {nproc} cores)"
                ),
                body_ok=(
                    f"**Host:** `{hostname}`\n"
                    f"**Load 1m:** `{load:.2f}` / `{limit:.2f}`"
                ),
                color_fire=color,
                color_ok=COLOR_OK,
            )
            if ev:
                events.append(ev)

        for mount in self.disk_mounts:
            used = disk_used_percent(mount)
            if used is None:
                log.warning("cannot read disk usage for %s", mount)
                continue
            key = f"disk:{mount}"
            recover_at = max(t.disk_percent - t.hysteresis, 0)
            high = used >= t.disk_percent if not self._state(key).firing else used >= recover_at
            color = COLOR_CRITICAL if used >= 95 else COLOR_WARNING
            ev = self._transition(
                key,
                high,
                now=now,
                title_fire=f"Disk almost full ({mount})",
                title_ok=f"Disk recovered ({mount})",
                body_fire=(
                    f"**Host:** `{hostname}`\n"
                    f"**Mount:** `{mount}`\n"
                    f"**Used:** `{used:.1f}%` (threshold {t.disk_percent:.0f}%)"
                ),
                body_ok=(
                    f"**Host:** `{hostname}`\n"
                    f"**Mount:** `{mount}`\n"
                    f"**Used:** `{used:.1f}%`"
                ),
                color_fire=color,
                color_ok=COLOR_OK,
            )
            if ev:
                events.append(ev)

        for name in self.services:
            active = service_active(name)
            if active is None:
                continue
            key = f"service:{name}"
            ev = self._transition(
                key,
                not active,
                now=now,
                title_fire=f"Service down: {name}",
                title_ok=f"Service recovered: {name}",
                body_fire=(
                    f"**Host:** `{hostname}`\n"
                    f"**Service:** `{name}`\n"
                    f"**Status:** inactive / failed"
                ),
                body_ok=(
                    f"**Host:** `{hostname}`\n"
                    f"**Service:** `{name}`\n"
                    f"**Status:** active"
                ),
                color_fire=COLOR_CRITICAL,
                color_ok=COLOR_OK,
            )
            if ev:
                events.append(ev)

        return events


def format_duration(seconds: float) -> str:
    total = int(max(seconds, 0))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if minutes or hours or days:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)
