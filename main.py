#!/usr/bin/env python3
"""Server Discord Alerts — system metrics + SSH login/logout."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

from checks import AlertState, SystemMonitor, Thresholds, cpu_count, read_boot_id
from discord_webhook import (
    COLOR_SSH_LOGIN,
    COLOR_WARNING,
    is_placeholder_url,
    send as discord_send,
)
from ssh_watch import SshWatcher

BASE_DIR = Path(__file__).resolve().parent
log = logging.getLogger("server-alerts")


def default_config() -> dict[str, Any]:
    return {
        "webhooks": {"system": "", "ssh": ""},
        "hostname": None,
        "poll_interval_sec": 15,
        "cooldown_sec": 300,
        "state_path": "/var/lib/server-alerts/state.json",
        "thresholds": {
            "cpu_percent": 85,
            "cpu_duration_sec": 120,
            "ram_percent": 90,
            "disk_percent": 85,
            "load_per_core": 1.5,
        },
        "disk_mounts": ["/"],
        "services": ["ssh", "docker", "nginx"],
        "ssh": {"journal_unit": "ssh"},
    }


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise SystemExit(f"config not found: {path}")
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise SystemExit("config.json must be a JSON object")
    return deep_merge(default_config(), data)


def resolve_state_path(configured: str) -> Path:
    path = Path(configured)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        probe = path.parent / ".write-test"
        probe.write_text("", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return path
    except OSError:
        fallback = BASE_DIR / "state.json"
        log.warning("cannot write %s, using %s", path, fallback)
        return fallback


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("state file is corrupt, starting empty: %s", exc)
        return {}


class AlertApp:
    def __init__(self, cfg: dict[str, Any], config_path: Path) -> None:
        self.cfg = cfg
        self.config_path = config_path
        self.hostname = cfg.get("hostname") or socket.gethostname()
        self.poll_interval = max(float(cfg.get("poll_interval_sec") or 15), 5)
        self.cooldown = float(cfg.get("cooldown_sec") or 300)
        self.state_path = resolve_state_path(str(cfg.get("state_path")))
        self.state = load_state(self.state_path)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        th = cfg.get("thresholds") or {}
        thresholds = Thresholds(
            cpu_percent=float(th.get("cpu_percent", 85)),
            cpu_duration_sec=float(th.get("cpu_duration_sec", 120)),
            ram_percent=float(th.get("ram_percent", 90)),
            disk_percent=float(th.get("disk_percent", 85)),
            load_per_core=float(th.get("load_per_core", 1.5)),
        )
        saved_alerts = {
            key: AlertState.from_dict(value)
            for key, value in (self.state.get("alerts") or {}).items()
        }
        self.monitor = SystemMonitor(
            thresholds=thresholds,
            disk_mounts=list(cfg.get("disk_mounts") or ["/"]),
            services=list(cfg.get("services") or []),
            cooldown_sec=self.cooldown,
            alert_states=saved_alerts,
            saved_boot_id=str(self.state.get("boot_id") or ""),
        )
        ssh_cfg = cfg.get("ssh") or {}
        idents = ssh_cfg.get("journal_identifiers")
        watcher_kw: dict[str, Any] = {}
        if isinstance(idents, list) and idents:
            watcher_kw["journal_identifiers"] = [str(item) for item in idents if item]
        self.ssh = SshWatcher(
            journal_unit=str(ssh_cfg.get("journal_unit") or "ssh"),
            hostname=self.hostname,
            send=self._send_ssh,
            **watcher_kw,
        )
        self.ssh.load_sessions(self.state.get("ssh_sessions"), time.time())

    def persist(self) -> None:
        with self.lock:
            payload = {
                "boot_id": self.monitor.boot_id or read_boot_id(),
                "alerts": self.monitor.snapshot_states(),
                "ssh_sessions": self.ssh.snapshot_sessions(),
            }
            try:
                atomic_write_json(self.state_path, payload)
            except OSError as exc:
                log.error("failed to save state: %s", exc)

    def _send_system(self, title: str, body: str, color: int) -> None:
        discord_send(
            self.cfg["webhooks"]["system"],
            title=title,
            body=body,
            color=color,
            username=self.hostname,
        )

    def _send_ssh(self, title: str, body: str, color: int) -> None:
        discord_send(
            self.cfg["webhooks"]["ssh"],
            title=title,
            body=body,
            color=color,
            username=self.hostname,
        )
        self.persist()

    def system_loop(self) -> None:
        nproc = cpu_count()
        while not self.stop_event.is_set():
            try:
                events = self.monitor.poll(time.time(), self.hostname, nproc)
                for event in events:
                    self._send_system(event.title, event.body, event.color)
                if events:
                    self.persist()
            except Exception:
                log.exception("system poll failed")
            if self.stop_event.wait(self.poll_interval):
                break

    def run(self) -> int:
        log.info(
            "start host=%s config=%s state=%s interval=%ss",
            self.hostname,
            self.config_path,
            self.state_path,
            int(self.poll_interval),
        )
        if is_placeholder_url(self.cfg["webhooks"]["system"]):
            log.warning("system webhook is not set in config.json")
        if is_placeholder_url(self.cfg["webhooks"]["ssh"]):
            log.warning("ssh webhook is not set in config.json")

        self.persist()
        ssh_thread = threading.Thread(target=self.ssh.run, name="ssh-watch", daemon=True)
        sys_thread = threading.Thread(target=self.system_loop, name="sys-mon", daemon=True)
        sys_thread.start()
        ssh_thread.start()

        def handle_stop(signum: int, _frame: Any) -> None:
            log.info("signal %s, shutting down", signum)
            self.stop_event.set()
            self.ssh.request_stop()

        signal.signal(signal.SIGTERM, handle_stop)
        signal.signal(signal.SIGINT, handle_stop)
        while not self.stop_event.is_set():
            self.stop_event.wait(1)
        ssh_thread.join(timeout=5)
        self.persist()
        log.info("stopped")
        return 0


def test_webhooks(cfg: dict[str, Any]) -> int:
    hostname = cfg.get("hostname") or socket.gethostname()
    system_ok = discord_send(
        cfg["webhooks"]["system"],
        title="Test system alert",
        body=(
            f"**Host:** `{hostname}`\n"
            f"**Status:** system webhook OK\n"
            f"If you can see this message, the system alerts channel is connected."
        ),
        color=COLOR_WARNING,
        username=hostname,
    )
    ssh_ok = discord_send(
        cfg["webhooks"]["ssh"],
        title="Test SSH alert",
        body=(
            f"**User:** `test`\n"
            f"**IP:** `203.0.113.10`\n"
            f"**Port:** `22`\n"
            f"**Method:** `publickey`\n"
            f"**Key:** `ED25519 SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abc`\n"
            f"**Key name:** `laptop-example`\n"
            f"**Host:** `{hostname}`\n"
            f"If you can see this message, the SSH alerts channel is connected."
        ),
        color=COLOR_SSH_LOGIN,
        username=hostname,
    )
    if system_ok and ssh_ok:
        print("both webhooks OK")
        return 0
    if is_placeholder_url(cfg["webhooks"]["system"]) or is_placeholder_url(
        cfg["webhooks"]["ssh"]
    ):
        print(
            "set webhooks.system and webhooks.ssh in config.json first, "
            "then run: python3 main.py --test-webhooks",
            file=sys.stderr,
        )
        return 2
    print("one or both webhooks failed — check the log above", file=sys.stderr)
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Server Discord Alerts")
    parser.add_argument(
        "--config",
        default=os.environ.get("SERVER_ALERTS_CONFIG", str(BASE_DIR / "config.json")),
        help="path to config.json",
    )
    parser.add_argument(
        "--test-webhooks",
        action="store_true",
        help="send one dummy message to each channel, then exit",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="one system poll (debug), without following SSH",
    )
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    args = parse_args()
    config_path = Path(args.config).expanduser().resolve()
    cfg = load_config(config_path)

    if args.test_webhooks:
        return test_webhooks(cfg)

    app = AlertApp(cfg, config_path)
    if args.once:
        events = app.monitor.poll(time.time(), app.hostname, cpu_count())
        for event in events:
            print(f"{event.title}: {event.body}")
        if not events:
            print("no alerts (everything is below threshold)")
        app.persist()
        return 0
    return app.run()


if __name__ == "__main__":
    sys.exit(main())
