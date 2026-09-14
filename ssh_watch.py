"""Follow sshd journal for successful login and logout events."""

from __future__ import annotations

import json
import logging
import pwd
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from checks import format_duration
from discord_webhook import COLOR_ROOT, COLOR_SSH_LOGIN, COLOR_SSH_LOGOUT

log = logging.getLogger("server-alerts.ssh")

RE_ACCEPTED = re.compile(
    r"Accepted (?P<method>publickey|password|keyboard-interactive(?:/pam)?|kex|hostbased)"
    r" for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
    r"(?: ssh2(?:: (?P<keyinfo>.+))?)?"
)
RE_KEYINFO = re.compile(
    r"(?:(?P<keytype>ssh-(?:rsa|ed25519|dss|ecdsa-sha2-nistp\d+)|"
    r"ecdsa-sha2-nistp\d+|RSA|ED25519|ECDSA|DSA)\s+)?"
    r"(?P<fp>(?:SHA256:[A-Za-z0-9+/=]+|MD5(?::[0-9a-fA-F]{2}){16}))"
    r"(?:\s+(?P<comment>.+))?"
)
RE_FOUND_KEY = re.compile(
    r"Found matching (?P<keytype>\S+) key: "
    r"(?P<fp>SHA256:[A-Za-z0-9+/=]+|MD5(?::[0-9a-fA-F]{2}){16})"
)
RE_KEYGEN_LF = re.compile(
    r"^\s*\d+\s+(SHA256:[A-Za-z0-9+/=]+)\s+(.*?)\s+\(([^)]+)\)\s*$"
)
RE_DISCONNECT = re.compile(
    r"^Disconnected from user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)"
)
RE_SESSION_OPEN = re.compile(
    r"session opened for user (?P<user>[^\s(]+)(?:\(uid=\d+\))?"
)
RE_SESSION_CLOSE = re.compile(
    r"session closed for user (?P<user>[^\s(]+)"
)

SendFn = Callable[[str, str, int], None]


def session_key(user: str, ip: str, port: str) -> str:
    return f"{user}|{ip}|{port}"


def parse_keyinfo(raw: str | None) -> tuple[str, str, str]:
    if not raw:
        return "", "", ""
    match = RE_KEYINFO.search(raw.strip())
    if not match:
        return "", "", raw.strip()
    comment = (match.group("comment") or "").strip()
    return (
        (match.group("keytype") or "").strip(),
        (match.group("fp") or "").strip(),
        comment,
    )


def authorized_keys_paths(user: str) -> list[Path]:
    homes: list[Path] = []
    try:
        homes.append(Path(pwd.getpwnam(user).pw_dir))
    except KeyError:
        pass
    if user == "root":
        homes.append(Path("/root"))
    paths: list[Path] = []
    seen: set[str] = set()
    for home in homes:
        for name in ("authorized_keys", "authorized_keys2"):
            path = home / ".ssh" / name
            key = str(path)
            if key not in seen:
                seen.add(key)
                paths.append(path)
    return paths


@dataclass
class KeyCatalog:
    """Map SHA256 fingerprints to authorized_keys comments."""

    _mtimes: dict[str, float] = field(default_factory=dict)
    _by_fp: dict[str, tuple[str, str]] = field(default_factory=dict)
    _by_user_fp: dict[str, tuple[str, str]] = field(default_factory=dict)

    def resolve(self, user: str, fingerprint: str) -> tuple[str, str]:
        if not fingerprint:
            return "", ""
        self._load_user(user)
        fp = fingerprint.strip()
        return self._by_user_fp.get(f"{user}|{fp}") or self._by_fp.get(fp) or ("", "")

    def _load_user(self, user: str) -> None:
        for path in authorized_keys_paths(user):
            try:
                mtime = path.stat().st_mtime
            except OSError:
                continue
            cache_key = str(path)
            if self._mtimes.get(cache_key) == mtime:
                continue
            self._mtimes[cache_key] = mtime
            try:
                result = subprocess.run(
                    ["ssh-keygen", "-lf", str(path)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
                log.warning("ssh-keygen -lf %s failed: %s", path, exc)
                continue
            if result.returncode != 0:
                continue
            for line in result.stdout.splitlines():
                match = RE_KEYGEN_LF.match(line)
                if not match:
                    continue
                fp, comment, keytype = match.group(1), match.group(2).strip(), match.group(3)
                if comment.lower() in {"no comment", "none", ""}:
                    comment = ""
                self._by_fp[fp] = (comment, keytype)
                self._by_user_fp[f"{user}|{fp}"] = (comment, keytype)


def format_key_fields(method: str, key_type: str, key_fp: str, key_name: str) -> str:
    if method != "publickey" and not key_fp:
        return "**Key:** `n/a`\n"
    bits = " ".join(part for part in (key_type, key_fp) if part) or "unknown"
    lines = [f"**Key:** `{bits}`"]
    if key_name:
        lines.append(f"**Key name:** `{key_name}`")
    return "".join(line + "\n" for line in lines)


def parse_journal_ts(entry: dict[str, Any]) -> float:
    raw = entry.get("__REALTIME_TIMESTAMP")
    try:
        return int(raw) / 1_000_000
    except (TypeError, ValueError):
        return time.time()


def format_local(ts: float) -> str:
    dt = datetime.fromtimestamp(ts).astimezone()
    tz = dt.tzname() or dt.strftime("%z")
    return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} {tz}"


@dataclass
class SshSession:
    user: str
    ip: str
    port: str
    method: str
    started: float
    key_type: str = ""
    key_fp: str = ""
    key_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "user": self.user,
            "ip": self.ip,
            "port": self.port,
            "method": self.method,
            "started": self.started,
            "key_type": self.key_type,
            "key_fp": self.key_fp,
            "key_name": self.key_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SshSession:
        return cls(
            user=str(data.get("user") or "?"),
            ip=str(data.get("ip") or "?"),
            port=str(data.get("port") or "?"),
            method=str(data.get("method") or "unknown"),
            started=float(data.get("started") or time.time()),
            key_type=str(data.get("key_type") or ""),
            key_fp=str(data.get("key_fp") or ""),
            key_name=str(data.get("key_name") or ""),
        )


@dataclass
class SshWatcher:
    journal_unit: str
    hostname: str
    send: SendFn
    sessions: dict[str, SshSession] = field(default_factory=dict)
    stop_event: threading.Event = field(default_factory=threading.Event)
    proc: subprocess.Popen[str] | None = None
    keys: KeyCatalog = field(default_factory=KeyCatalog)
    _pending_by_user: dict[str, str] = field(default_factory=dict)
    _login_dedupe: dict[str, float] = field(default_factory=dict)
    _pending_key_by_pid: dict[str, tuple[str, str]] = field(default_factory=dict)

    def snapshot_sessions(self) -> dict[str, dict[str, Any]]:
        return {key: sess.to_dict() for key, sess in self.sessions.items()}

    def load_sessions(self, data: dict[str, Any] | None, now: float) -> None:
        if not data:
            return
        cutoff = now - 48 * 3600
        for key, raw in data.items():
            try:
                sess = SshSession.from_dict(raw)
            except Exception:
                continue
            if sess.started < cutoff:
                continue
            self.sessions[key] = sess

    def request_stop(self) -> None:
        self.stop_event.set()
        proc = self.proc
        if proc and proc.poll() is None:
            proc.terminate()

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self._follow_once()
            except Exception:
                log.exception("ssh journal follow crashed")
            if self.stop_event.is_set():
                break
            time.sleep(2)

    def handle_message(self, message: str, ts: float, pid: str = "") -> None:
        message = message.strip()
        if not message:
            return

        found = RE_FOUND_KEY.search(message)
        if found:
            if pid:
                self._pending_key_by_pid[pid] = (
                    found.group("keytype"),
                    found.group("fp"),
                )
            return

        accepted = RE_ACCEPTED.search(message)
        if accepted:
            key_type, key_fp, key_name = parse_keyinfo(accepted.group("keyinfo"))
            if pid and pid in self._pending_key_by_pid:
                pending_type, pending_fp = self._pending_key_by_pid.pop(pid)
                key_type = key_type or pending_type
                key_fp = key_fp or pending_fp
            if key_fp:
                looked_name, looked_type = self.keys.resolve(accepted.group("user"), key_fp)
                key_name = key_name or looked_name
                key_type = key_type or looked_type
            self._on_login(
                user=accepted.group("user"),
                ip=accepted.group("ip"),
                port=accepted.group("port"),
                method=accepted.group("method"),
                ts=ts,
                key_type=key_type,
                key_fp=key_fp,
                key_name=key_name,
            )
            return

        disconnect = RE_DISCONNECT.search(message)
        if disconnect:
            self._on_logout(
                user=disconnect.group("user"),
                ip=disconnect.group("ip"),
                port=disconnect.group("port"),
                ts=ts,
            )
            return

        opened = RE_SESSION_OPEN.search(message)
        if opened:
            user = opened.group("user")
            key = self._pending_by_user.pop(user, None)
            if key and key in self.sessions:
                return
            recent = self._login_dedupe.get(user, 0)
            if ts - recent < 8:
                return
            self._on_login(user=user, ip="unknown", port="?", method="session", ts=ts)
            return

        closed = RE_SESSION_CLOSE.search(message)
        if closed:
            user = closed.group("user")
            matches = [k for k, s in self.sessions.items() if s.user == user]
            if len(matches) == 1:
                sess = self.sessions[matches[0]]
                self._on_logout(user=sess.user, ip=sess.ip, port=sess.port, ts=ts)
            return

    def _on_login(
        self,
        user: str,
        ip: str,
        port: str,
        method: str,
        ts: float,
        key_type: str = "",
        key_fp: str = "",
        key_name: str = "",
    ) -> None:
        key = session_key(user, ip, port)
        self.sessions[key] = SshSession(
            user=user,
            ip=ip,
            port=port,
            method=method,
            started=ts,
            key_type=key_type,
            key_fp=key_fp,
            key_name=key_name,
        )
        self._pending_by_user[user] = key
        self._login_dedupe[user] = ts
        root = user == "root"
        title = "SSH login (root)" if root else "SSH login"
        color = COLOR_ROOT if root else COLOR_SSH_LOGIN
        body = (
            f"**User:** `{user}`\n"
            f"**IP:** `{ip}`\n"
            f"**Port:** `{port}`\n"
            f"**Method:** `{method}`\n"
            f"{format_key_fields(method, key_type, key_fp, key_name)}"
            f"**Host:** `{self.hostname}`\n"
            f"**Time:** {format_local(ts)}"
        )
        self.send(title, body, color)
        log.info(
            "ssh login user=%s ip=%s port=%s method=%s key=%s %s name=%s",
            user,
            ip,
            port,
            method,
            key_type or "-",
            key_fp or "-",
            key_name or "-",
        )

    def _on_logout(self, user: str, ip: str, port: str, ts: float) -> None:
        key = session_key(user, ip, port)
        sess = self.sessions.pop(key, None)
        if sess is None:
            # Match leftover session for this user+ip if port differs.
            for existing_key, existing in list(self.sessions.items()):
                if existing.user == user and existing.ip == ip:
                    sess = self.sessions.pop(existing_key)
                    break
        duration = format_duration(ts - sess.started) if sess else "unknown"
        method = sess.method if sess else "unknown"
        key_type = sess.key_type if sess else ""
        key_fp = sess.key_fp if sess else ""
        key_name = sess.key_name if sess else ""
        root = user == "root"
        title = "SSH logout (root)" if root else "SSH logout"
        color = COLOR_ROOT if root else COLOR_SSH_LOGOUT
        body = (
            f"**User:** `{user}`\n"
            f"**IP:** `{ip}`\n"
            f"**Port:** `{port}`\n"
            f"**Method:** `{method}`\n"
            f"{format_key_fields(method, key_type, key_fp, key_name)}"
            f"**Duration:** {duration}\n"
            f"**Host:** `{self.hostname}`\n"
            f"**Time:** {format_local(ts)}"
        )
        self.send(title, body, color)
        log.info("ssh logout user=%s ip=%s port=%s duration=%s", user, ip, port, duration)

    def _follow_once(self) -> None:
        cmd = [
            "journalctl",
            "-u",
            self.journal_unit,
            "-o",
            "json",
            "-n",
            "0",
            "-f",
            "--no-pager",
            "-q",
        ]
        log.info("following ssh journal: %s", " ".join(cmd))
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert self.proc.stdout is not None
        try:
            for line in self.proc.stdout:
                if self.stop_event.is_set():
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                message = entry.get("MESSAGE") or ""
                if isinstance(message, list):
                    message = "".join(chr(b) if isinstance(b, int) else str(b) for b in message)
                pid = str(entry.get("_PID") or "")
                self.handle_message(str(message), parse_journal_ts(entry), pid=pid)
        finally:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            err = ""
            if self.proc.stderr:
                try:
                    err = self.proc.stderr.read()[:500]
                except Exception:
                    pass
            if self.proc.returncode not in (0, None, -15, 15) and not self.stop_event.is_set():
                log.warning(
                    "journalctl exited %s: %s",
                    self.proc.returncode,
                    err.strip() or "(no stderr)",
                )
            self.proc = None
