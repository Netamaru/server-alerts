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
    r"Disconnected from user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)"
)
RE_RECEIVED_DISCONNECT = re.compile(
    r"Received disconnect from (?P<ip>\S+) port (?P<port>\d+)"
)
RE_CONNECTION_CLOSED = re.compile(
    r"Connection closed by(?: user (?P<user>\S+))? (?P<ip>\S+) port (?P<port>\d+)"
)
RE_CLOSE_SESSION = re.compile(
    r"Close session: user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
RE_TIMEOUT = re.compile(
    r"Timeout, client not responding from user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)"
)
RE_SESSION_OPEN = re.compile(
    r"session opened for user (?P<user>[^\s(]+)(?:\(uid=\d+\))?"
)
RE_SESSION_CLOSE = re.compile(
    r"session closed for user (?P<user>[^\s(]+)"
)
DEFAULT_JOURNAL_IDENTIFIERS = ("sshd", "sshd-session", "sshd-auth")
LOGOUT_DEDUPE_SEC = 12
REAP_GRACE_SEC = 15
REAP_INTERVAL_SEC = 15

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


def is_preauth_message(message: str) -> bool:
    lower = message.lower()
    return (
        "[preauth]" in lower
        or " authenticating user " in lower
        or " invalid user " in lower
    )


def normalize_ip(ip: str) -> str:
    ip = ip.strip().strip("[]")
    if ip.startswith("::ffff:"):
        return ip[7:]
    return ip


def peer_aliases(ip: str, port: str) -> set[tuple[str, str]]:
    ip = normalize_ip(ip)
    aliases = {(ip, port)}
    if ip.startswith("::ffff:"):
        aliases.add((ip[7:], port))
    return aliases


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
    pid: str = ""

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
            "pid": self.pid,
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
            pid=str(data.get("pid") or ""),
        )


@dataclass
class SshWatcher:
    journal_unit: str
    hostname: str
    send: SendFn
    journal_identifiers: list[str] = field(
        default_factory=lambda: list(DEFAULT_JOURNAL_IDENTIFIERS)
    )
    sessions: dict[str, SshSession] = field(default_factory=dict)
    stop_event: threading.Event = field(default_factory=threading.Event)
    proc: subprocess.Popen[str] | None = None
    keys: KeyCatalog = field(default_factory=KeyCatalog)
    _pending_by_user: dict[str, str] = field(default_factory=dict)
    _login_dedupe: dict[str, float] = field(default_factory=dict)
    _logout_dedupe: dict[str, float] = field(default_factory=dict)
    _pending_key_by_pid: dict[str, tuple[str, str]] = field(default_factory=dict)
    _sessions_by_pid: dict[str, str] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def snapshot_sessions(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {key: sess.to_dict() for key, sess in self.sessions.items()}

    def load_sessions(self, data: dict[str, Any] | None, now: float) -> None:
        if not data:
            return
        cutoff = now - 48 * 3600
        with self._lock:
            for key, raw in data.items():
                try:
                    sess = SshSession.from_dict(raw)
                except Exception:
                    continue
                if sess.started < cutoff:
                    continue
                self.sessions[key] = sess
                if sess.pid:
                    self._sessions_by_pid[sess.pid] = key

    def request_stop(self) -> None:
        self.stop_event.set()
        proc = self.proc
        if proc and proc.poll() is None:
            proc.terminate()

    def run(self) -> None:
        reaper = threading.Thread(target=self._reap_loop, name="ssh-reap", daemon=True)
        reaper.start()
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
                pid=pid,
            )
            return

        if is_preauth_message(message):
            return

        disconnect = RE_DISCONNECT.search(message)
        if disconnect:
            self._on_logout(
                user=disconnect.group("user"),
                ip=disconnect.group("ip"),
                port=disconnect.group("port"),
                ts=ts,
                pid=pid,
            )
            return

        close_session = RE_CLOSE_SESSION.search(message)
        if close_session:
            self._on_logout(
                user=close_session.group("user"),
                ip=close_session.group("ip"),
                port=close_session.group("port"),
                ts=ts,
                pid=pid,
            )
            return

        timed_out = RE_TIMEOUT.search(message)
        if timed_out:
            self._on_logout(
                user=timed_out.group("user"),
                ip=timed_out.group("ip"),
                port=timed_out.group("port"),
                ts=ts,
                pid=pid,
            )
            return

        conn_closed = RE_CONNECTION_CLOSED.search(message)
        if conn_closed:
            self._on_logout(
                user=conn_closed.group("user") or "",
                ip=conn_closed.group("ip"),
                port=conn_closed.group("port"),
                ts=ts,
                pid=pid,
            )
            return

        received = RE_RECEIVED_DISCONNECT.search(message)
        if received:
            self._on_logout(
                user="",
                ip=received.group("ip"),
                port=received.group("port"),
                ts=ts,
                pid=pid,
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
            self._on_login(user=user, ip="unknown", port="?", method="session", ts=ts, pid=pid)
            return

        closed = RE_SESSION_CLOSE.search(message)
        if closed:
            self._on_logout(user=closed.group("user"), ip="", port="", ts=ts, pid=pid)
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
        pid: str = "",
    ) -> None:
        key = session_key(user, ip, port)
        sess = SshSession(
            user=user,
            ip=ip,
            port=port,
            method=method,
            started=ts,
            key_type=key_type,
            key_fp=key_fp,
            key_name=key_name,
            pid=pid,
        )
        with self._lock:
            self.sessions[key] = sess
            self._pending_by_user[user] = key
            self._login_dedupe[user] = ts
            if pid:
                self._sessions_by_pid[pid] = key
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

    def _on_logout(
        self,
        user: str,
        ip: str,
        port: str,
        ts: float,
        pid: str = "",
    ) -> None:
        sess = self._pop_session(user=user, ip=ip, port=port, pid=pid)
        if sess is None:
            # PAM "session closed" has no IP/port. Without a unique tracked
            # session, do not guess — a later disconnect line or the reaper
            # will close the right one.
            if not user or (not ip and not port):
                return
        if sess:
            user = sess.user
            if not ip or ip in {"?", "unknown"}:
                ip = sess.ip
            if not port or port == "?":
                port = sess.port
            method = sess.method
            key_type = sess.key_type
            key_fp = sess.key_fp
            key_name = sess.key_name
            duration = format_duration(ts - sess.started)
        else:
            method = "unknown"
            key_type = key_fp = key_name = ""
            duration = "unknown"
        dedupe_key = session_key(user, ip or "?", port or "?")
        last = self._logout_dedupe.get(dedupe_key, 0)
        if ts - last < LOGOUT_DEDUPE_SEC:
            return
        self._logout_dedupe[dedupe_key] = ts
        if len(self._logout_dedupe) > 256:
            cutoff = ts - 600
            self._logout_dedupe = {
                key: seen for key, seen in self._logout_dedupe.items() if seen >= cutoff
            }
        root = user == "root"
        title = "SSH logout (root)" if root else "SSH logout"
        color = COLOR_ROOT if root else COLOR_SSH_LOGOUT
        body = (
            f"**User:** `{user}`\n"
            f"**IP:** `{ip or "unknown"}`\n"
            f"**Port:** `{port or "?"}`\n"
            f"**Method:** `{method}`\n"
            f"{format_key_fields(method, key_type, key_fp, key_name)}"
            f"**Duration:** {duration}\n"
            f"**Host:** `{self.hostname}`\n"
            f"**Time:** {format_local(ts)}"
        )
        self.send(title, body, color)
        log.info("ssh logout user=%s ip=%s port=%s duration=%s", user, ip, port, duration)

    def _pop_session(
        self,
        user: str = "",
        ip: str = "",
        port: str = "",
        pid: str = "",
    ) -> SshSession | None:
        ip = normalize_ip(ip) if ip else ip
        specific_ip = bool(ip and ip not in {"?", "unknown"})
        specific_port = bool(port and port != "?")
        with self._lock:
            if user and specific_ip and specific_port:
                key = session_key(user, ip, port)
                sess = self.sessions.pop(key, None)
                if sess:
                    self._forget_pid(key)
                    return sess
            if specific_ip and specific_port:
                for key, sess in list(self.sessions.items()):
                    if normalize_ip(sess.ip) == ip and sess.port == port:
                        if not user or sess.user == user:
                            self.sessions.pop(key)
                            self._forget_pid(key)
                            return sess
            if pid:
                key = self._sessions_by_pid.get(pid)
                if key and key in self.sessions:
                    sess = self.sessions[key]
                    port_ok = not specific_port or sess.port == port
                    ip_ok = not specific_ip or normalize_ip(sess.ip) == ip
                    user_ok = not user or sess.user == user
                    if port_ok and ip_ok and user_ok:
                        self.sessions.pop(key)
                        self._forget_pid(key)
                        return sess
            # A concrete port that matched nothing must not steal another session.
            if specific_port:
                return None
            if user and specific_ip:
                matches = [
                    key
                    for key, sess in self.sessions.items()
                    if sess.user == user and normalize_ip(sess.ip) == ip
                ]
                if len(matches) == 1:
                    key = matches[0]
                    sess = self.sessions.pop(key)
                    self._forget_pid(key)
                    return sess
                return None
            if user:
                matches = [key for key, sess in self.sessions.items() if sess.user == user]
                if len(matches) == 1:
                    key = matches[0]
                    sess = self.sessions.pop(key)
                    self._forget_pid(key)
                    return sess
        return None

    def _forget_pid(self, key: str) -> None:
        dead = [pid for pid, mapped in self._sessions_by_pid.items() if mapped == key]
        for pid in dead:
            self._sessions_by_pid.pop(pid, None)

    def _journal_cmd(self) -> list[str]:
        # Follow syslog identifiers, not only -u ssh/sshd. After PAM opens a
        # session, systemd-logind moves sshd into session-*.scope so logout
        # lines never appear in journalctl -u ssh.
        cmd = ["journalctl", "-o", "json", "-n", "0", "-f", "--no-pager", "-q"]
        idents = [ident for ident in self.journal_identifiers if ident]
        units = [self.journal_unit] if self.journal_unit else []
        if not idents and not units:
            units = ["ssh"]
        groups: list[list[str]] = []
        if idents:
            ident_args: list[str] = []
            for ident in idents:
                ident_args.extend(["-t", ident])
            groups.append(ident_args)
            comm_args: list[str] = []
            for ident in idents:
                comm_args.extend(["_COMM=" + ident])
            groups.append(comm_args)
        for unit in units:
            groups.append(["-u", unit])
        for index, group in enumerate(groups):
            if index:
                cmd.append("+")
            cmd.extend(group)
        return cmd

    def _reap_loop(self) -> None:
        while not self.stop_event.wait(REAP_INTERVAL_SEC):
            try:
                self._reap_dead_sessions()
            except Exception:
                log.exception("ssh session reap failed")

    def _reap_dead_sessions(self) -> None:
        peers = self._list_ssh_peers()
        if peers is None:
            return
        now = time.time()
        dead: list[SshSession] = []
        with self._lock:
            for sess in list(self.sessions.values()):
                if sess.ip in {"", "?", "unknown"} or sess.port in {"", "?"}:
                    continue
                if now - sess.started < REAP_GRACE_SEC:
                    continue
                if peer_aliases(sess.ip, sess.port).isdisjoint(peers):
                    dead.append(sess)
        for sess in dead:
            self._on_logout(sess.user, sess.ip, sess.port, now, pid=sess.pid)

    def _list_ssh_peers(self) -> set[tuple[str, str]] | None:
        try:
            result = subprocess.run(
                ["ss", "-tnH"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            log.debug("ss not available for ssh reap: %s", exc)
            return None
        if result.returncode != 0:
            return None
        peers: set[tuple[str, str]] = set()
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            peer = parts[-1]
            if peer.count(":") < 1:
                continue
            ip, _, port = peer.rpartition(":")
            ip = normalize_ip(ip)
            if ip and port.isdigit():
                peers.update(peer_aliases(ip, port))
        return peers

    def _follow_once(self) -> None:
        cmd = self._journal_cmd()
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
