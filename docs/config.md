# Config

File: `config.json` at the package root. Do not commit it (it is listed in `.gitignore`). Start from `config.example.json`.

`install.sh` sets `chmod 600` because this file contains webhook tokens.

Every key is optional except the webhooks if you want alerts to actually send. Missing keys use the defaults from `config.example.json`.

## `webhooks`

| Key | Channel |
|---|---|
| `system` | CPU, RAM, disk, load, reboot, services |
| `ssh` | SSH login and logout |

Example:

```json
"webhooks": {
  "system": "https://discord.com/api/webhooks/ID/TOKEN",
  "ssh": "https://discord.com/api/webhooks/ID/TOKEN"
}
```

They may be the same or different per server. Other servers do not have to use the same channels.

## `hostname`

`null` = `socket.gethostname()`. Set a string if you want a custom name on the webhook username (for example `prod-web-1`).

## `poll_interval_sec`

System check interval. Default `15`. Effective minimum is 5 seconds.

## `cooldown_sec`

After a recovery, the same alert will not fire again until this many seconds have passed (default `300`). Prevents flapping.

## `state_path`

Default `/var/lib/server-alerts/state.json`. Stores boot ID, alert status, and open SSH sessions. If the path is not writable (running without root), it falls back to `state.json` in the package folder.

## `thresholds`

| Key | Default | Meaning |
|---|---|---|
| `cpu_percent` | `85` | Busy CPU (user+system+irq, and so on) |
| `cpu_duration_sec` | `120` | Must stay above the threshold this long |
| `ram_percent` | `90` | `(MemTotal - MemAvailable) / MemTotal` |
| `disk_percent` | `85` | Used percent per mount in `disk_mounts` |
| `load_per_core` | `1.5` | 1-minute load ≥ this value × CPU count |

Internal hysteresis is about 5% (CPU/RAM/disk) and 0.2 per core (load) so recovery does not bounce on the threshold.

## `disk_mounts`

Array of paths. Default `["/"]`. Add e.g. `"/var/lib/docker"` to watch it separately. Alerts are per mount.

## `services`

systemd unit names checked with `systemctl is-active`. Default:

```json
["ssh", "docker", "nginx"]
```

On Ubuntu the SSH unit is named `ssh`, not `sshd`. On a server without nginx, remove `"nginx"`.

## `ssh.journal_unit`

Extra systemd unit OR'd into the journal follow. Default `"ssh"` (Ubuntu/Debian). Use `"sshd"` on RHEL/Fedora/Arch.

Logout lines are often *not* on this unit. After PAM opens a session, logind moves sshd into `session-*.scope`, so `journalctl -u ssh` still sees login but misses disconnect. The watcher follows `SYSLOG_IDENTIFIER` / `_COMM` `sshd`, `sshd-session`, and `sshd-auth` as well.

Optional `ssh.journal_identifiers` overrides that list.

Only **successful** logins and logouts are sent. Failed passwords / invalid users are ignored.

For publickey logins, the alert includes:

- key type + `SHA256:...` fingerprint from the sshd log
- **Key name** = comment in `~/.ssh/authorized_keys` (via `ssh-keygen -lf`), when present

Add a comment on the authorized_keys line so Discord shows a device name, for example `ssh-ed25519 AAAA... laptop-neta`.

## Discord messages

Components V2 (`flags` 32768): Container + Text Display, no legacy embeds.

- System warning: orange; very high: red; recovery: green; reboot: purple
- SSH login: green; logout: blue; **root**: red
