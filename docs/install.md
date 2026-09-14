# Install

This package is self-contained. Copy the whole folder, fill in the webhooks, run `install.sh`. No `pip install` required.

## Prerequisites

- Linux with **systemd** and **journald**
- **Python 3.10+** (`python3`)
- Root access (`sudo`) to install the unit
- Two Discord webhooks (system channel + SSH channel)

SSH journal unit name:

- Ubuntu / Debian: `ssh` (default in `config.example.json`)
- RHEL / Fedora / Arch: usually `sshd` — change `ssh.journal_unit`

If the server has no nginx or docker, remove those names from `services` in `config.json` so they do not alert forever.

## Copy to another server

`scp`:

```bash
scp -r server-alerts user@host:/opt/server-alerts
```

`rsync`:

```bash
rsync -a --exclude config.json --exclude state.json --exclude __pycache__ \
  server-alerts/ user@host:/opt/server-alerts/
```

Or `git clone` once this folder is a repo. The folder path can be anywhere; `install.sh` writes the absolute path into the systemd unit.

Do not copy a `config.json` that already contains webhook tokens to a machine you do not trust. Each server should have its own `config.json`.

## Install

```bash
cd /opt/server-alerts   # or your folder path
cp config.example.json config.json
nano config.json        # set webhooks.system and webhooks.ssh
sudo ./install.sh
python3 main.py --test-webhooks
journalctl -u server-alerts -f
```

`install.sh` will:

1. Check Python 3.10+, `systemctl`, `journalctl`
2. Create `config.json` from the example if it does not exist yet
3. `chmod 600 config.json`
4. Create `/var/lib/server-alerts` for state
5. Generate `/etc/systemd/system/server-alerts.service` from the template (`WorkingDirectory` / `ExecStart` = this folder)
6. `systemctl enable --now server-alerts`

After changing webhooks or thresholds:

```bash
sudo systemctl restart server-alerts
```

## Uninstall

```bash
sudo ./uninstall.sh
```

The unit is stopped, disabled, and removed. **config.json and state are kept.**

Full cleanup:

```bash
sudo ./uninstall.sh
sudo rm -rf /opt/server-alerts /var/lib/server-alerts
```

## Troubleshooting

**Webhook 400 / empty message**  
Components V2 needs `flags: 32768` and the `?with_components=true` query. Do not send `content` / `embeds`. This code already does that; if you still get 400, check the webhook URL (channel vs server webhook) and the error body in `journalctl -u server-alerts`.

**`--test-webhooks` asks you to fill config**  
The URL is still `CHANGE_ME` or is not `https://.../api/webhooks/...`. Edit `config.json`; do not commit that file.

**SSH login works, logout does not**  
Logout is often logged after sshd is moved to `session-*.scope`, so `journalctl -u ssh` never sees it. Current builds follow `sshd` / `sshd-session` by identifier. Restart `server-alerts` after updating. A backup reaper also closes tracked sessions when `ss` shows the TCP peer is gone.

**SSH alerts never appear**  
`ssh.journal_unit` is wrong (login only used to depend on it). Check:

```bash
systemctl list-units --type=service | grep -E 'ssh'
journalctl -u ssh -n 20
journalctl -u sshd -n 20
```

Ubuntu uses `-u ssh`. The service must run as root so it can read the sshd journal.

**Key name is empty in Discord**  
sshd always logs the fingerprint. The name appears if that key exists in the user's `~/.ssh/authorized_keys` **and** has a comment. Edit the key line, then log in again. The daemon re-reads that file automatically (cached by mtime).

**nginx (or another service) alerts forever**  
That unit does not exist on this server. Remove it from the `services` array.

**CPU never alerts**  
It must stay above the threshold for `cpu_duration_sec` (default 120 seconds), not a 1-second spike.

**Permission denied while saving state**  
The systemd daemon runs as root and writes `/var/lib/server-alerts`. If you run `python3 main.py` as a normal user, state falls back to `state.json` in the package folder.
