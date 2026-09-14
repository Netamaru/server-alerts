# Server Discord Alerts

Portable package that sends server alerts to Discord (Components V2):

- **System alerts** — CPU, RAM, disk, load, reboot, service down (`ssh`, `docker`, `nginx`, or your own list)
- **SSH alerts** — successful login and logout for every user, including root

No pip dependencies. Requires Python 3.10+, systemd, and `journalctl`.

## Quick start

1. Copy this folder to the target server (any path).
2. Create config and fill in two webhook URLs:

```bash
cp config.example.json config.json
nano config.json
```

3. Install the service:

```bash
sudo ./install.sh
```

4. Test both channels:

```bash
python3 main.py --test-webhooks
```

Full documentation:

- [docs/install.md](docs/install.md) — copy to another server, prerequisites, uninstall, troubleshooting
- [docs/config.md](docs/config.md) — webhooks, thresholds, services, SSH unit name

## What gets alerted

System (edge-triggered + 5 minute cooldown, with a recovery message):

- CPU ≥ 85% for 2 minutes
- RAM ≥ 90%
- Disk ≥ 85% (default mount `/`)
- 1-minute load ≥ 1.5 per core (scales with CPU count)
- Reboot (boot ID changed)
- A service listed in `config.json` is not `active`

SSH:

- Successful login (publickey / password / keyboard-interactive), including fingerprint and key name from `authorized_keys`
- Logout (session duration when it can be computed)

Hostname, CPU count, and the service list are **not hardcoded** — each server reads them from the machine and its own `config.json`.

## Useful commands

```bash
sudo systemctl status server-alerts
journalctl -u server-alerts -f
python3 main.py --once          # one system poll, no Discord
sudo ./uninstall.sh             # remove the unit; config/state are kept
```
