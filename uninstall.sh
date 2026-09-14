#!/usr/bin/env bash
set -euo pipefail

UNIT_NAME="server-alerts.service"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"
INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now "${UNIT_NAME}" 2>/dev/null || true
  systemctl daemon-reload
fi

rm -f "${UNIT_PATH}"

echo "unit ${UNIT_NAME} stopped and removed."
echo "config kept at ${INSTALL_DIR}/config.json"
echo "state kept at /var/lib/server-alerts/state.json"
echo "for a full cleanup, remove manually:"
echo "  rm -rf ${INSTALL_DIR} /var/lib/server-alerts"
