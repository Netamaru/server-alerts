#!/usr/bin/env bash
set -euo pipefail

UNIT_NAME="server-alerts.service"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="${INSTALL_DIR}/systemd/server-alerts.service.in"
CONFIG_EXAMPLE="${INSTALL_DIR}/config.example.json"
CONFIG_PATH="${INSTALL_DIR}/config.json"
STATE_DIR="/var/lib/server-alerts"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found" >&2
  exit 1
fi

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "Python 3.10+ is required (found $(python3 --version 2>&1))" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found — this package requires systemd" >&2
  exit 1
fi

if ! command -v journalctl >/dev/null 2>&1; then
  echo "journalctl not found — SSH alerts require journald" >&2
  exit 1
fi

if [[ ! -f "${TEMPLATE}" ]]; then
  echo "unit template not found: ${TEMPLATE}" >&2
  exit 1
fi

PYTHON="$(command -v python3)"

if [[ ! -f "${CONFIG_PATH}" ]]; then
  cp "${CONFIG_EXAMPLE}" "${CONFIG_PATH}"
  echo "created config.json from config.example.json — fill in the webhook URLs first"
fi
chmod 600 "${CONFIG_PATH}"

mkdir -p "${STATE_DIR}"
chmod 700 "${STATE_DIR}"

tmp="$(mktemp)"
sed \
  -e "s|__INSTALL_DIR__|${INSTALL_DIR}|g" \
  -e "s|__PYTHON__|${PYTHON}|g" \
  "${TEMPLATE}" > "${tmp}"
install -m 644 "${tmp}" "${UNIT_PATH}"
rm -f "${tmp}"

systemctl daemon-reload
systemctl enable --now "${UNIT_NAME}"

echo
echo "installed:"
echo "  folder : ${INSTALL_DIR}"
echo "  unit   : ${UNIT_PATH}"
echo "  config : ${CONFIG_PATH}"
echo "  state  : ${STATE_DIR}/state.json"
echo
if grep -q "CHANGE_ME" "${CONFIG_PATH}"; then
  echo "WARNING: webhook URLs are still placeholders."
  echo "  1. edit ${CONFIG_PATH}"
  echo "  2. python3 ${INSTALL_DIR}/main.py --test-webhooks"
  echo "  3. sudo systemctl restart ${UNIT_NAME}"
else
  echo "logs: journalctl -u ${UNIT_NAME} -f"
  echo "test webhooks: python3 ${INSTALL_DIR}/main.py --test-webhooks"
fi
