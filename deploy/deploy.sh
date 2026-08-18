#!/usr/bin/env bash
#
# deploy.sh — deploy the IPM watcher as a systemd service on Linux.
#
# Installs the runtime files into /opt/ipm-watch, creates a venv (no
# third-party deps required), and enables the ipm-watch service.
#
# Usage: sudo ./deploy.sh [watch_dir] [out_dir]
#   defaults: watch_dir=/opt/vaultspay/inbox  out_dir=/opt/vaultspay/output

set -euo pipefail

WATCH_DIR="${1:-/opt/vaultspay/inbox}"
OUT_DIR="${2:-/opt/vaultspay/output}"
APP_DIR=/opt/ipm-watch
UNIT=/etc/systemd/system/ipm-watch.service
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
    echo "error: run with sudo" >&2
    exit 1
fi

echo "==> Installing runtime files to $APP_DIR"
install -d "$APP_DIR"
install -m 755 "$SCRIPT_DIR/../watch_ipm.py" "$APP_DIR/"
install -m 755 "$SCRIPT_DIR/../test.py" "$APP_DIR/"
install -d "$APP_DIR/parser"
install -m 644 "$SCRIPT_DIR"/../parser/*.py "$APP_DIR/parser/"
install -d "$APP_DIR/metadata"
install -m 644 "$SCRIPT_DIR"/../metadata/*.json "$APP_DIR/metadata/"
install -m 644 "$SCRIPT_DIR"/../requirements.txt "$APP_DIR/"

echo "==> Creating input/output directories"
install -d -o "$(id -u root)" -g "$(id -g root)" "$WATCH_DIR" "$OUT_DIR"

echo "==> Creating Python virtualenv"
if [[ ! -x "$APP_DIR/venv/bin/python" ]]; then
    python3 -m venv "$APP_DIR/venv"
fi
if [[ -f "$SCRIPT_DIR/../requirements.txt" ]]; then
    "$APP_DIR/venv/bin/pip" install -r "$SCRIPT_DIR/../requirements.txt"
fi

echo "==> Writing systemd unit"
cat > "$UNIT" <<EOF
[Unit]
Description=Mastercard IPM file watcher and validator
After=network.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/watch_ipm.py \\
    --watch $WATCH_DIR \\
    --out $OUT_DIR \\
    --prefix TESTR \\
    --interval 5
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

echo "==> Enabling service"
systemctl daemon-reload
systemctl enable ipm-watch
systemctl restart ipm-watch

echo "==> Done"
echo "    status:    systemctl status ipm-watch"
echo "    logs:      journalctl -u ipm-watch -f"
echo "    watching:  $WATCH_DIR  ->  $OUT_DIR"
