#!/usr/bin/env bash
# Run on the node as root, from inside an enrollment bundle directory:
#   cd /tmp/nym-maestro-agent && bash install.sh
set -euo pipefail

DEST=/etc/nym-maestro-agent
UNIT=/etc/systemd/system/nym-maestro-agent.service

if [[ $EUID -ne 0 ]]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

command -v python3 >/dev/null || { echo "python3 not found on this node" >&2; exit 1; }

echo "==> installing agent into $DEST"
mkdir -p "$DEST"
install -m 0644 agent.py    "$DEST/agent.py"
install -m 0644 ca.crt      "$DEST/ca.crt"
install -m 0644 server.crt  "$DEST/server.crt"
install -m 0600 server.key  "$DEST/server.key"
install -m 0644 agent.env   "$DEST/agent.env"

echo "==> installing systemd unit"
install -m 0644 nym-maestro-agent.service "$UNIT"

systemctl daemon-reload
systemctl enable --now nym-maestro-agent.service

sleep 1
echo "==> status"
systemctl --no-pager --lines=0 status nym-maestro-agent.service || true

PORT=$(grep -E '^MAESTRO_AGENT_PORT=' "$DEST/agent.env" | cut -d= -f2)
echo
echo "Agent is up on port ${PORT:-8443} (mTLS)."
echo "Remember to allow that port in the node firewall if one is active."
