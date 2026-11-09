#!/usr/bin/env bash
# install-council.sh — stand up the griff-proxy-backed ThreadChat nodes (the
# OpenClaw + Hermes council members) as systemd --user services on .41.
#
# All six proxy agents run on the workstation that hosts griff-proxy. Each gets
# its own node + port + systemd unit. Idempotent.
#
# Usage:  ./install-council.sh            (install all six)
#         ./install-council.sh agent_99   (just one)
set -euo pipefail

TR="$HOME/build/ThreadChat"
UNIT_SRC="$TR/adapters/deploy-proxy/threadchat-proxy@.service"
USER_UNIT_DIR="$HOME/.config/systemd/user"
PROXY="http://127.0.0.1:18895"
TOKEN="$HOME/ishtar/griff-proxy/secrets/callers/sparks.token"

# agent -> adapter, port. OpenClaw: griff/99/23. Hermes: 66/77/88.
declare -A ADAPTER=(
  [agent_griff]=openclaw [agent_99]=openclaw [agent_23]=openclaw
  [agent_66]=hermes      [agent_77]=hermes   [agent_88]=hermes )
declare -A PORT=(
  [agent_griff]=4461 [agent_66]=4462 [agent_99]=4463
  [agent_23]=4464    [agent_77]=4465 [agent_88]=4466 )

install_one() {
  local id="$1"
  local adapter="${ADAPTER[$id]:-}"; local port="${PORT[$id]:-}"
  [ -n "$adapter" ] || { echo "unknown agent: $id"; return 1; }
  echo "installing $id ($adapter) on port $port"
  mkdir -p "$USER_UNIT_DIR"
  cat > "$TR/adapters/deploy-proxy/threadchat-proxy-$id.env" <<EOF
TC_ID=$id
TC_ADAPTER=adapters/$adapter/node.py
TC_PROXY=$PROXY
TC_TOKEN=$TOKEN
TC_PEER=$id
TC_PORT=$port
EOF
  cp "$UNIT_SRC" "$USER_UNIT_DIR/threadchat-proxy@.service"
  systemctl --user daemon-reload
  loginctl enable-linger "$USER" 2>/dev/null || true
  systemctl --user enable --now "threadchat-proxy@$id.service"
}

[ -x "$TR/.venv/bin/python" ] || { echo "no venv at $TR/.venv"; exit 3; }
[ -r "$TOKEN" ] || { echo "no caller token at $TOKEN"; exit 3; }

if [ "${1:-}" != "" ]; then
  install_one "$1"
else
  for a in agent_griff agent_66 agent_99 agent_23 agent_77 agent_88; do install_one "$a"; done
fi

sleep 3
echo "── listening ports ──"
ss -ulnp 2>/dev/null | grep -oE ':(446[1-6]) ' | sort -u || echo "none yet"
echo "── units ──"
systemctl --user list-units 'threadchat-proxy@*' --no-pager --no-legend 2>/dev/null | awk '{print $1, $4}'
