#!/usr/bin/env bash
# install-threadchat.sh — stand up the ThreadChat node for THIS host as a
# systemd --user service. Run it once per machine (it detects which agent lives
# here from the hostname / IP). Idempotent: re-running re-installs cleanly.
#
#   .41  -> agent_10    local :22334
#   .248 -> agent_ellie local :22333
#   .29  -> agent_33    local :22333
#
# Usage:  ./install-threadchat.sh            (auto-detect this host)
#         ./install-threadchat.sh agent_33   (force a specific agent)
set -euo pipefail

TR="$HOME/build/ThreadChat"
UNIT_SRC="$TR/adapters/omegaclaw/deploy/threadchat@.service"
USER_UNIT_DIR="$HOME/.config/systemd/user"

# ── which agent lives on this box? ─────────────────────────────────────────
detect() {
  local ip
  ip=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^192\.168\.86\.' | head -1)
  case "$ip" in
    192.168.86.41)  echo "agent_10   http://127.0.0.1:22334 $HOME/agents/agent_10/.auth-secret" ;;
    192.168.86.248) echo "agent_ellie http://127.0.0.1:22333 $HOME/agents/agent_ellie/.auth-secret" ;;
    192.168.86.29)  echo "agent_33   http://127.0.0.1:22333 $HOME/agents/agent_33/.auth-secret" ;;
    *) echo "" ;;
  esac
}

if [ "${1:-}" != "" ]; then
  case "$1" in
    agent_10)    LINE="agent_10   http://127.0.0.1:22334 $HOME/agents/agent_10/.auth-secret" ;;
    agent_ellie) LINE="agent_ellie http://127.0.0.1:22333 $HOME/agents/agent_ellie/.auth-secret" ;;
    agent_33)    LINE="agent_33   http://127.0.0.1:22333 $HOME/agents/agent_33/.auth-secret" ;;
    *) echo "unknown agent: $1"; exit 2 ;;
  esac
else
  LINE=$(detect)
fi

[ -n "$LINE" ] || { echo "could not detect which agent lives here; pass one explicitly"; exit 2; }
read -r TC_ID TC_LOCAL TC_SECRET <<<"$LINE"
TC_PORT=4460

echo "installing ThreadChat node: id=$TC_ID local=$TC_LOCAL port=$TC_PORT"
[ -r "$TC_SECRET" ] || { echo "auth secret not readable at $TC_SECRET"; exit 3; }
[ -x "$TR/.venv/bin/python" ] || { echo "no venv python at $TR/.venv — build it first"; exit 3; }

# ── write the per-host env file the unit reads ─────────────────────────────
mkdir -p "$USER_UNIT_DIR"
cat > "$TR/adapters/omegaclaw/deploy/threadchat-$TC_ID.env" <<EOF
TC_ID=$TC_ID
TC_LOCAL=$TC_LOCAL
TC_SECRET=$TC_SECRET
TC_PORT=$TC_PORT
EOF

# ── install the templated unit ─────────────────────────────────────────────
cp "$UNIT_SRC" "$USER_UNIT_DIR/threadchat@.service"
systemctl --user daemon-reload
# keep it running after logout (safe to run repeatedly)
loginctl enable-linger "$USER" 2>/dev/null || true
systemctl --user enable --now "threadchat@$TC_ID.service"

sleep 3
echo "── status ──"
systemctl --user --no-pager --lines=6 status "threadchat@$TC_ID.service" || true
echo "── port ──"
ss -ulnp 2>/dev/null | grep ":$TC_PORT " && echo "LISTENING on udp/$TC_PORT" || echo "NOT LISTENING — check journalctl --user -u threadchat@$TC_ID"
