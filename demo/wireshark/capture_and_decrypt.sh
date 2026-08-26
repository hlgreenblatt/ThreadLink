#!/usr/bin/env bash
# capture_and_decrypt.sh — the ThreadLink QUIC decryption demo, one command.
#
# Produces three artifacts in this directory:
#   handshake.pcap          the raw QUIC packets on the wire (encrypted)
#   threadlink-keys.log     the TLS 1.3 secrets aioquic wrote (SSLKEYLOGFILE)
#   decrypted.txt           tshark's view AFTER applying the keys — the payload
#
# The story: the pcap alone shows only QUIC's opaque, encrypted UDP. Feed the
# keylog to Wireshark/tshark and the ThreadHello frames (HELLO, ROUTE_TABLE)
# appear in the clear — proving the link is genuinely encrypted, and that we
# hold the keys because WE are the endpoint, not because we broke anything.
#
# NEEDS CAPTURE PRIVILEGE. Pick ONE, once:
#   sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v dumpcap || command -v tcpdump)"
#   ...or run this whole script under sudo.
set -euo pipefail
cd "$(dirname "$0")"
PORT=4455
export SSLKEYLOGFILE="$PWD/threadlink-keys.log"
PY=/home/maxquasar/build/ThreadRouter/.venv/bin/python
rm -f handshake.pcap threadlink-keys.log decrypted.txt

CAP=$(command -v dumpcap || command -v tcpdump)
echo "capturing on lo udp/$PORT with $CAP ..."
"$CAP" -i lo -f "udp port $PORT" -w handshake.pcap >/dev/null 2>&1 &
CAPPID=$!
sleep 1.5

"$PY" two_node_exchange.py
sleep 1
kill "$CAPPID" 2>/dev/null || true
wait "$CAPPID" 2>/dev/null || true

echo "=== keys written ==="; wc -l threadlink-keys.log
echo "=== packets captured ==="; tshark -r handshake.pcap 2>/dev/null | wc -l

if command -v tshark >/dev/null; then
  echo "=== DECRYPTED ThreadHello frames (tls.keylog applied) ==="
  tshark -r handshake.pcap -o "tls.keylog_file:$SSLKEYLOGFILE" \
         -O quic -Y quic 2>/dev/null | tee decrypted.txt | head -60
else
  echo "tshark not installed — open handshake.pcap in Wireshark and set"
  echo "  Preferences > Protocols > TLS > (Pre)-Master-Secret log filename = $SSLKEYLOGFILE"
fi
