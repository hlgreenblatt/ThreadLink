#!/usr/bin/env bash
# capture_route_events_lan.sh — the ThreadHello ROUTE-EVENTS demo over the REAL LAN.
#
# Ellie (this workstation, .41) gains a free model, announces it to a sister
# node on the GB10 (.29), shares a route delta, then withdraws the path and
# retracts the model. The whole add -> share -> withdraw -> remove sequence is
# captured on wlo1 and decrypted with the TLS keys Ellie's own endpoint wrote.
#
# Real 192.168.86.x addresses on the wire — not loopback.
#
# Artifacts (this dir):
#   route_events_lan.pcapng     raw QUIC on wlo1 (encrypted)
#   route_events_keys.log       Ellie's TLS 1.3 secrets (SSLKEYLOGFILE)
#   route_events_decrypted.txt  tshark's view after applying the keys
#   route_events_lan.dsb.pcapng self-decrypting (keys embedded as a DSB)
set -euo pipefail
cd "$(dirname "$0")"

PEER_IP=192.168.86.29
SISTER_HOST=192.168.86.29
PORT=4433
IFACE=wlo1
PY=/home/maxquasar/build/ThreadRouter/.venv/bin/python
REMOTE_PY=/home/maxquasar/build/ThreadRouter/.venv/bin/python

export SSLKEYLOGFILE="$PWD/route_events_keys.log"
rm -f route_events_lan.pcapng route_events_keys.log route_events_decrypted.txt route_events_lan.dsb.pcapng

# make sure nothing stale is bound on the peer (truncated procname hides from pgrep;
# kill by the port it holds)
ssh "$SISTER_HOST" "pid=\$(ss -ulnp 2>/dev/null | grep -oP ':$PORT\b.*pid=\K[0-9]+' | head -1); [ -n \"\$pid\" ] && kill \$pid 2>/dev/null; true"

# 1. sister node on .29 (background, self-exits after MODEL_UPDATE removed)
echo "[.41] starting sister listener on $SISTER_HOST:$PORT ..."
ssh "$SISTER_HOST" 'mkdir -p ~/build/ThreadLink/demo/wireshark/certs'
scp -q route_events_listener.py "$SISTER_HOST:/home/maxquasar/build/ThreadLink/demo/wireshark/"
ssh "$SISTER_HOST" "cd ~/build/ThreadLink/demo/wireshark && $REMOTE_PY route_events_listener.py 0.0.0.0 $PORT" \
    > sister_out.log 2>&1 &
SSHPID=$!

# wait until the sister is ACTUALLY bound before capturing (poll, ARM can be slow)
echo "[.41] waiting for sister to bind $PORT ..."
for i in $(seq 1 20); do
  if ssh "$SISTER_HOST" "ss -ulnp 2>/dev/null | grep -q ':$PORT\b'"; then echo "  bound."; break; fi
  sleep 0.5
done

# 2. capture on the LAN interface — DURATION-bounded so dumpcap flushes cleanly on
#    its own (a SIGTERM'd dumpcap can drop its final unflushed buffer on a tiny
#    capture, which is exactly how this demo silently produced an empty pcap).
echo "[.41] capturing on $IFACE udp/$PORT for ${CAP_SECS:=15}s ..."
dumpcap -i "$IFACE" -f "udp port $PORT" -a "duration:$CAP_SECS" \
        -w route_events_lan.pcapng >dumpcap.log 2>&1 &
CAPPID=$!
for i in $(seq 1 20); do
  grep -q "File:" dumpcap.log 2>/dev/null && { echo "  capture live."; break; }
  sleep 0.3
done
sleep 1.0   # margin

# 3. Ellie announces (keylog written here, she is the TLS client)
echo "[.41] running Ellie the announcer ..."
"$PY" route_events_announcer.py "$PEER_IP" "$PORT"

# let the duration-bounded capture close itself, then the sister exits
wait "$CAPPID" 2>/dev/null || true
wait "$SSHPID" 2>/dev/null || true

chmod 644 route_events_lan.pcapng route_events_keys.log 2>/dev/null || true

echo; echo "── sister node saw (over the LAN) ──"; cat sister_out.log
echo; echo "── keys written ──"; wc -l route_events_keys.log

# NOTE: a sandboxed tshark cannot read files under $HOME or the sandbox tree
# ("You don't have permission to read the file") even when the perms are 644 —
# it is the process that is confined, not the path. Decode from a plain /tmp copy.
WORK=$(mktemp -d /tmp/re.XXXXXX)
cp route_events_lan.pcapng "$WORK/cap.pcapng"
cp route_events_keys.log   "$WORK/keys.log"
cp ../../wireshark/threadlink.lua "$WORK/threadlink.lua"
chmod 644 "$WORK"/*

echo "── packets captured ──"; tshark -r "$WORK/cap.pcapng" 2>/dev/null | wc -l

echo; echo "=== DECRYPTED ThreadHello route events (dissector loaded) ==="
tshark -r "$WORK/cap.pcapng" -o "tls.keylog_file:$WORK/keys.log" \
       -X lua_script:"$WORK/threadlink.lua" \
       -Y "threadhello" \
       -T fields -e ip.src -e ip.dst -e threadhello.msg \
       -e threadhello.action -e threadhello.model -e threadhello.model_class \
       -E header=y -E separator="  " 2>/dev/null | tee route_events_decrypted.txt

# 4. self-decrypting single file (keys embedded as a Decryption Secrets Block).
#    editcap runs unsandboxed here; build in /tmp then copy back.
if command -v editcap >/dev/null; then
  editcap --inject-secrets "tls,$WORK/keys.log" \
          "$WORK/cap.pcapng" "$WORK/cap.dsb.pcapng" 2>/dev/null \
    && cp "$WORK/cap.dsb.pcapng" route_events_lan.dsb.pcapng \
    && chmod 644 route_events_lan.dsb.pcapng \
    && echo && echo "self-decrypting: route_events_lan.dsb.pcapng (open in Wireshark, no keylog needed)"
fi
rm -rf "$WORK"
