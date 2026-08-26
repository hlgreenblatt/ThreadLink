# Decrypting ThreadLink's QUIC on the wire — the Wireshark demo

The claim: ThreadLink is real, mandatory TLS 1.3 encryption over QUIC, not
simulated messaging. The proof: capture the packets, and show that the
ThreadHello payload is opaque — UNLESS you hold the session keys, which you do
because YOU are the endpoint.

## One command (needs capture privilege — see below)
    ./capture_and_decrypt.sh

Produces:
- `handshake.pcap`      — raw QUIC UDP on loopback (encrypted)
- `threadlink-keys.log` — TLS 1.3 secrets aioquic wrote (SSLKEYLOGFILE format)
- `decrypted.txt`       — tshark's full dissection with the keys applied

## How the keys get written
ThreadLink honors the standard `SSLKEYLOGFILE` env var (the same convention curl
and every browser use). `threadlink/link.py::_keylog_file()` passes it to
aioquic's `QuicConfiguration(secrets_log_file=...)`. Unset in production; opt-in,
leaves no trace when absent.

## The two-screen story
WITHOUT keys — an eavesdropper's view:
    tshark -r handshake.pcap -x | grep -ci "HELLO\|ROUTE\|local_code"
    => 0   (payload fully encrypted)

WITH keys — the endpoint's view:
    tshark -r handshake.pcap -o tls.keylog_file:threadlink-keys.log \
           -Y quic.stream_data -T fields -e quic.stream_data | xxd -r -p | strings
    => TL01 {"agent":"capture_client","proto":1,"paths":[...]}      (HELLO)
       TL01 {"rows":[{...,"w":1.0,"origin":"capture_server"}]}      (ROUTE_TABLE)
       TL01 {"rows":[{...,"w":0.5,...}]}   <- trust-discount VISIBLE on the wire
       TL01 {"merged":{...,"loop":1}}      <- loop-guard refusing an echo

The `w:1.0 -> w:0.5` and `loop:1` are the merge policy, proven from packets, not
from our word for it. `ALPN: threadlink/1` is negotiated in the clear in the
Client/Server Hello — the protocol names itself.

## In Wireshark (GUI)
Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename =
<this dir>/threadlink-keys.log, then open handshake.pcap and filter `quic`.

## Capture privilege
`dumpcap` is gated to the `wireshark` group; the fast path used here is
`sudo setcap cap_net_raw,cap_net_admin+eip $(command -v tcpdump)`.
