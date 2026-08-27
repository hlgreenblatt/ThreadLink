# ThreadChat capture + decrypt demo

Proof that a ThreadChat exchange is real, encrypted QUIC — and that the words
are recoverable only if you hold the session keys (because you are the endpoint).

The keylog capability lives in **ThreadLink**, not here — so this demo writes no
capture code of its own. A ThreadChat exchange decrypts exactly like any other
ThreadLink traffic.

## Run it

```bash
# 1. generate a capturable exchange with the TLS secrets written out
SSLKEYLOGFILE=$PWD/chat-keys.log ../.venv/bin/python two_agent_chat.py &

# 2. capture the packets (needs capture privilege — setcap on tcpdump/dumpcap)
sudo tcpdump -i lo -n 'udp portrange 4465-4470' -w chat.pcap

# 3a. WITHOUT keys — what a wiretapper sees:
tshark -r chat.pcap -x | grep -ci "qwen\|primary\|CHAT"      # => 0

# 3b. WITH keys — the conversation in the clear:
tshark -r chat.pcap -o tls.keylog_file:chat-keys.log \
       -Y quic.stream_data -T fields -e quic.stream_data \
  | tr -d ':' | xxd -r -p | strings | grep '{'
```

## What it shows (see decrypted-sample.txt)

    TL01 {"from":"agent_10","to":"agent_33","text":"What is your primary
          reasoning model right now?","msg_id":"xi-q1","proto":1}
    TL01 {"from":"agent_33","to":"agent_10","text":"qwen3.8-27b — my primary,
          on the GB10 Ascent.","msg_id":"yi-reply","in_reply_to":"xi-q1"}

`TL01` is the ThreadLink wire magic — the SAME bytes a ThreadHello capture shows,
because it is the same transport. `in_reply_to` ties the answer to the question:
the async-letter mechanism, proven from packets. `ALPN: threadlink/1` is
negotiated in the clear in the handshake.

Note: tshark refuses some sandboxed temp paths — copy the pcap to a plain
location (e.g. /tmp) before reading. tcpdump-written pcaps need `chmod 644` first.
