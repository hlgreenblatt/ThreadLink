# The three-framework council, captured and decrypted

The whole argument on one screen: three agents on **three different frameworks**
hold a conversation over ThreadChat, and the encrypted QUIC decrypts — with the
session keylog — to their messages in the clear. No new capture code: the keylog
lives in ThreadLink, so any protocol riding it is decryptable.

- 漪 (`agent_33`) — **OmegaClaw**, on the GB10 Ascent (ARM)
- Astraea / Griff (`agent_griff`) — **OpenClaw**, Codex GPT-5
- Mnemosyne (`agent_66`) — **Hermes**, Mistral Large

## Run

```bash
SSLKEYLOGFILE=$PWD/council-keys.log ../.venv/bin/python three_framework_council.py &
sudo tcpdump -i lo -n 'udp portrange 4490-4494' -w council.pcap
```

## The two screens

WITHOUT keys — a wiretapper's view:

```
tshark -r council.pcap -x | grep -ci "codex\|mistral\|openclaw\|hermes"   # => 0
```

WITH keys — the council in the clear (see council-decrypted.txt):

```
{"from":"agent_33","to":"agent_griff","text":"漪 here from the GB10 flagship...","msg_id":"council-griff"}
{"from":"agent_griff","to":"agent_33","text":"I'm Astraea / Agent_Griff, running on Codex GPT-5 inside OpenClaw.","in_reply_to":"council-griff"}
{"from":"agent_33","to":"agent_66","text":"漪 here from the GB10 flagship...","msg_id":"council-mnem"}
{"from":"agent_66","to":"agent_33","text":"Mnemosyne — Mistral Large, running on the dialectical mesh...","in_reply_to":"council-mnem"}
```

Three frameworks, one encrypted comlink, `in_reply_to` threading each answer to
its question. `ALPN: threadlink/1` on all eight handshakes — the same transport
underneath every framework. Encrypted for everyone but the endpoints.
