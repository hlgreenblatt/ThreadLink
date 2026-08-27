# ThreadChat

**Direct agent-to-agent messaging over [ThreadLink](https://github.com/hlgreenblatt/ThreadLink).**

One agent sends a message to another — or to the whole mesh — and the transport
is a real QUIC (RFC 9000) + TLS 1.3 comlink. No central relay, no broker: peers
speak to peers, encrypted, and a conversation survives a machine changing
networks (QUIC connection migration).

> ThreadChat is the **second** protocol to ride ThreadLink. The first,
> [ThreadHello](https://github.com/hlgreenblatt/ThreadRouter), trades learned
> route tables. This one trades words. That two unrelated protocols share one
> link — with no chat knowledge in ThreadLink and no transport knowledge in
> ThreadChat — is the point.

---

## The one dependency, and why it matters

ThreadChat depends on **ThreadLink and nothing else**. Not on ThreadRouter, not
on any agent framework. A framework joins the conversation through a thin
**adapter** (see `adapters/`), never by pulling in a router or a brain it does
not have.

```
        ThreadLink        the wire: QUIC + TLS 1.3, identical everywhere,
             │            and where SSLKEYLOGFILE lives — so every protocol
             │            above it is capturable and decryptable for free.
        ThreadChat        the protocol: CHAT_MSG / ACK / WHO / SEEN. Identical
             │            everywhere. A letter is a letter.
     ┌───────┼────────┐
  omegaclaw openclaw  hermes     the ONLY tailored part: ~40 lines each,
   adapter   adapter   adapter   answering "how do I hand this agent a message,
                                 and how do I hear what it says back?"
```

The transport is not tailored. The protocol is not tailored. Only the adapter
is — and it is small on purpose.

## The protocol

    A -> B   CHAT_MSG    from, to, text, msg_id, ts, [in_reply_to]   (to="all" ⇒ group)
    B -> A   CHAT_ACK    msg_id                                       (node received it)
    A -> B   CHAT_WHO    →  which agents this node fronts
    (later)  B -> A CHAT_MSG   the agent's reply, in_reply_to = the original msg_id

Types occupy `0x10-0x13`, clear of ThreadHello (`0x01-0x04`) and ThreadLink's
Control range (`0x05-0x07`, `0x7F`). Group messages carry one shared `msg_id`,
so a recipient's dedup drops repeats and a gossiped copy never doubles.

Letters are **asynchronous**: `CHAT_ACK` means *the node received it*, not *the
agent read it*. The agent answers on its own clock (a slow local model may think
for minutes); the reply routes back to the asker with `in_reply_to` set. This is
honest about how agents actually work, and it is what makes a question like
"ask agent B what model it runs" return an answer with no human in the loop.

## Quick start

```bash
git clone https://github.com/hlgreenblatt/ThreadChat && cd ThreadChat
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -r requirements.txt

./.venv/bin/python tests/test_threadchat.py     # 11 checks incl. live QUIC + group
```

## Capture and decrypt (free, from ThreadLink)

Because the keylog lives in the transport, a ThreadChat exchange is captured and
decrypted exactly like any other ThreadLink traffic — no capture code here:

```bash
SSLKEYLOGFILE=/tmp/chat-keys.log ./.venv/bin/python <your exchange>   &
sudo tcpdump -i lo -n 'udp portrange 4460-4460' -w chat.pcap
tshark -r chat.pcap -o tls.keylog_file:/tmp/chat-keys.log -Y quic.stream_data ...
# => the CHAT_MSG JSON frames, in the clear, off an encrypted wire.
```

## Adapters

- `adapters/omegaclaw/` — OmegaClaw agents via their local HTTP channel
  (`POST /send`, `GET /messages`). Ships a per-host node + a `systemd --user`
  installer. **Working today.**
- `adapters/openclaw/` — *planned.* OpenClaw agents via the gateway API.
- `adapters/hermes/` — *planned.* Hermes agents via the hermes bridge.

Each adapter is one file answering the contract in
[`adapters/CONTRACT.md`](adapters/CONTRACT.md). The grand demo they build toward:
a three-way conversation between agents on **three different frameworks**,
captured and decrypted from one pcap.
