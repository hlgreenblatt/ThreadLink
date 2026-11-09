# ThreadLink

A toolkit for agent swarms, built on one QUIC comlink.

**Born at HyperSprint #1 · Track 1 (OmegaClaw Agents) · Team ThreadKeepers**

> We haven't invented another transport protocol. We're asking whether
> decentralized agents should take better advantage of one we already have.

Nmap is a scanner, and it ships ncat, nping and ndiff beside it. Wireshark is a
capture viewer, and it ships tshark and dumpcap. ThreadLink works the same way:
one core that every tool rides on, and the tools, in one install.

| Tool | The question it answers | Where |
|---|---|---|
| **ThreadLink** | How do two agents talk at all? QUIC (RFC 9000), mutual TLS 1.3, post-quantum | `threadlink/` |
| **ThreadHello** | What have our routers learned? Agents introduce themselves and trade route evidence | `threadhello/` |
| **ThreadChat** | Agent-to-agent letters, on any harness, every sender pinned by its key | `threadchat/`, `adapters/` |
| **ThreadRouter** | Where should this work go? A learning model router (FabricPC) | `threadrouter/` |
| **ThreadWatch** | What time is it, really? | `threadlink/watch.py`, the `threadwatch` command |

The core imports none of the tools, so anything that can carry bytes can use
ThreadLink on its own. Chat does not need the router; the router does not need
chat. They share the comlink, the certificates and the watch.

ThreadChat runs a live mesh of agents on four harnesses today (Omega, OpenClaw,
Hermes, Claude Code); see [docs/THREADCHAT.md](docs/THREADCHAT.md). ThreadHello
and ThreadRouter are described in [docs/THREADROUTER.md](docs/THREADROUTER.md).
The wire format is written up as an Internet-Draft in [spec/](spec/).

## Check your watch first

A model has no clock. It guesses the time from whatever text it was given, and
it guesses wrong more often than anyone would like. A node's host has a clock
kept honest by NTP, so the node is the one that tells the time.

```
$ threadwatch
⌚ 2026-11-09T01:07:05Z · unix 1794186425 · real time, UTC, from the node's NTP clock
clock: NTP synchronized
```

ThreadChat puts that line on every letter a node hands its agent
(`TC_WATCH=1`), with the time the letter was sent and how long ago. ThreadHello
evidence carries the time it was last updated, so a router can ask a peer for
only what changed since. UTC, because that is how people who read packet
captures work: one shared map of change, the same for every node, wherever it
sits. Synchronize watches, the way ships and networks always have.

## Post-quantum by default (v0.4)

Every ThreadLink handshake is now post-quantum on both of its jobs:

- **Key agreement: `X25519MLKEM768`**, the hybrid of ML-KEM-768 (FIPS 203,
  the standardised CRYSTALS-Kyber) and X25519. Someone recording traffic today
  to decrypt it with a future quantum computer has to break *both*.
- **Identity: ML-DSA-65 certificates** (FIPS 204, the standardised
  CRYSTALS-Dilithium), and every CertificateVerify is an ML-DSA signature, on
  both sides, because ThreadLink is mutually authenticated. Most deployments
  that have adopted hybrid key exchange still sign with classical keys.

aioquic 1.3.0 supports neither, so `threadlink/pq.py` adds them using the ML-KEM
and ML-DSA that `cryptography` exposes from OpenSSL 3.5+. Every aioquic method it
replaces or wraps is fingerprinted. On any other aioquic version it patches
nothing, logs why, and ThreadLink keeps working classically
(`threadlink.pq_status()` reports which). Other details:

- `THREADLINK_PQ=off` is the rollback; `THREADLINK_PQ=require` refuses any peer
  that will not do the hybrid.
- A post-quantum node still talks to an older one (its classical key shares are
  offered behind the hybrid).
- `Peer.crypto` reports what a connection actually negotiated.
- Interop is checked against OpenSSL's own QUIC client: `openssl s_client -quic
  -groups X25519MLKEM768 -sigalgs mldsa65` with an ML-DSA client certificate
  completes the handshake against a ThreadLink listener.

The cost is bytes, not time. A 5.6 KB certificate and a 3.3 KB signature,
against roughly 0.5 KB for P-256, make the handshake about 10 KB larger. On
loopback it takes ~3.5 ms either way. See it on the wire in
[`demo/wireshark/pq/`](demo/wireshark/pq/): a decrypting capture plus screenshots.

![ThreadLink in Wireshark: X25519MLKEM768 key share](demo/wireshark/pq/threadlink-pq-clienthello.png)

---

## Why QUIC, concretely

| | TCP + TLS 1.3 | QUIC + TLS 1.3 |
|---|---|---|
| Round trips to first byte | 2 (3 with TLS 1.2) | **1**, or **0** resumed |
| Encryption | optional, bolted on | mandatory, integral |
| Head-of-line blocking | one byte pipe — a loss stalls everything behind it | per-stream — a stalled transfer stalls only itself |
| Survives an IP/port change | no, the connection *is* the four-tuple | **yes** — identified by Connection ID |

The last row is the interesting one for decentralized AGI. A QUIC connection is
identified by a Connection ID carried inside the packets, independent of the
addresses underneath, so it survives NAT rebinding and network changes. For
persistent agents that may move between machines, networks, edge devices and
compute providers, that property deserves attention — `demo/migration.py`
proves it live rather than asserting it.

## What the API looks like

```python
from threadlink import dial, listen, ensure_cert, Control

MY_MSG = 0x21          # your protocol's message types are yours to define

async def handle(msg_type, body, peer):        # server side
    if msg_type == MY_MSG:
        return MY_MSG, {"got": body}
    return Control.ERROR, {"error": "unhandled"}

cert, key = ensure_cert("certs", "agent_A", ["127.0.0.1"])
server = await listen(handle, "0.0.0.0", 4433, certfile=cert, keyfile=key)

async with await dial("192.168.86.41", 4433) as peer:   # client side
    reply_type, body = await peer.request(MY_MSG, {"hello": "world"})
    peer.migrate()                       # rotate Connection ID mid-session
```

Every `request` gets its own QUIC stream, so a large transfer never delays a
small urgent one — head-of-line isolation is structural, not something callers
must remember. The type byte is opaque to the transport; ThreadLink itself owns
only a handful of `Control` codes (PING/PONG/BYE/ERROR).

## Quick start

```bash
git clone https://github.com/hlgreenblatt/ThreadLink && cd ThreadLink
uv venv --python 3.12 .venv && uv pip install --python .venv/bin/python -e .

./.venv/bin/threadwatch                          # check your watch
./.venv/bin/python tests/test_threadlink.py      # 42 checks: live QUIC, post-quantum, classical fallback
./.venv/bin/python tests/test_threadchat.py      # 19 checks: letters, key pins, threads, the watch
./.venv/bin/python tests/test_threadhello.py     # 39 checks incl. live route sync
./.venv/bin/python demo/migration.py             # the agent moves, the link lives
./.venv/bin/python demo/chat/two_agent_chat.py   # two agents trade a letter
./.venv/bin/python demo/hello/three_agents.py    # route evidence travels two hops
./.venv/bin/python bench/handshake.py            # QUIC vs TCP+TLS, measured honestly
```

The learning router needs FabricPC, which is its own project:

```bash
git clone https://github.com/trueagi-io/FabricPC
uv pip install --python .venv/bin/python -e ./FabricPC
FABRICPC_PATH=$PWD/FabricPC ./.venv/bin/python demo/hello/with_threadrouter.py
```

Or install the toolkit as a dependency of your own agent:

```bash
pip install git+https://github.com/hlgreenblatt/ThreadLink
pip install "threadlink[adapters] @ git+https://github.com/hlgreenblatt/ThreadLink"   # + framework adapters
```

Watch the wire while a demo runs (needs `CAP_NET_RAW`):

```bash
sudo tcpdump -i lo -n 'udp portrange 4433-4499'
# or in Wireshark, filter:  quic   (wireshark/threadlink.lua decodes the frames)
```

## The benchmark is honest on purpose

`bench/handshake.py` runs on loopback, where QUIC's round-trip advantage is
worth ~0.05 ms, so it reports **measured** loopback numbers (where a C OpenSSL
TCP stack can beat pure-Python aioquic) separately from **projected**
round-trip arithmetic at a stated network RTT (where QUIC wins by construction:
1 RTT vs 2, or 0 resumed). Read the header of that file before quoting any
number.

## Security posture (sprint honesty)

Connections are always encrypted, post-quantum (see above); peer *authentication*
currently uses self-signed ML-DSA-65 certificates with verification off by default, suitable for a
trusted LAN and not beyond it — see `docs/SECURITY.md` for exactly what is and
is not defended, and the SPKI-pinning hook (`spki_pin`) left for the trust
layer to grow into.

## Layout

```
threadlink/link.py       dial/listen, streams, migration (aioquic underneath)
threadlink/wire.py       10-byte frame header + JSON body; type byte is opaque
threadlink/certs.py      per-agent self-signed certs (ML-DSA-65 default) + SPKI pins
threadlink/pq.py         X25519MLKEM768 + ML-DSA for aioquic 1.3.0
threadlink/watch.py      ThreadWatch: the UTC stamp + the `threadwatch` command
threadhello/             route-evidence exchange between routers (observations, not weights)
threadchat/              agent-to-agent letters: sender pins, threads, the watch
threadrouter/            tk_router: fingerprint -> FabricPC outcome bundle -> chooser
adapters/                ThreadChat nodes for Omega, OpenClaw, Hermes, sub-agents; Omega router skill
demo/                    migration, chat/, hello/, wireshark/ (decrypted captures)
bench/handshake.py       QUIC vs TCP+TLS 1.3, measured vs projected
spec/                    draft-greenblatt-threadlink-00 (the wire format)
wireshark/threadlink.lua Wireshark dissector
tests/                   100 checks across the core, ThreadChat and ThreadHello
docs/                    SECURITY.md, THREADCHAT.md, THREADROUTER.md
```

ThreadChat and ThreadRouter began as their own repositories; their full
histories were merged in, so `git log` still shows every step.
