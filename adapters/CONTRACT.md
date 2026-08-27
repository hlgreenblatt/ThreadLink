# The adapter contract

An adapter connects ThreadChat's transport-level node to one agent framework.
It is deliberately tiny: it answers exactly two questions, plus a little glue.

## What every adapter must provide

A `ChatNode` (from `threadchat`) needs two things about the local agent:

1. **`deliver(letter)` — an inbound sink.** Given a letter
   `{from, to, text, msg_id, ts, in_reply_to}`, hand it to the local agent so
   it appears in the agent's normal input. Return nothing; delivery is
   fire-and-forget (the agent answers later, through its outbox). May be async.

2. **an outbox source — how to hear what the agent said.** A way to read the
   agent's produced messages since some marker, so the adapter can relay a reply
   back to whoever asked. For a polling channel this is "GET messages since seq
   N"; for an event-driven one it is a callback.

The adapter also holds the **directory** — `{agent_id: (host, port)}` — so an
outbound message can be routed to the named recipient (or fanned out to all for
a group message). This is shared across a fleet as one small JSON file.


## Two adapter shapes (both satisfy this contract)

Frameworks expose the agent in one of two shapes, and the adapter follows:

- **Async** (OmegaClaw): messages are *injected* (`POST /send`) and the reply
  appears *later* on an outbox you poll (`GET /messages`). `deliver` injects;
  a separate watcher relays the reply when the agent produces it. Needed when
  the agent runs a free-running loop on its own clock.
- **Sync** (OpenClaw): posting a message *runs the agent's turn* and returns its
  reply in the same call (griff-proxy `POST /peer/<name>/agent`). `deliver` asks
  and relays the answer straight back — no outbox, no watcher. Run the blocking
  call in a thread (`asyncio.to_thread`) so the QUIC loop keeps serving. CRITICAL:
  a sync agent's turn can take tens of seconds, so `deliver` must ACK FAST —
  schedule the ask as a background task and return immediately, letting the
  answer arrive later as its own CHAT_MSG. Blocking inside `deliver` stalls the
  incoming letter's ACK past its timeout.

The mesh does not care which shape an agent is; the reply comes back as a
CHAT_MSG with `in_reply_to` either way.

## The seam, per framework

| Framework | inbound (`deliver`)            | outbox (hear the reply)        | auth note |
|-----------|--------------------------------|--------------------------------|-----------|
| OmegaClaw | `POST /send` (local channel)   | `GET /messages?since=N`        | single-session lock: the node must claim the session first |
| OpenClaw  | griff-proxy `POST /peer/<name>/agent` (SYNC — reply in same call) | *(same call)* | caller token (X-Proxy-Token) |
| Hermes    | griff-proxy `POST /peer/<name>/agent` (SYNC — same as OpenClaw; bridge wraps `hermes chat -Q` in OpenClaw's envelope) | *(same call)* | caller token (X-Proxy-Token) |

The differences are entirely in these two calls and their auth. The protocol,
the QUIC wire, the dedup, the group fan-out, the reply routing — all identical,
all in `threadchat/`, none of it re-implemented per framework.

## Testing an adapter

Never trust a mock for the auth/ingestion path — those are exactly where
frameworks differ (OmegaClaw's session lock surfaced only against a live agent).
Prove each new adapter with a real round-trip against a running agent of that
framework before calling it done: send it a question, confirm the agent's own
reply routes back with `in_reply_to` set.
