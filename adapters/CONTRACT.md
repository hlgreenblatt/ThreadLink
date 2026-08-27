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

## The seam, per framework

| Framework | inbound (`deliver`)            | outbox (hear the reply)        | auth note |
|-----------|--------------------------------|--------------------------------|-----------|
| OmegaClaw | `POST /send` (local channel)   | `GET /messages?since=N`        | single-session lock: the node must claim the session first |
| OpenClaw  | gateway message API *(planned)*| gateway outbound stream/poll   | gateway token |
| Hermes    | hermes bridge inbound *(planned)* | `hermes chat -Q` / bridge out | bridge token |

The differences are entirely in these two calls and their auth. The protocol,
the QUIC wire, the dedup, the group fan-out, the reply routing — all identical,
all in `threadchat/`, none of it re-implemented per framework.

## Testing an adapter

Never trust a mock for the auth/ingestion path — those are exactly where
frameworks differ (OmegaClaw's session lock surfaced only against a live agent).
Prove each new adapter with a real round-trip against a running agent of that
framework before calling it done: send it a question, confirm the agent's own
reply routes back with `in_reply_to` set.
