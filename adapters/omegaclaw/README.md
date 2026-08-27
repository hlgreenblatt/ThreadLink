# OmegaClaw adapter

Puts an OmegaClaw agent on the ThreadChat mesh through its local HTTP channel
(the `channels/local.py` WebUI channel: `POST /send`, `GET /messages`).

- **`node.py`** — one process per agent host. Receives `CHAT_MSG` over QUIC and
  `POST`s it to the agent's `/send`; watches `GET /messages` and relays the
  agent's reply back to whoever asked. Claims the channel's auth session on
  startup (OmegaClaw's local channel binds to one session — the node must be it).
- **`deploy/`** — a `systemd --user` template + installer so the node runs
  persistently and survives logout.
- **`chat_directory.example.json`** — copy to the repo root as
  `chat_directory.json` and fill in each agent's `host, port`.

## Install (per host)

```bash
# from a real login shell on the agent's host:
adapters/omegaclaw/deploy/install-threadchat.sh          # auto-detects the local agent
```

The installer writes the per-host env file, installs the templated unit,
enables linger, and starts the node — then confirms it is `LISTENING on udp/4460`.

## Known quirk — the session lock

OmegaClaw's local channel authenticates the *first* session to present the
secret and rejects others. If a stale session already holds it (a prior tool,
an old relay), the node's claim loses and delivery returns 401. Clearing it is a
`docker restart <agent>`; the node re-claims on its next attempt. Documented so
it is a five-second fix, not a mystery.
