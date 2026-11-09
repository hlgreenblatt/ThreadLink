# OpenClaw adapter

Puts an OpenClaw agent (Astraea/Griff, 灵犀/99, Theia/23) on the ThreadChat mesh
through **griff-proxy** — the fleet's existing inter-agent bus.

OpenClaw is **synchronous**: `POST /peer/<name>/agent` (with a caller token)
runs the agent's turn and returns its reply in the same HTTP response. So this
adapter's `deliver` asks the agent and relays the answer straight back — no
outbox to poll. See `../CONTRACT.md` (sync vs async shapes).

## Run (on the host that can reach griff-proxy — the .41 workstation)

```bash
python adapters/openclaw/node.py \
    --id agent_griff \
    --proxy http://127.0.0.1:18895 \
    --token ~/ishtar/griff-proxy/secrets/callers/sparks.token \
    --peer-name agent_griff \
    --directory chat_directory.json --port 4461
```

`--peer-name` is the agent's name at the proxy; `--id` is its name on the mesh
(usually the same). Each OpenClaw agent gets its own node + port.

## Proven

2026-08-27: 漪 (OmegaClaw, .29) asked Griff (OpenClaw, .41) "what framework are
you on?" over ThreadChat/QUIC; Griff answered *"Astraea / Agent_Griff, running on
Codex GPT-5 inside OpenClaw"* — routed back with `in_reply_to` set. First
cross-framework conversation on the mesh.

## Auth note

Uses a griff-proxy **caller token** (e.g. `sparks.token`), not a per-agent
secret. The token authorizes the caller to reach that peer; the proxy's ACL
governs who may call whom. No single-session lock (that was OmegaClaw's quirk).
