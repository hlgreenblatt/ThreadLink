#!/usr/bin/env python3
"""Route-events LAN demo — the LISTENER (a sister node on the GB10).

Serves ThreadHello on a real LAN address and prints every route event it
receives, so the announcer side (Ellie, on the workstation) can be seen to
actually change this node's view of the mesh: a model appears, a delta merges,
a path is withdrawn, the model retracts.

Run on .29:
    ~/build/ThreadRouter/.venv/bin/python route_events_listener.py <bind-ip> <port>
It runs until it has seen a MODEL_UPDATE(removed), then prints a summary and exits.
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "build/ThreadRouter"))
sys.path.insert(0, str(Path.home() / "build/ThreadLink"))

from threadlink import ensure_cert
from threadhello import HelloAgent, RouteStore

CERTS = Path.home() / "build/ThreadLink/demo/wireshark/certs"


async def main() -> None:
    bind = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4433

    cert, key = ensure_cert(CERTS, "sister_66", [bind, "127.0.0.1"])
    node = HelloAgent("agent_66", RouteStore("agent_66"),
                      known_paths={"cloud_free", "local_chat", "local_code"})

    done = asyncio.Event()

    # wrap the handler BEFORE serve() — serve captures self.handle by reference,
    # so the narration must be in place first or the wrapper never fires.
    from threadhello import HelloMsg
    orig = node.handle

    async def narrating_handle(msg_type, body, ctx):
        reply = await orig(msg_type, body, ctx)
        if msg_type == HelloMsg.MODEL_UPDATE:
            act, mdl = body.get("action"), body.get("model")
            caps = node.peers_caps.get(body.get("agent", "?"), set())
            cls = body.get("model_class", "?")
            asr = body.get("assurance", "?")
            basis = body.get("basis", "")
            tail = f" — {basis}" if basis else ""
            print(f"[sister] MODEL_UPDATE: {body.get('agent')} {act} {mdl} "
                  f"[{cls}, assurance={asr}{tail}] -> now serves {sorted(caps)} "
                  f"(epoch {node.epoch})", flush=True)
            if act == "removed":
                done.set()
        elif msg_type == HelloMsg.ROUTE_UPDATE:
            print(f"[sister] ROUTE_UPDATE: merged delta, store now {len(node.store)} "
                  f"rows (epoch {node.epoch})", flush=True)
        elif msg_type == HelloMsg.ROUTE_WITHDRAW:
            print(f"[sister] ROUTE_WITHDRAW: path {body.get('path')} down, "
                  f"store now {len(node.store)} rows (epoch {node.epoch})", flush=True)
        return reply

    node.handle = narrating_handle
    await node.serve(bind, port, certfile=str(cert), keyfile=str(key))
    print(f"[sister] agent_66 listening on {bind}:{port}", flush=True)

    try:
        await asyncio.wait_for(done.wait(), timeout=60)
        print(f"[sister] SUMMARY: final store {len(node.store)} rows, "
              f"caps {dict((k, sorted(v)) for k, v in node.peers_caps.items())}, "
              f"epoch {node.epoch}", flush=True)
    except asyncio.TimeoutError:
        print("[sister] TIMEOUT waiting for events", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
