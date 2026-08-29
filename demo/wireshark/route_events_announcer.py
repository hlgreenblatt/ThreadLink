#!/usr/bin/env python3
"""Route-events LAN demo — the ANNOUNCER (Ellie, on the workstation).

Ellie gains access to a free model, tells the mesh, shares a route delta for
it, then drops the model and withdraws the path. This is the real event
sequence that the sister node (route_events_listener.py) receives over the LAN,
and that the pcap decrypts to.

Set SSLKEYLOGFILE before running so the capture can be decrypted:
    SSLKEYLOGFILE=keys.log ~/.venv/bin/python route_events_announcer.py <peer-ip> <port>
"""
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path.home() / "build/ThreadRouter"))
sys.path.insert(0, str(Path.home() / "build/ThreadLink"))

from threadhello import HelloAgent, RouteStore

# Two models of DIFFERENT provenance, so the local/cloud distinction is on the wire:
LOCAL_MODEL = "ollama/qwen3.8-27b"          # runs on the fleet — private & free
LOCAL_PATH = "local_chat"
CLOUD_MODEL = "openrouter/nemotron-nano-free"  # third-party — not private (free tier)
CLOUD_PATH = "cloud_free"


async def main() -> None:
    peer_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.86.29"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4433

    ellie = HelloAgent("agent_ellie", RouteStore("agent_ellie"),
                       known_paths={"cloud_free", "local_chat", "local_code"})

    print(f"[ellie] --> {peer_ip}:{port}", flush=True)
    await asyncio.sleep(0.3)  # let the listener settle / capture arm

    t0 = time.time()
    # 1a. Ellie pulls a new model onto the fleet — LOCAL: private and free.
    print(f"[ellie] 1a. loaded {LOCAL_MODEL} on the fleet — announcing "
          "MODEL_UPDATE added [local/free, private]", flush=True)
    ack = await ellie.announce_model(peer_ip, port, action="added",
                                     model=LOCAL_MODEL, path=LOCAL_PATH,
                                     local=True, free=True)
    print(f"[ellie]     acked [{ack.get('model_class')}], peer epoch = {ack.get('epoch')}",
          flush=True)

    # 1b. Ellie also gains a free CLOUD model — NOT private (leaves the fleet).
    print(f"[ellie] 1b. gained {CLOUD_MODEL} — announcing "
          "MODEL_UPDATE added [cloud/free, NOT private]", flush=True)
    ack = await ellie.announce_model(peer_ip, port, action="added",
                                     model=CLOUD_MODEL, path=CLOUD_PATH,
                                     local=False, free=True)
    print(f"[ellie]     acked [{ack.get('model_class')}], peer epoch = {ack.get('epoch')}",
          flush=True)

    # 2. Ellie shares a route observation for the cloud model (ROUTE_UPDATE delta).
    ellie.store.observe([1.0, 1.0, 1.0, 0.2, 1.0, 0.0, 0.0, 0.0], CLOUD_PATH,
                        {"completed": 1.0, "format_valid": 1.0, "task_fit": 1.0,
                         "privacy": 0.2, "cost": 0.0, "latency": 1.0})
    res = await ellie.push_update(peer_ip, port, since=0.0)
    print(f"[ellie] 2.  shared {res['pushed']} route row(s) (ROUTE_UPDATE)", flush=True)

    await asyncio.sleep(0.3)  # the models are "used" for a moment

    # 3. The cloud access expires; withdraw its path (route-down)...
    print(f"[ellie] 3.  cloud access expired; withdrawing {CLOUD_PATH} "
          "(ROUTE_WITHDRAW)", flush=True)
    await ellie.withdraw_route(peer_ip, port, path=CLOUD_PATH)

    # 4. ...then retract the cloud capability (MODEL_UPDATE removed).
    print(f"[ellie] 4.  retracting {CLOUD_MODEL} (MODEL_UPDATE removed)", flush=True)
    ack = await ellie.announce_model(peer_ip, port, action="removed",
                                     model=CLOUD_MODEL, path=CLOUD_PATH,
                                     local=False, free=True)
    conv_ms = (time.time() - t0) * 1000
    print(f"[ellie]     done. The local model stays; the cloud one is gone. "
          f"add->share->withdraw->remove in {conv_ms:.0f} ms, "
          f"final peer epoch = {ack.get('epoch')}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
