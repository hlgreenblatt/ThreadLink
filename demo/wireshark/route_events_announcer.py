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

# Three models spanning the assurance ladder — locality and CONTROLS are
# separate questions, and the wire says both:
#   LOCAL      on the fleet, self-attested by the operator
#   CLOUD certified   third-party BUT under a 3PAO/FedRAMP attestation (defensible)
#   CLOUD unverified  third-party free tier, no DPA, no assessment (the risky one)
LOCAL_MODEL = "ollama/qwen3.8-27b"
LOCAL_PATH = "local_chat"
CERT_MODEL = "bedrock/claude-sonnet"           # a cloud PROCESSOR under attestation
CERT_PATH = "cloud_certified"
RAW_MODEL = "openrouter/nemotron-nano-free"     # free tier, no controls basis
RAW_PATH = "cloud_free"


async def main() -> None:
    peer_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.86.29"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4433

    ellie = HelloAgent("agent_ellie", RouteStore("agent_ellie"),
                       known_paths={"cloud_free", "cloud_certified",
                                    "local_chat", "local_code"})

    print(f"[ellie] --> {peer_ip}:{port}", flush=True)
    await asyncio.sleep(0.3)  # let the listener settle / capture arm

    t0 = time.time()
    # 1a. LOCAL model on the fleet — self-attested (no third party in the loop).
    print(f"[ellie] 1a. loaded {LOCAL_MODEL} on the fleet "
          "[local/free, assurance=self_attested]", flush=True)
    ack = await ellie.announce_model(peer_ip, port, action="added",
                                     model=LOCAL_MODEL, path=LOCAL_PATH,
                                     local=True, free=True,
                                     assurance="self_attested",
                                     basis="operator-run on fleet hardware")
    print(f"[ellie]     acked [{ack.get('model_class')}, {ack.get('assurance')}], "
          f"peer epoch = {ack.get('epoch')}", flush=True)

    # 1b. CLOUD but CERTIFIED — a data processor under a 3PAO attestation. Leaves
    #     the fleet, yet its controls are independently assessed.
    print(f"[ellie] 1b. gained {CERT_MODEL} "
          "[cloud/paid, assurance=certified — 3PAO/FedRAMP]", flush=True)
    ack = await ellie.announce_model(peer_ip, port, action="added",
                                     model=CERT_MODEL, path=CERT_PATH,
                                     local=False, free=False,
                                     assurance="certified",
                                     basis="3PAO / FedRAMP Moderate + DPA Art.28")
    print(f"[ellie]     acked [{ack.get('model_class')}, {ack.get('assurance')}], "
          f"peer epoch = {ack.get('epoch')}", flush=True)

    # 1c. CLOUD and UNVERIFIED — free tier, no DPA, no assessment. This is the one
    #     a privacy-aware peer should refuse for anything sensitive.
    print(f"[ellie] 1c. gained {RAW_MODEL} "
          "[cloud/free, assurance=unverified — no DPA]", flush=True)
    ack = await ellie.announce_model(peer_ip, port, action="added",
                                     model=RAW_MODEL, path=RAW_PATH,
                                     local=False, free=True,
                                     assurance="unverified",
                                     basis="")
    print(f"[ellie]     acked [{ack.get('model_class')}, {ack.get('assurance')}], "
          f"peer epoch = {ack.get('epoch')}", flush=True)

    # 2. Share a route observation for the unverified cloud path (ROUTE_UPDATE).
    ellie.store.observe([1.0, 1.0, 1.0, 0.1, 1.0, 0.0, 0.0, 0.0], RAW_PATH,
                        {"completed": 1.0, "format_valid": 1.0, "task_fit": 1.0,
                         "privacy": 0.1, "cost": 0.0, "latency": 1.0})
    res = await ellie.push_update(peer_ip, port, since=0.0)
    print(f"[ellie] 2.  shared {res['pushed']} route row(s) (ROUTE_UPDATE)", flush=True)

    await asyncio.sleep(0.3)

    # 3. The unverified free tier is pulled first (route-down)...
    print(f"[ellie] 3.  unverified cloud pulled; withdrawing {RAW_PATH} "
          "(ROUTE_WITHDRAW)", flush=True)
    await ellie.withdraw_route(peer_ip, port, path=RAW_PATH)

    # 4. ...and retract that model. The local and CERTIFIED cloud models remain.
    print(f"[ellie] 4.  retracting {RAW_MODEL} (MODEL_UPDATE removed)", flush=True)
    ack = await ellie.announce_model(peer_ip, port, action="removed",
                                     model=RAW_MODEL, path=RAW_PATH,
                                     local=False, free=True,
                                     assurance="unverified")
    conv_ms = (time.time() - t0) * 1000
    print(f"[ellie]     done. Kept: local (self_attested) + certified cloud. "
          f"Dropped: the unverified free tier. "
          f"add->share->withdraw->remove in {conv_ms:.0f} ms, "
          f"final peer epoch = {ack.get('epoch')}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
