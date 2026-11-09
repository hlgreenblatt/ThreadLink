#!/usr/bin/env python3
"""
Three OmegaClaws, one ThreadLink mesh, gossiping via ThreadHello.

The demonstration makes the argument, so this is built to be watched rather than
to print a pass/fail. What it shows, in order:

  1. Three agents come up on three UDP ports, each with its own TLS identity.
  2. Each learns something DIFFERENT first-hand — different request shapes,
     different paths, different outcomes.
  3. They gossip along a chain: A <-> B, then B <-> C. A and C never speak.
  4. C ends up knowing what A measured, attributed to A.

Point 4 is the one to linger on. Nobody copied a model. A's evidence travelled
two hops through a swarm, was discounted as second-hand at each, and still
arrived usable and attributable. That is a route table propagating — and the
`origin` field means you can always answer "who actually measured this?"

Run:
    .venv/bin/python demo/three_agents.py
Watch the wire at the same time:
    sudo tcpdump -i lo -n 'udp portrange 4433-4435'
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadlink import ensure_cert, spki_pin                # noqa: E402
from threadhello import HelloAgent, RouteStore              # noqa: E402

logging.basicConfig(level=logging.WARNING, format="%(message)s")

HOST = "127.0.0.1"
CERTS = Path(__file__).resolve().parent.parent / "certs"

# A realistic heterogeneous fleet: C is a laptop with no local GPU, so it has
# never heard of `local_code`. The merge filter has to cope with that.
FLEET = {
    "omegaclaw_A": (4433, {"local_code", "local_chat", "cloud_deepseek", "cloud_glm"}),
    "omegaclaw_B": (4434, {"local_code", "local_chat", "cloud_deepseek", "cloud_glm"}),
    "omegaclaw_C": (4435, {"cloud_deepseek", "cloud_glm"}),
}

# (fingerprint, path, bundle) — what each agent measured for itself.
# fp order: has_code_fence, is_question, length_norm, numeric_density,
#           is_imperative, open_ended, live_info, multi_hop
#
# A deliberately measures the SAME request shape on two different paths: one
# path C also has, and one it does not. That single choice lets the demo show
# both behaviours on the same run — the shared path propagates two hops, the
# GPU-only path is refused at C — instead of leaving either to be taken on faith.
CODE_SHAPE = [1, 0, 0.55, 0.10, 1, 0, 0, 0]       # "write me a function…"

FIRST_HAND = {
    "omegaclaw_A": [
        (CODE_SHAPE, "local_code",                # C has no GPU → will be refused
         {"completed": 1.0, "format_valid": 1.0, "task_fit": 0.92,
          "privacy": 1.0, "cost": 0.0, "latency": 0.31}),
        (CODE_SHAPE, "cloud_deepseek",            # everyone has this → will travel
         {"completed": 1.0, "format_valid": 0.97, "task_fit": 0.89,
          "privacy": 0.0, "cost": 0.61, "latency": 0.52}),
    ],
    "omegaclaw_B": [
        ([0, 1, 0.20, 0.00, 0, 1, 0, 0], "cloud_glm",     # "what do you think…"
         {"completed": 1.0, "format_valid": 0.85, "task_fit": 0.74,
          "privacy": 0.0, "cost": 0.42, "latency": 0.19}),
    ],
    "omegaclaw_C": [
        ([0, 1, 0.35, 0.60, 0, 0, 1, 1], "cloud_deepseek",  # "latest numbers…"
         {"completed": 1.0, "format_valid": 0.95, "task_fit": 0.88,
          "privacy": 0.0, "cost": 0.55, "latency": 0.44}),
    ],
}

BAR = "─" * 72


def show(agents: dict[str, HelloAgent], title: str) -> None:
    print(f"\n{BAR}\n{title}\n{BAR}")
    for name, ag in agents.items():
        s = ag.store.summary()
        print(f"  {name:14s} rows={s['rows']:<3d} "
              f"first-hand={s['first_hand']:<3d} second-hand={s['second_hand']:<3d} "
              f"paths={','.join(s['paths']) or '—'}")


async def main() -> None:
    agents: dict[str, HelloAgent] = {}
    servers = []

    print(f"{BAR}\nThreadLink · three OmegaClaws · QUIC/TLS1.3 over UDP\n{BAR}")
    for name, (port, paths) in FLEET.items():
        cert, key = ensure_cert(CERTS, name, [HOST])
        ag = HelloAgent(name, RouteStore(name), paths, spki_pin(cert))
        for fp, path, bundle in FIRST_HAND[name]:
            ag.store.observe(fp, path, bundle)
        servers.append(await ag.serve(HOST, port, certfile=cert, keyfile=key))
        agents[name] = ag
        print(f"  {name:14s} udp/{port}  spki={ag.spki[:16]}…  paths={len(paths)}")

    show(agents, "BEFORE — each agent knows only what it measured itself")

    print(f"\n{BAR}\nGOSSIP ROUND 1 · A <-> B   (C is not involved)\n{BAR}")
    r = await agents["omegaclaw_A"].sync_with(HOST, FLEET["omegaclaw_B"][0])
    print(f"  handshake {r['handshake_ms']} ms · full exchange {r['total_ms']} ms")
    print(f"  A pulled {r['pulled']}   A pushed {r['pushed']} rows")

    print(f"\n{BAR}\nGOSSIP ROUND 2 · B <-> C   (A is not involved)\n{BAR}")
    r = await agents["omegaclaw_B"].sync_with(HOST, FLEET["omegaclaw_C"][0])
    print(f"  handshake {r['handshake_ms']} ms · full exchange {r['total_ms']} ms")
    print(f"  B pulled {r['pulled']}   B pushed {r['pushed']} rows")

    show(agents, "AFTER — evidence has propagated across the mesh")

    # The payoff: did A's first-hand measurement reach C, two hops away?
    print(f"\n{BAR}\nDID A's EVIDENCE REACH C?   (A and C never connected)\n{BAR}")
    c_store = agents["omegaclaw_C"].store
    from_a = [o for o in c_store._obs.values() if o.origin == "omegaclaw_A"]
    if from_a:
        for o in from_a:
            print(f"  ✓ C holds cell={o.cell} path={o.path:<15s} "
                  f"origin={o.origin} weight={o.weight:.2f}")
        print("\n  Weight decays with distance: A measured it at 1.00, B discounted it")
        print("  to 0.50 as second-hand, C to 0.25 at two hops. Nobody had to code a")
        print("  hop count — it falls out of applying the same trust rule at each step.")
    else:
        print("  ✗ nothing from A reached C")

    dropped = [o for o in agents["omegaclaw_B"].store._obs.values()
               if o.path == "local_code"]
    print(f"\n  C has no local GPU, so `local_code` observations are refused there:")
    print(f"    B holds local_code rows: {len(dropped)}")
    print(f"    C holds local_code rows: "
          f"{len([o for o in c_store._obs.values() if o.path == 'local_code'])}"
          f"   ← filtered by known_paths, not learned as fiction")

    for s in servers:
        s.close()
    print(f"\n{BAR}\ndone.\n{BAR}")


if __name__ == "__main__":
    asyncio.run(main())
