#!/usr/bin/env python3
"""
The real integration: ThreadRouter -> ThreadLink -> ThreadRouter.

Everything else in demo/ uses hand-written fingerprints so it runs anywhere.
This one imports the actual tk_router from threadkeeper-v2 and drives the whole
loop with real objects:

    real request text
      -> tk_router.fingerprint()          (8 floats, no raw text)
      -> RouteStore.observe()             (agent A's evidence)
      -> ThreadLink / QUIC                (encrypted, 1 RTT)
      -> RouteStore.merge()               (agent B, discounted, filtered)
      -> Router.learn_outcome()           (B's FabricPC net actually updates)

The last step is the one worth checking: B's predictions for that request shape
should MOVE after learning from A, without B ever running the request itself.

Run:  .venv/bin/python demo/with_threadrouter.py
      (needs a FabricPC clone at ./FabricPC or $FABRICPC_PATH)
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
# FabricPC ships `jax_setup.py` at its repo root, and tk_router imports it as a
# top-level module — so the FabricPC directory has to be on the path too, not
# just its parent. Without this the router silently degrades to "FabricPC
# unavailable" and every learn_outcome becomes a no-op.
# Clone it next to this repo's root:  git clone https://github.com/trueagi-io/FabricPC
FABRICPC = Path(os.environ.get("FABRICPC_PATH", REPO / "FabricPC"))
sys.path.insert(0, str(FABRICPC))

from threadlink import ensure_cert, spki_pin                # noqa: E402
from threadhello import HelloAgent, RouteStore              # noqa: E402

BAR = "─" * 74
HOST, PORT = "127.0.0.1", 4437
CERTS = Path(__file__).resolve().parent.parent / "certs"

REQUEST = "write me a python function that parses a json config file"


async def main() -> None:
    try:
        import tk_router
    except ImportError as exc:
        print(f"tk_router not importable from {REPO}: {exc}")
        print("if FabricPC is missing:  git clone https://github.com/trueagi-io/FabricPC")
        print("(or set FABRICPC_PATH to an existing clone)")
        return

    print(f"{BAR}\nThreadRouter -> ThreadLink -> ThreadRouter\n{BAR}")

    # Sanity: the two modules must agree on the outcome vocabulary, or every
    # shared bundle would be silently misaligned.
    from threadhello import ATTRS as TH_ATTRS
    assert TH_ATTRS == tk_router.ATTRS, "ATTRS drift between threadhello and tk_router"
    print(f"  attrs agree: {tk_router.ATTRS}")
    print(f"  roster paths: {len(tk_router.PATHS)}")

    paths = set(tk_router.PATHS)
    fp = tk_router.fingerprint(REQUEST)
    print(f"\n  request     : {REQUEST!r}")
    print(f"  fingerprint : {[round(x, 2) for x in fp]}")
    print(f"  ^ 8 floats of word shape. The request text itself never leaves.")

    # ---- Agent A measures a real outcome --------------------------------
    bundle = tk_router.measure_outcome(
        request=REQUEST,
        reply="def parse_config(path):\n    import json\n    return json.load(open(path))\n",
        cost_usd=0.0, latency_ms=820.0, is_local=True,
    )
    print(f"\n  A measured on 'local_code': "
          f"{ {k: round(v, 2) for k, v in bundle.items()} }")

    cert, key = ensure_cert(CERTS, "tr_agent_A", [HOST])
    A = HelloAgent("tr_agent_A", RouteStore("tr_agent_A"), paths, spki_pin(cert))
    A.store.observe(fp, "local_code", bundle)
    server = await A.serve(HOST, PORT, certfile=cert, keyfile=key)

    # ---- Agent B has its own router and has never seen this ------------
    B = HelloAgent("tr_agent_B", RouteStore("tr_agent_B"), paths)
    router_b = tk_router.Router()

    before = _predict(router_b, REQUEST)
    print(f"\n  B predicts BEFORE learning : {before}")

    res = await B.sync_with(HOST, PORT)
    print(f"\n  synced over QUIC in {res['total_ms']} ms "
          f"(handshake {res['handshake_ms']} ms)")
    print(f"  B pulled: {res['pulled']}")

    taught = B.store.teach(router_b, epochs=40)
    print(f"  replayed {taught} observation(s) into B's FabricPC net")

    after = _predict(router_b, REQUEST)
    print(f"\n  B predicts AFTER learning  : {after}")

    print(f"\n{BAR}")
    if before != after:
        print("✓ B's routing changed from A's experience, over an encrypted link,")
        print("  without B ever running the request and without the text leaving A.")
    else:
        print("· B's prediction did not move. Most likely FabricPC is unavailable so")
        print("  learn_outcome is a no-op — check tk_router's lazy init. The transport")
        print("  and merge path above still completed.")
    print(BAR)

    server.close()


def _predict(router, request: str):
    """Best path + its utility, defensively — Router.predict has a safe-null mode."""
    try:
        chosen, _bundles, utility, _fp = router.predict(request)
    except Exception as exc:
        return f"<predict failed: {type(exc).__name__}>"
    if chosen is None:
        return "<no prediction — FabricPC unavailable>"
    return f"{chosen} (utility {utility.get(chosen, 0.0):+.3f})"


if __name__ == "__main__":
    asyncio.run(main())
