#!/usr/bin/env python3
"""
ThreadHello tests — the route-sharing protocol and its merge policy.

Weighted toward the merge policy, because that is where a subtle bug would be
invisible: a swarm with a broken trust rule still runs, still gossips, and
quietly converges on the wrong answer. The live section runs the real protocol
over a real ThreadLink QUIC connection — a stub would prove nothing.

Transport-level behaviour (framing, certs, streams, migration mechanics) is
tested where it lives: the ThreadLink repo.

Run:  .venv/bin/python tests/test_threadhello.py
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadlink import Control, ensure_cert, spki_pin                # noqa: E402
from threadlink.link import client_config, dial                      # noqa: E402
from threadhello import (                                            # noqa: E402
    HelloAgent, HelloMsg, Observation, RouteStore, cell_key, fp_of_cell,
)
from threadhello.routeshare import DEFAULT_TRUST, MAX_WEIGHT         # noqa: E402

PASS, FAIL = [], []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  {'✓' if cond else '✗'} {name}{'  — ' + detail if detail and not cond else ''}")


# ------------------------------------------------------------- cells
def test_cells() -> None:
    print("\nfingerprint cells")
    fp = [1, 0, 0.55, 0.10, 1, 0, 0, 0]
    c = cell_key(fp)
    check("cell is 8 digits", len(c) == 8 and c.isdigit(), c)
    check("binary features preserved exactly", c[0] == "1" and c[1] == "0")
    check("stable under tiny jitter",
          cell_key([1, 0, 0.56, 0.11, 1, 0, 0, 0]) == c)
    back = fp_of_cell(c)
    check("inverse recovers binary features",
          back[0] == 1.0 and back[1] == 0.0 and back[4] == 1.0)
    check("inverse puts continuous in right bucket",
          abs(back[2] - 0.625) < 1e-9, str(back[2]))


# ------------------------------------------------------------- merge
def test_merge() -> None:
    print("\nmerge policy")
    fp = [1, 0, 0.5, 0.1, 1, 0, 0, 0]
    good = {"completed": 1.0, "format_valid": 1.0, "task_fit": 0.9,
            "privacy": 1.0, "cost": 0.0, "latency": 0.3}

    a = RouteStore("A")
    a.observe(fp, "p1", good)
    check("first-hand observation stored", len(a) == 1)
    check("first-hand weight is 1.0",
          abs(list(a._obs.values())[0].weight - 1.0) < 1e-9)

    b = RouteStore("B")
    stats = b.merge(a.export(), known_paths={"p1"})
    check("peer observation accepted", stats["accepted"] == 1)
    check("second-hand is discounted",
          abs(list(b._obs.values())[0].weight - DEFAULT_TRUST) < 1e-9,
          str(list(b._obs.values())[0].weight))
    check("origin is preserved across the hop",
          list(b._obs.values())[0].origin == "A")

    # Gossip ring: A must refuse its own evidence coming back.
    back = a.merge(b.export(), known_paths={"p1"})
    check("own observations refused (loop guard)", back["loop"] == 1)

    # Heterogeneous fleet: unknown paths are dropped, not invented.
    c = RouteStore("C")
    dropped = c.merge(a.export(), known_paths={"other"})
    check("unknown path refused", dropped["unknown_path"] == 1 and len(c) == 0)

    # Two hops: weight decays multiplicatively without any hop counter.
    d = RouteStore("D")
    d.merge(b.export(), known_paths={"p1"})
    check("weight decays over two hops",
          abs(list(d._obs.values())[0].weight - DEFAULT_TRUST ** 2) < 1e-9,
          str(list(d._obs.values())[0].weight))

    # Malformed records must not poison a batch.
    e = RouteStore("E")
    mixed = [{"garbage": True}, *a.export(), {"cell": "xx", "path": "p1"}]
    st = e.merge(mixed, known_paths={"p1"})
    check("malformed records isolated", st["malformed"] == 2 and st["accepted"] == 1)

    # Out-of-range attributes are rejected (tk_router guarantees [0,1]).
    bad = a.export()
    bad[0]["bundle"]["task_fit"] = 4.2
    f = RouteStore("F")
    check("out-of-range attr rejected",
          f.merge(bad, known_paths={"p1"})["malformed"] == 1)

    # Evidence accumulates but is capped.
    g = RouteStore("G")
    for _ in range(200):
        g.observe(fp, "p1", good)
    check("weight capped at MAX_WEIGHT",
          abs(list(g._obs.values())[0].weight - MAX_WEIGHT) < 1e-9,
          str(list(g._obs.values())[0].weight))

    # Averaging: two opposite observations land in the middle.
    h = RouteStore("H")
    h.observe(fp, "p1", {**good, "task_fit": 0.0})
    h.observe(fp, "p1", {**good, "task_fit": 1.0})
    check("bundles are weight-averaged",
          abs(list(h._obs.values())[0].bundle["task_fit"] - 0.5) < 1e-9)


# --------------------------------------------------- live protocol over QUIC
async def test_live() -> None:
    print("\nlive ThreadHello over QUIC")
    with tempfile.TemporaryDirectory() as d:
        cert, key = ensure_cert(d, "srv", ["127.0.0.1"])
        srv = HelloAgent("srv", RouteStore("srv"), {"p1"}, spki_pin(cert))
        srv.store.observe([1, 0, 0.5, 0.1, 1, 0, 0, 0], "p1",
                          {"completed": 1.0, "format_valid": 1.0, "task_fit": 0.9,
                           "privacy": 1.0, "cost": 0.0, "latency": 0.3})
        server = await srv.serve("127.0.0.1", 4456, certfile=cert, keyfile=key)

        cli = HelloAgent("cli", RouteStore("cli"), {"p1"})
        res = await cli.sync_with("127.0.0.1", 4456)
        check("handshake completed", res["handshake_ms"] is not None)
        check("route row pulled over QUIC", res["pulled"]["accepted"] == 1)
        check("client learned the peer's row", len(cli.store) == 1)
        check("origin survived the wire",
              list(cli.store._obs.values())[0].origin == "srv")
        check("server saw the client's HELLO", "cli" in srv.peers_seen)

        # Protocol version mismatch must be refused clearly, not silently.
        async with await dial("127.0.0.1", 4456, config=client_config()) as peer:
            _t, ack = await peer.request(HelloMsg.HELLO, {"agent": "old", "proto": 99})
            check("version mismatch refused", ack.get("error") == "protocol_mismatch")

            # PING answered via ThreadLink's generic control types.
            _t, pong = await peer.request(Control.PING, {"t": 7})
            check("PING answered with PONG",
                  _t == Control.PONG and pong.get("t") == 7)

            # The route exchange must survive a mid-session migration.
            before = peer.peer_connection_id
            after = peer.migrate()
            _t, tbl = await peer.request(HelloMsg.ROUTE_REQ, {"since": 0})
            check("route pull survives connection migration",
                  before != after and len(tbl.get("rows") or []) == 1)

        # --- event-driven route updates: a capability appears, then withdraws ---
        print("\nlive route events (MODEL_UPDATE / ROUTE_WITHDRAW)")
        ev = HelloAgent("ev", RouteStore("ev"), {"p1"})
        ep0 = srv.epoch

        # MODEL_UPDATE(added): the server learns ev now serves a model on a path.
        ack = await ev.announce_model("127.0.0.1", 4456,
                                      action="added", model="free/nemotron", path="p1")
        check("MODEL_UPDATE added is acked", ack.get("noted") == "free/nemotron")
        check("server recorded the peer capability",
              "free/nemotron" in srv.peers_caps.get("ev", set()))
        check("epoch advanced on capability add", ack.get("epoch") == ep0 + 1)

        # ROUTE_UPDATE: a delta of observations merges without a full table pull.
        ev.store.observe([1, 1, 1, 0.5, 1, 0, 0, 0], "p1",
                         {"completed": 1.0, "format_valid": 1.0, "task_fit": 1.0,
                          "privacy": 1.0, "cost": 0.0, "latency": 1.0})
        before_rows = len(srv.store)
        res = await ev.push_update("127.0.0.1", 4456, since=0.0)
        check("ROUTE_UPDATE delta merged", len(srv.store) == before_rows + res["pushed"])

        # ROUTE_WITHDRAW: the path goes down; its rows are dropped (route-down).
        ack = await ev.withdraw_route("127.0.0.1", 4456, path="p1")
        check("ROUTE_WITHDRAW drops the path's rows",
              all(k[1] != "p1" for k in srv.store._obs))
        check("epoch advanced on withdraw", ack.get("epoch") > ep0 + 1)

        # MODEL_UPDATE(removed): capability retracts and its route goes with it.
        ack = await ev.announce_model("127.0.0.1", 4456,
                                      action="removed", model="free/nemotron", path="p1")
        check("capability retracted", "free/nemotron" not in srv.peers_caps.get("ev", set()))

        server.close()


def main() -> int:
    print("═" * 60)
    print("ThreadHello test suite")
    print("═" * 60)
    test_cells()
    test_merge()
    asyncio.run(test_live())
    print("\n" + "═" * 60)
    print(f"{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        for f in FAIL:
            print(f"  FAILED: {f}")
    print("═" * 60)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
