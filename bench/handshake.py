#!/usr/bin/env python3
"""
ThreadLink benchmark — QUIC vs TCP+TLS 1.3, measured honestly.

READ THIS BEFORE QUOTING A NUMBER
=================================
This benchmark runs both stacks over LOOPBACK, where the round-trip time is
roughly 0.05 ms. QUIC's headline advantage is spending ONE round trip on the
handshake instead of TWO, so on loopback that advantage is worth ~0.05 ms and
is completely buried by process scheduling noise. A wall-clock number from this
machine would be honest about this machine and misleading about anything else.

So we report two different things, and keep them apart:

  MEASURED    what actually happened here, including the fixed CPU cost of
              crypto — QUIC is not free, and on loopback it can lose.

  PROJECTED   round trips × a stated network RTT. This is arithmetic, not a
              measurement, and it is labelled as such. It is the number that
              matters for agents on different machines, which is the entire
              point of a comlink.

The round-trip counts themselves are structural facts about the protocols, not
things we measured:
  TCP + TLS 1.3   1 RTT (SYN/SYN-ACK/ACK) + 1 RTT (TLS) = 2 RTT to first byte
  TCP + TLS 1.2                                         = 3 RTT
  QUIC + TLS 1.3  transport and crypto in one           = 1 RTT
  QUIC resumed    0-RTT with a session ticket           = 0 RTT

Run:  .venv/bin/python bench/handshake.py
      .venv/bin/python bench/handshake.py --iterations 50 --rtt 40
"""

from __future__ import annotations

import argparse
import asyncio
import json
import ssl
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadlink import ensure_cert                               # noqa: E402
from threadlink.link import client_config, dial, listen          # noqa: E402
from threadlink.wire import FrameReader, encode                  # noqa: E402

# The bench's own application message type — ThreadLink carries any byte.
BATCH = 0x10

HOST = "127.0.0.1"
QUIC_PORT = 4443
TCP_PORT = 4444
CERTS = Path(__file__).resolve().parent.parent / "certs"

# Round trips to first application byte — structural, not measured.
RTT_COST = {"quic": 1, "quic_resumed": 0, "tcp_tls13": 2, "tcp_tls12": 3}


# ---------------------------------------------------------------- payload
def make_route_batch(n: int) -> dict:
    """A realistic body: n route observations, same shape ThreadHello sends."""
    t = round(time.time(), 3)
    rows = [{
        "cell": format(i % 256, "08b"),
        "path": f"path_{i % 4}",
        "bundle": {"completed": 1.0, "format_valid": 0.9, "task_fit": 0.8,
                   "privacy": 1.0, "cost": 0.1, "latency": 0.2},
        "w": 1.0, "ts": t, "origin": "bench",
    } for i in range(n)]
    return {"rows": rows, "agent": "bench"}


# ---------------------------------------------------------------- TCP+TLS
async def tcp_server(certfile: str, keyfile: str, payload: dict):
    """Baseline: same frames, same JSON, over TCP+TLS 1.3. Only transport differs."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile, keyfile)
    reply = encode(BATCH, payload)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        fr = FrameReader()
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                got = False
                for _mt, _body in fr.feed(data):
                    got = True
                if got:
                    writer.write(reply)
                    await writer.drain()
                    break
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    return await asyncio.start_server(handle, HOST, TCP_PORT, ssl=ctx)


async def tcp_once(payload_frame: bytes) -> float:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t0 = time.perf_counter()
    reader, writer = await asyncio.open_connection(HOST, TCP_PORT, ssl=ctx)
    writer.write(payload_frame)
    await writer.drain()
    fr = FrameReader()
    while True:
        data = await reader.read(65536)
        if not data:
            break
        done = False
        for _mt, _b in fr.feed(data):
            done = True
        if done:
            break
    elapsed = (time.perf_counter() - t0) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionResetError, ssl.SSLError):
        pass
    return elapsed


# ------------------------------------------------------------------- QUIC
async def quic_once(payload: dict) -> tuple[float, float]:
    """Returns (handshake_ms, total_ms) for one cold connect + one exchange."""
    t0 = time.perf_counter()
    async with await dial(HOST, QUIC_PORT, config=client_config()) as peer:
        hs = peer.handshake_ms or 0.0
        await peer.request(BATCH, payload)
        return hs, (time.perf_counter() - t0) * 1000


async def quic_concurrent(payload: dict, n: int) -> float:
    """N exchanges on ONE connection, all in flight at once.

    This is the property a handshake benchmark misses: each exchange gets its
    own QUIC stream, so they do not queue behind each other. Over TCP these
    would share one byte pipe.
    """
    async with await dial(HOST, QUIC_PORT, config=client_config()) as peer:
        t0 = time.perf_counter()
        await asyncio.gather(*[
            peer.request(BATCH, payload) for _ in range(n)
        ])
        return (time.perf_counter() - t0) * 1000


# ------------------------------------------------------------------- main
async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iterations", type=int, default=30)
    ap.add_argument("--rows", type=int, default=64, help="route observations per message")
    ap.add_argument("--rtt", type=float, default=40.0,
                    help="network RTT in ms to PROJECT onto (not measured)")
    ap.add_argument("--concurrent", type=int, default=16)
    ap.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = ap.parse_args()

    payload = make_route_batch(args.rows)
    frame = encode(BATCH, payload)
    cert, key = ensure_cert(CERTS, "bench", [HOST])

    async def handler(mt, body, peer):
        return BATCH, payload

    qserver = await listen(handler, HOST, QUIC_PORT, certfile=cert, keyfile=key)
    tserver = await tcp_server(cert, key, payload)
    await asyncio.sleep(0.2)

    bar = "─" * 74
    print(f"{bar}\nThreadLink benchmark · {args.rows} route rows "
          f"({len(frame)} B/frame) · {args.iterations} iterations\n{bar}")

    # warm both stacks so we time steady state, not first-call import cost
    await quic_once(payload)
    await tcp_once(frame)

    q_hs, q_tot, t_tot = [], [], []
    for _ in range(args.iterations):
        hs, tot = await quic_once(payload)
        q_hs.append(hs)
        q_tot.append(tot)
        t_tot.append(await tcp_once(frame))

    def stat(xs):
        return {"median": statistics.median(xs),
                "p95": sorted(xs)[max(0, int(len(xs) * 0.95) - 1)],
                "mean": statistics.mean(xs)}

    q, t = stat(q_tot), stat(t_tot)
    qh = stat(q_hs)

    print("\nMEASURED on loopback (RTT ≈ 0.05 ms — crypto CPU cost dominates)")
    print(f"  {'':22s} {'median':>10s} {'p95':>10s}")
    print(f"  {'QUIC handshake':22s} {qh['median']:>9.2f}m {qh['p95']:>9.2f}m")
    print(f"  {'QUIC connect+exchange':22s} {q['median']:>9.2f}m {q['p95']:>9.2f}m")
    print(f"  {'TCP+TLS1.3 same':22s} {t['median']:>9.2f}m {t['p95']:>9.2f}m")
    delta = t["median"] - q["median"]
    verdict = "QUIC faster" if delta > 0 else "TCP faster (loopback: no RTT to save)"
    print(f"  {'difference':22s} {delta:>+9.2f}m   {verdict}")

    print(f"\nPROJECTED to a {args.rtt:.0f} ms network (round trips × RTT — arithmetic)")
    print(f"  {'':22s} {'RTTs':>6s} {'setup':>10s}")
    for name, rtts in RTT_COST.items():
        print(f"  {name:22s} {rtts:>6d} {rtts * args.rtt:>9.1f}m")
    saved = (RTT_COST["tcp_tls13"] - RTT_COST["quic"]) * args.rtt
    print(f"\n  QUIC saves {saved:.0f} ms of setup per connection at {args.rtt:.0f} ms RTT,")
    print(f"  and {RTT_COST['tcp_tls13'] * args.rtt:.0f} ms on a resumed (0-RTT) connection.")

    conc = await quic_concurrent(payload, args.concurrent)
    print(f"\nCONCURRENT STREAMS · {args.concurrent} exchanges on ONE connection")
    print(f"  total {conc:.2f} ms  ({conc / args.concurrent:.2f} ms each)")
    print(f"  Each rides its own QUIC stream. Over TCP these share one byte pipe,")
    print(f"  so a loss in front of the queue stalls every one behind it.")

    print(f"\n{bar}")
    print("HONEST READING: on loopback QUIC's round-trip advantage is worth ~0.05 ms")
    print("and the crypto cost is real, so the MEASURED column can favour TCP. The")
    print("advantage is in round trips, and it grows with distance — which is exactly")
    print("the regime a distributed agent swarm lives in.")
    print("")
    print("AND ONE MORE THING WE ARE NOT HIDING: this compares a PURE-PYTHON QUIC")
    print("stack (aioquic) against TCP+TLS handled by OpenSSL in C. Most of the gap")
    print("above is our connection setup burning CPU in Python, not QUIC being slow —")
    print(f"note that {args.concurrent} concurrent exchanges cost "
          f"{conc / args.concurrent:.2f} ms each once the")
    print("connection exists. If ThreadLink ever needs the last word on throughput,")
    print("the move is a Rust/C QUIC core (quiche, msquic), not a change of protocol.")
    print(bar)

    if args.json:
        print(json.dumps({
            "rows": args.rows, "frame_bytes": len(frame),
            "iterations": args.iterations,
            "measured_ms": {"quic_handshake": qh, "quic_total": q, "tcp_total": t},
            "rtt_cost": RTT_COST,
            "projected_rtt_ms": args.rtt,
            "concurrent": {"n": args.concurrent, "total_ms": conc},
        }, indent=2))

    qserver.close()
    tserver.close()


if __name__ == "__main__":
    asyncio.run(main())
