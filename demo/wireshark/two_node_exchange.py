#!/usr/bin/env python3
"""One process, two ThreadHello nodes, one real QUIC exchange on loopback —
built to be captured. Server on 4455, client dials it, they trade route tables,
then both exit cleanly so the pcap has a complete handshake + app data + close.

Run with SSLKEYLOGFILE set so the TLS secrets are written for Wireshark.
"""
import asyncio
import sys
from pathlib import Path

REPO = Path("/home/maxquasar/build/ThreadRouter")
sys.path.insert(0, str(REPO))

from threadlink import ensure_cert
from threadhello import HelloAgent, RouteStore

CERTS = REPO / "certs"
PORT = 4455


async def main():
    # server side
    scert, skey = ensure_cert(CERTS, "capture_server")
    sstore = RouteStore("capture_server")
    # give the server something to hand over, so ROUTE_TABLE frames carry payload
    sstore.observe([1.0, 1.0, 1.0, 0.5, 1.0, 0.0, 0.0, 0.0], "local_code",
                   {"completed": 1.0, "format_valid": 1.0, "task_fit": 1.0,
                    "privacy": 1.0, "cost": 0.0, "latency": 1.0})
    server = HelloAgent("capture_server", store=sstore,
                        known_paths={"local_code", "local_chat"})
    await server.serve("127.0.0.1", PORT, certfile=str(scert), keyfile=str(skey))

    # client side
    cstore = RouteStore("capture_client")
    client = HelloAgent("capture_client", store=cstore,
                        known_paths={"local_code", "local_chat"})
    await asyncio.sleep(0.3)  # let the listener settle before we capture the dial
    res = await client.sync_with("127.0.0.1", PORT)
    print("EXCHANGE OK:", {k: res[k] for k in ("peer", "handshake_ms", "pulled", "pushed")})
    await asyncio.sleep(0.3)  # let CONNECTION_CLOSE flush into the capture


if __name__ == "__main__":
    asyncio.run(main())
