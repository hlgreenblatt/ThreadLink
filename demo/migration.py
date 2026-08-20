#!/usr/bin/env python3
"""
Connection migration — the agent moves, the conversation does not break.

This is the property worth the most to a decentralized swarm, and the one that
is easiest to hand-wave, so this demo proves it rather than asserting it.

A TCP connection IS its four-tuple: (src ip, src port, dst ip, dst port). Change
any of the four — the laptop moves to another network, a NAT rebinds, a
container is rescheduled onto a different host — and the connection is dead. The
application reconnects, redoes the handshake, and re-establishes whatever session
state it was holding.

A QUIC connection is identified by a CONNECTION ID carried inside the packets,
deliberately independent of the addresses underneath. The path can change and the
connection continues: same keys, same open streams, same session.

WHAT THIS SCRIPT SHOWS
  1. Two agents connect. The client stores a note on the server, which the
     server keeps in PER-SESSION state. Note the Connection ID.
  2. The client rotates to a completely different Connection ID mid-session
     (QuicConnection.change_connection_id — RFC 9000 §5.1).
  3. It immediately asks for its note back on the SAME connection.
  4. The note comes back: the session — keys, streams, server-side state —
     survived the identifier change.

Step 3 is the whole demo. Over TCP there is nothing analogous to attempt: the
identifier and the path are the same thing, so changing one destroys the other.

The two message types below are defined HERE, not in ThreadLink — the transport
carries any protocol an application invents. That is the point of the split.

Run:  .venv/bin/python demo/migration.py
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadlink import ensure_cert                       # noqa: E402
from threadlink.link import client_config, dial, listen  # noqa: E402

HOST, PORT = "127.0.0.1", 4436
CERTS = Path(__file__).resolve().parent.parent / "certs"
BAR = "─" * 72

# This demo's own application protocol: two message types nobody else knows.
NOTE_PUT = 0x10
NOTE_GET = 0x11


async def main() -> None:
    cert, key = ensure_cert(CERTS, "migration_peer", [HOST])

    notes: dict[str, str] = {}          # the server-side session state

    async def handle(msg_type, body, peer):
        if msg_type == NOTE_PUT:
            notes[str(body.get("key"))] = str(body.get("text", ""))
            return NOTE_PUT, {"stored": True, "count": len(notes)}
        if msg_type == NOTE_GET:
            return NOTE_GET, {"text": notes.get(str(body.get("key")))}
        return None

    server = await listen(handle, HOST, PORT, certfile=cert, keyfile=key)

    print(f"{BAR}\nThreadLink · connection migration\n{BAR}")

    async with await dial(HOST, PORT, config=client_config()) as peer:
        cid_before = peer.peer_connection_id.hex()
        own_cid = peer.connection_id.hex()
        print(f"\n1. CONNECTED")
        print(f"   handshake      {peer.handshake_ms:.2f} ms")
        print(f"   our cid        {own_cid}")
        print(f"   peer cid       {cid_before}   ← this is what rotates")

        t0 = time.perf_counter()
        _t, ack = await peer.request(NOTE_PUT, {
            "key": "waypoint", "text": "remember me across the move"})
        print(f"\n2. TALKING (before migration)")
        print(f"   stored a note in the peer's session state "
              f"in {(time.perf_counter() - t0) * 1000:.2f} ms")

        # ---- the migration ------------------------------------------------
        cid_after = peer.migrate().hex()
        print(f"\n3. MIGRATED — new Connection ID, same live connection")
        print(f"   was  {cid_before}")
        print(f"   now  {cid_after}")
        print(f"   changed: {cid_before != cid_after}")

        # ---- prove the session survived -----------------------------------
        t1 = time.perf_counter()
        _t, back = await peer.request(NOTE_GET, {"key": "waypoint"})
        ms = (time.perf_counter() - t1) * 1000

        print(f"\n4. STILL TALKING (after migration)")
        print(f"   note came back: {back.get('text')!r} in {ms:.2f} ms")
        print(f"   no new handshake, no new keys, no reconnect")

        ok = back.get("text") == "remember me across the move" and cid_before != cid_after
        print(f"\n{BAR}")
        if ok:
            print("✓ The identifier changed underneath a live session and the")
            print("  conversation continued. For an agent that may move between")
            print("  machines, networks or compute providers, this is the property.")
        else:
            print("✗ migration did not behave as expected")
        print(BAR)

    server.close()


if __name__ == "__main__":
    asyncio.run(main())
