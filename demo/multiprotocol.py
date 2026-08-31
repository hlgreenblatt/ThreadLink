#!/usr/bin/env python3
"""One ThreadLink listener, two riding protocols, streams self-sorting by BIND.

Before BIND, ThreadHello and ThreadChat could only share a connection by
hand-partitioning the type byte (0x01-0x0A vs 0x10-0x13). Now each data stream
opens with a BIND frame naming its riding protocol, so a single listener can host
BOTH and route each stream to the right handler with no global type registry and
no risk of collision — ThreadHello's 0x01 (HELLO) and a hypothetical ThreadChat
0x01 would never be confused, because the stream says which protocol it carries.

Run:  python demo/multiprotocol.py
"""
import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path.home() / "build/ThreadLink"))
sys.path.insert(0, str(Path.home() / "build/ThreadRouter"))
sys.path.insert(0, str(Path.home() / "build/ThreadChat"))

from threadlink import ensure_cert, dial, listen
from threadlink.link import client_config
from threadhello import HelloAgent, HelloMsg, RouteStore, THREADHELLO
from threadchat import ChatNode, ChatMsg, THREADCHAT

PORT = 4468


async def main() -> None:
    d = tempfile.mkdtemp()
    scert, skey = ensure_cert(d, "hub", ["127.0.0.1"])
    ccert, ckey = ensure_cert(d, "client", ["127.0.0.1"])

    # A router agent and a chat node, both fronted by ONE listener.
    hello = HelloAgent("hub", RouteStore("hub"), {"local_chat", "cloud_free"})
    hello.store.observe([1, 1, 1, 0.5, 1, 0, 0, 0], "local_chat",
                        {"completed": 1.0, "format_valid": 1.0, "task_fit": 1.0,
                         "privacy": 1.0, "cost": 0.0, "latency": 1.0})
    chat_inbox = []
    chat = ChatNode("hub", lambda letter: chat_inbox.append(letter))

    # The registry: two riding protocols on one connection. A stream's BIND frame
    # picks the handler.
    server = await listen(
        {THREADHELLO: hello.handle, THREADCHAT: chat.handle},
        "127.0.0.1", PORT, certfile=str(scert), keyfile=str(skey))
    print(f"hub listening on 127.0.0.1:{PORT} — hosting {THREADHELLO} AND {THREADCHAT}")
    await asyncio.sleep(0.2)

    async with await dial("127.0.0.1", PORT,
                          config=client_config(certfile=str(ccert), keyfile=str(ckey))) as peer:
        # Stream 1: a ThreadHello route request.
        _t, table = await peer.request(THREADHELLO, HelloMsg.ROUTE_REQ,
                                       {"since": 0, "limit": 10})
        rows = table.get("rows") or []
        print(f"  [threadhello/1] ROUTE_REQ -> {len(rows)} route row(s)")

        # Stream 2: a ThreadChat message — SAME connection, different protocol.
        _t, ack = await peer.request(THREADCHAT, ChatMsg.CHAT_MSG, {
            "from": "client", "to": "hub", "text": "hello over the same link",
            "msg_id": "m1", "ts": 0, "proto": 1})
        print(f"  [threadchat/1]  CHAT_MSG -> ack by {ack.get('by')}, "
              f"inbox now {len(chat_inbox)}")

        # Control plane: liveness on the connection's control stream.
        pong = await peer.ping()
        print(f"  [control]       PING -> PONG id={pong.get('id')}")

    server.close()
    ok = rows and ack.get("by") == "hub" and chat_inbox
    print("RESULT:", "PASS — two protocols, one link, self-sorted by BIND" if ok else "FAIL")


if __name__ == "__main__":
    asyncio.run(main())
