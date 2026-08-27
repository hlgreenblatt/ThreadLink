#!/usr/bin/env python3
"""ThreadChat protocol tests — real QUIC on loopback, fake agent sinks.

Proves the wire behaviour without any OmegaClaw present: a letter reaches the
recipient, an ack comes back, a group message fans out with one msg_id, dedup
holds, and a reply routes to the original asker. Mirrors test_threadhello.py.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadlink import ensure_cert
from threadchat import ChatNode, ChatMsg, CHAT_VERSION

CERTS = Path(__file__).resolve().parent.parent / "certs"
ok = fail = 0


def check(cond, label):
    global ok, fail
    if cond:
        ok += 1
        print(f"  ✓ {label}")
    else:
        fail += 1
        print(f"  ✗ {label}")


async def serve(node, port):
    cert, key = ensure_cert(CERTS, node.agent_id)
    return await node.serve("127.0.0.1", port, certfile=str(cert), keyfile=str(key))


async def main():
    # three fake agents: each records what it was handed
    inbox = {"A": [], "B": [], "C": []}

    def sink(name):
        return lambda letter: inbox[name].append(letter)

    A = ChatNode("A", sink("A"), directory={
        "B": ("127.0.0.1", 4471), "C": ("127.0.0.1", 4472)})
    B = ChatNode("B", sink("B"), directory={
        "A": ("127.0.0.1", 4470), "C": ("127.0.0.1", 4472)})
    C = ChatNode("C", sink("C"), directory={
        "A": ("127.0.0.1", 4470), "B": ("127.0.0.1", 4471)})

    await serve(A, 4470)
    await serve(B, 4471)
    await serve(C, 4472)
    await asyncio.sleep(0.3)

    # 1. A -> B direct letter
    res = await A.send_to("B", "what is your primary model?", msg_id="m1")
    await asyncio.sleep(0.1)
    check(len(inbox["B"]) == 1, "direct letter reached B")
    check(inbox["B"][0]["text"] == "what is your primary model?", "text intact")
    check(inbox["B"][0]["from"] == "A", "sender attributed")
    check(res["ack"].get("by") == "B", "ack came back from B")

    # 2. B replies to A (in_reply_to)
    await B.send_to("A", "qwen3.8-27b", msg_id="m1r", in_reply_to="m1")
    await asyncio.sleep(0.1)
    check(inbox["A"] and inbox["A"][-1]["text"] == "qwen3.8-27b", "reply reached A")
    check(inbox["A"][-1]["in_reply_to"] == "m1", "reply carries in_reply_to")

    # 3. dedup: same msg_id twice -> delivered once
    await A.send_to("C", "hello", msg_id="dup1")
    await A.send_to("C", "hello", msg_id="dup1")
    await asyncio.sleep(0.1)
    check(len(inbox["C"]) == 1, "duplicate msg_id delivered only once")

    # 4. group broadcast: one msg_id to all, each gets it once
    inbox["B"].clear(); inbox["C"].clear()
    results = await A.broadcast("standup in 5", msg_id="grp1")
    await asyncio.sleep(0.1)
    check(len(inbox["B"]) == 1 and len(inbox["C"]) == 1, "group message reached B and C")
    check(inbox["B"][0]["msg_id"] == "grp1" and inbox["C"][0]["msg_id"] == "grp1",
          "group message shares one msg_id")
    check(all("error" not in r for r in results), "broadcast reported no errors")

    # 5. proto version guard
    bad = ChatNode("X", sink("A"))
    reply = await bad.handle(ChatMsg.CHAT_MSG, {"proto": 999, "msg_id": "x"}, None)
    check(reply and reply[1].get("error") == "proto_mismatch", "version mismatch refused")

    print("\n" + "=" * 60)
    print(f"{ok} passed, {fail} failed")
    print("=" * 60)
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    asyncio.run(main())
