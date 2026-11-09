#!/usr/bin/env python3
"""ThreadChat protocol tests — real QUIC on loopback, fake agent sinks.

Proves the wire behaviour without any OmegaClaw present: a letter reaches the
recipient, an ack comes back, a group message fans out with one msg_id, dedup
holds, and a reply routes to the original asker. Mirrors test_threadhello.py.
"""

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadlink import ensure_cert
from threadchat import ChatNode, ChatMsg, CHAT_VERSION, watch_stamp

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
        "B": ("127.0.0.1", 5471), "C": ("127.0.0.1", 5472)})
    B = ChatNode("B", sink("B"), directory={
        "A": ("127.0.0.1", 5470), "C": ("127.0.0.1", 5472)})
    C = ChatNode("C", sink("C"), directory={
        "A": ("127.0.0.1", 5470), "B": ("127.0.0.1", 5471)})

    await serve(A, 5470)
    await serve(B, 5471)
    await serve(C, 5472)
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

    # 6. sender pins: "from" is self-asserted, so a pinned node checks the key
    from threadlink import spki_pin
    pins = {"A": spki_pin(ensure_cert(CERTS, "A")[0])}
    inbox["P"] = []
    P = ChatNode("P", sink("P"), pins=pins, strict=True)
    await serve(P, 5473)
    await asyncio.sleep(0.2)
    await A.send_to("P", "real A", msg_id="p1", host="127.0.0.1", port=5473)
    await asyncio.sleep(0.1)
    check([l["text"] for l in inbox["P"]] == ["real A"], "pinned sender with its own key accepted")
    forger = ChatNode("A", sink("C"))              # says "A" but holds C's key
    cc, ck = ensure_cert(CERTS, "C")
    forger._certfile, forger._keyfile = str(cc), str(ck)
    r = await forger.send_to("P", "forged", msg_id="p2", host="127.0.0.1", port=5473)
    forged_err = str(r["ack"].get("error"))
    await asyncio.sleep(0.1)
    check(len(inbox["P"]) == 1, "forged sender (wrong key) not delivered")
    check(forged_err == "sender_key_mismatch", "forged sender told sender_key_mismatch")
    r = await B.send_to("P", "unpinned", msg_id="p3", host="127.0.0.1", port=5473)
    strict_err = str(r["ack"].get("error"))
    await asyncio.sleep(0.1)
    check(len(inbox["P"]) == 1 and strict_err == "unknown_sender",
          "strict node refuses a sender with no pin")

    # watch: a node with watch on hands its agent the real UTC time first (Captain 2026-11-08)
    inbox["W"] = []
    W = ChatNode("W", sink("W"), watch=True)
    await serve(W, 5474)
    await asyncio.sleep(0.3)
    await A.send_to("W", "what time is it?", msg_id="w1", host="127.0.0.1", port=5474)
    await asyncio.sleep(0.1)
    got = inbox["W"][0] if inbox["W"] else {}
    first, _, rest = str(got.get("text", "")).partition("\n")
    check(first.startswith("⌚ ") and "Z · unix " in first and " · sent " in first,
          "watch node: first line is the UTC stamp with the sender's time")
    check(rest == "what time is it?", "watch node: the letter itself follows intact")
    check(abs(float(got.get("delivered_ts", 0)) - time.time()) < 5 and got.get("watch") == first,
          "watch node: delivered_ts + watch fields carried for the adapter")
    check(watch_stamp(None, 0).startswith("⌚ 1970-01-01T00:00:00Z · unix 0"), "the epoch reads as the epoch")

    print("\n" + "=" * 60)
    print(f"{ok} passed, {fail} failed")
    print("=" * 60)
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    asyncio.run(main())
