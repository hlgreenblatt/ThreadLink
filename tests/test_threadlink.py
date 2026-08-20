#!/usr/bin/env python3
"""
ThreadLink transport tests — framing, certificates, and the live QUIC link.

Everything here is transport. The protocols that ride on ThreadLink (e.g.
ThreadHello in the ThreadRouter repo) bring their own suites; the handler used
below is a deliberately dumb echo app defined inside the test, which is itself
a check that the transport carries a protocol it has never heard of.

Run:  .venv/bin/python tests/test_threadlink.py
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadlink import (                                    # noqa: E402
    Control, FrameReader, LinkError, WireError,
    decode, encode, ensure_cert, spki_pin, type_name,
)
from threadlink.link import client_config, dial, listen     # noqa: E402

PASS, FAIL = [], []

# The test's own application protocol — unknown to the transport on purpose.
ECHO = 0x21
BOOM = 0x22


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  {'✓' if cond else '✗'} {name}{'  — ' + detail if detail and not cond else ''}")


# ---------------------------------------------------------------- wire
def test_wire() -> None:
    print("\nwire format")
    t, b = decode(encode(ECHO, {"a": 1, "s": "héllo"}))
    check("round-trips type and unicode body", t == ECHO and b["s"] == "héllo")

    t, _ = decode(encode(Control.PING, {}))
    check("enum types compare as ints", t == Control.PING == 0x05)

    t, _ = decode(encode(0xEE, {}))
    check("unknown app type passes through untouched", t == 0xEE)

    try:
        encode(300, {})
        check("type wider than one byte rejected", False)
    except WireError:
        check("type wider than one byte rejected", True)

    # A frame split at every possible boundary must still reassemble.
    frame = encode(ECHO, {"rows": [{"x": 1}] * 5})
    ok = True
    for cut in range(1, len(frame)):
        r = FrameReader()
        got = list(r.feed(frame[:cut])) + list(r.feed(frame[cut:]))
        if len(got) != 1 or got[0][0] != ECHO:
            ok = False
            break
    check("reassembles across every split point", ok)

    r = FrameReader()
    many = b"".join(encode(Control.PING, {"i": i}) for i in range(5))
    check("yields 5 messages from one read", len(list(r.feed(many))) == 5)

    try:
        decode(b"XXXX" + b"\x00" * 6)
        check("rejects bad magic", False)
    except WireError:
        check("rejects bad magic", True)

    try:
        list(FrameReader().feed(b"NOPE" + b"\x00" * 20))
        check("reader rejects bad magic", False)
    except WireError:
        check("reader rejects bad magic", True)

    check("type_name uses enum name when there is one",
          type_name(Control.BYE) == "BYE" and type_name(0x21) == "0x21")


# -------------------------------------------------------------- certs
def test_certs() -> None:
    print("\ncertificates")
    with tempfile.TemporaryDirectory() as d:
        c1, k1 = ensure_cert(d, "agent_x", ["127.0.0.1"])
        check("cert and key created", Path(c1).exists() and Path(k1).exists())
        check("key is not world readable", (Path(k1).stat().st_mode & 0o077) == 0)
        c2, _ = ensure_cert(d, "agent_x")
        check("regeneration is idempotent", c1 == c2)
        pin = spki_pin(c1)
        check("spki pin is stable", pin == spki_pin(c1) and len(pin) > 20)
        c3, _ = ensure_cert(d, "agent_y")
        check("different agents get different pins", spki_pin(c3) != pin)


# ------------------------------------------------------------ live QUIC
async def test_live() -> None:
    print("\nlive QUIC round trip")
    with tempfile.TemporaryDirectory() as d:
        cert, key = ensure_cert(d, "srv", ["127.0.0.1"])

        async def handle(msg_type, body, peer):
            if msg_type == ECHO:
                return ECHO, {"echo": body}
            if msg_type == Control.PING:
                return Control.PONG, {"t": body.get("t")}
            if msg_type == BOOM:
                raise RuntimeError("handler exploded on purpose")
            if msg_type == Control.BYE:
                return None
            return Control.ERROR, {"error": "unhandled", "detail": type_name(msg_type)}

        server = await listen(handle, "127.0.0.1", 4455, certfile=cert, keyfile=key)

        async with await dial("127.0.0.1", 4455, config=client_config()) as peer:
            check("handshake completed", peer.handshake_ms is not None)

            _t, body = await peer.request(ECHO, {"msg": "over QUIC"})
            check("app message round-trips over QUIC",
                  _t == ECHO and body["echo"]["msg"] == "over QUIC")

            # A handler exception must come back as ERROR, not kill the link.
            _t, err = await peer.request(BOOM, {})
            check("handler exception reported as ERROR frame",
                  _t == Control.ERROR and err.get("error") == "RuntimeError")
            _t, again = await peer.request(ECHO, {"msg": "still alive"})
            check("connection survives a handler crash",
                  again["echo"]["msg"] == "still alive")

            # A type the server never heard of gets a clean refusal.
            _t, unk = await peer.request(0x66, {})
            check("unknown type answered, not hung",
                  _t == Control.ERROR and unk.get("error") == "unhandled")

            # Concurrency: 12 exchanges in flight on one connection.
            out = await asyncio.gather(*[
                peer.request(Control.PING, {"t": i}) for i in range(12)
            ])
            check("12 concurrent streams all answered",
                  len(out) == 12 and all(m == Control.PONG for m, _ in out))
            check("replies matched to their own streams",
                  sorted(b["t"] for _, b in out) == list(range(12)))

            before = peer.peer_connection_id
            after = peer.migrate()
            _t, post = await peer.request(ECHO, {"msg": "after the move"})
            check("connection id rotated", before != after and len(after) > 0)
            check("session survived migration",
                  post["echo"]["msg"] == "after the move")

            await peer.send(Control.BYE, {})   # one-way; nothing to await

        server.close()

    # A dial to a dead port must fail with LinkError, not hang forever.
    try:
        async with await dial("127.0.0.1", 4499,
                              config=client_config(), timeout=1.5):
            pass
        check("dead peer raises LinkError", False)
    except LinkError:
        check("dead peer raises LinkError", True)
    except Exception as exc:
        check("dead peer raises LinkError", False, type(exc).__name__)


def main() -> int:
    print("═" * 60)
    print("ThreadLink transport test suite")
    print("═" * 60)
    test_wire()
    test_certs()
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
