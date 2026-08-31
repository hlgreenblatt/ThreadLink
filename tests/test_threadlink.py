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
    Control, ThreadLinkError, FrameReader, LinkError, WireError,
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
        ccert, ckey = ensure_cert(d, "cli", ["127.0.0.1"])  # client's own identity

        PROTO = "test/1"

        async def handle(msg_type, body, peer):
            if msg_type == ECHO:
                return ECHO, {"echo": body}
            if msg_type == BOOM:
                raise RuntimeError("handler exploded on purpose")
            return Control.ERROR, {"error": "unhandled", "detail": type_name(msg_type)}

        server = await listen({PROTO: handle}, "127.0.0.1", 4455,
                              certfile=cert, keyfile=key)

        # ThreadLink is mutually authenticated: an anonymous client (no cert) MUST
        # be rejected before it can exchange any message. The listener aborts the
        # handshake with a native TLS certificate_required alert.
        try:
            async with await dial("127.0.0.1", 4455,
                                  config=client_config(), timeout=3) as anon:
                await anon.ping()
            check("anonymous client rejected (mutual auth)", False)
        except LinkError as exc:
            check("anonymous client rejected (mutual auth)", True)
            check("close reason names mutual authentication",
                  "mutual authentication" in str(exc))

        async with await dial("127.0.0.1", 4455,
                              config=client_config(certfile=ccert, keyfile=ckey)) as peer:
            check("handshake completed", peer.handshake_ms is not None)

            _t, body = await peer.request(PROTO, ECHO, {"msg": "over QUIC"})
            check("app message round-trips over QUIC",
                  _t == ECHO and body["echo"]["msg"] == "over QUIC")

            # A handler exception must come back as ERROR, not kill the link.
            _t, err = await peer.request(PROTO, BOOM, {})
            check("handler exception reported as ERROR frame",
                  _t == Control.ERROR and err.get("error") == "RuntimeError")
            _t, again = await peer.request(PROTO, ECHO, {"msg": "still alive"})
            check("connection survives a handler crash",
                  again["echo"]["msg"] == "still alive")

            # A type the server never heard of gets a clean refusal.
            _t, unk = await peer.request(PROTO, 0x66, {})
            check("unknown type answered, not hung",
                  _t == Control.ERROR and unk.get("error") == "unhandled")

            # Liveness on the control stream: many PINGs correlate by id.
            pongs = await asyncio.gather(*[peer.ping() for _ in range(12)])
            check("12 control-stream pings all answered",
                  len(pongs) == 12 and all("id" in p for p in pongs))
            check("ping ids are distinct",
                  len({p["id"] for p in pongs}) == 12)

            # Concurrency on data streams: 12 exchanges in flight at once.
            out = await asyncio.gather(*[
                peer.request(PROTO, ECHO, {"n": i}) for i in range(12)
            ])
            check("12 concurrent data streams all answered",
                  len(out) == 12 and all(m == ECHO for m, _ in out))
            check("replies matched to their own streams",
                  sorted(b["echo"]["n"] for _, b in out) == list(range(12)))

            before = peer.peer_connection_id
            after = peer.migrate()
            _t, post = await peer.request(PROTO, ECHO, {"msg": "after the move"})
            check("connection id rotated", before != after and len(after) > 0)
            check("session survived migration",
                  post["echo"]["msg"] == "after the move")

            await peer.bye("cli")   # control stream; nothing to await

        server.close()

    # A stream that BINDs to an unregistered riding protocol is refused.
    with tempfile.TemporaryDirectory() as d:
        cert, key = ensure_cert(d, "srv", ["127.0.0.1"])
        ccert, ckey = ensure_cert(d, "cli", ["127.0.0.1"])

        async def echo(msg_type, body, peer):
            return msg_type, body

        server = await listen({"known/1": echo}, "127.0.0.1", 4457,
                              certfile=cert, keyfile=key)
        async with await dial("127.0.0.1", 4457,
                              config=client_config(certfile=ccert, keyfile=ckey)) as peer:
            try:
                await peer.request("unknown/9", 0x20, {}, timeout=3)
                check("unknown riding protocol refused", False)
            except LinkError:
                check("unknown riding protocol refused", True)
            # the connection still works for a known protocol afterward
            _t, b = await peer.request("known/1", 0x20, {"ok": 1})
            check("connection survives an unknown-proto refusal", b.get("ok") == 1)
        server.close()

    # One listener hosting TWO riding protocols; streams self-sort by BIND.
    with tempfile.TemporaryDirectory() as d:
        cert, key = ensure_cert(d, "srv", ["127.0.0.1"])
        ccert, ckey = ensure_cert(d, "cli", ["127.0.0.1"])

        async def alpha(mt, body, peer):
            return mt, {"who": "alpha", **body}

        async def beta(mt, body, peer):
            return mt, {"who": "beta", **body}

        server = await listen({"alpha/1": alpha, "beta/1": beta},
                              "127.0.0.1", 4458, certfile=cert, keyfile=key)
        async with await dial("127.0.0.1", 4458,
                              config=client_config(certfile=ccert, keyfile=ckey)) as peer:
            _t, a = await peer.request("alpha/1", 0x30, {"x": 1})
            _t, b = await peer.request("beta/1", 0x30, {"x": 2})
            check("stream bound to alpha routed to alpha handler", a.get("who") == "alpha")
            check("stream bound to beta routed to beta handler", b.get("who") == "beta")
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
