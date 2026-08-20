"""
ThreadLink wire format — framing only.

Deliberately dumb. This module knows how to turn a (type, dict) pair into bytes
and back, and NOTHING about agents, routers or FabricPC. That separation is the
whole point: ThreadLink is a comlink any agent swarm can use, and "Hello" is one
application that happens to ride on it.

FRAME LAYOUT (10-byte header, big-endian):

    0        4     5      6                10
    +--------+-----+------+----------------+-----------------+
    | 'TL01' | typ | flag | length (uint32)|  body (JSON)    |
    +--------+-----+------+----------------+-----------------+

  magic   4B  'TL01' — catches a mis-wired stream immediately instead of
                       feeding garbage to json.loads.
  typ     1B  message type — opaque to the transport; the riding protocol defines it
  flag    1B  reserved (0). Bit 0 will mean "body is compressed" once route
              tables get big enough to be worth it; unused bits stay zero so an
              old peer can reject a frame it cannot understand.
  length  4B  body length, capped at MAX_BODY so a hostile or buggy peer can't
              make us allocate a gigabyte.
  body    JSON, UTF-8.

Why JSON and not msgpack/CBOR: at sprint scale the bodies are small (a route
batch is a few hundred floats) and being able to read a decoded frame during a
live demo is worth more than the bytes. The flag byte is where compression goes
when that stops being true — the header does not have to change.

One frame is one message. Framing still matters even though QUIC gives us
reliable ordered streams, because a stream is a byte pipe: reads arrive in
arbitrary chunks and two messages can land in one read.
"""

from __future__ import annotations

import json
import struct
from enum import IntEnum
from typing import Any, Iterator

MAGIC = b"TL01"
HEADER = struct.Struct(">4sBBI")   # magic, type, flags, length
HEADER_LEN = HEADER.size           # 10

# A single frame is capped well below QUIC's flow-control window. Route batches
# are chunked by the sender rather than sent as one enormous frame, so a slow
# peer never has to buffer more than this before it can act.
MAX_BODY = 4 * 1024 * 1024         # 4 MiB

class Control(IntEnum):
    """The few message types the TRANSPORT itself owns.

    Everything else in the 0x00-0xFF type space belongs to whatever protocol
    rides on ThreadLink — the transport carries the byte, it does not interpret
    it. (ThreadHello, for example, claims 0x01-0x04 for its handshake and route
    exchange, and ThreadLink neither knows nor cares.)
    """

    PING = 0x05         # Liveness / latency probe.
    PONG = 0x06
    BYE = 0x07          # Graceful goodbye; peer may drop state.
    ERROR = 0x7F        # Handler failure, reported instead of a dead stream.


class WireError(Exception):
    """Malformed frame. Always fatal for the stream it arrived on."""


def encode(msg_type: int, body: dict[str, Any], flags: int = 0) -> bytes:
    """Serialize one message to a single frame.

    `msg_type` is any application-chosen value 0x00-0xFF (IntEnum members
    work as-is). The transport does not interpret it.
    """
    if not 0 <= int(msg_type) <= 0xFF:
        raise WireError(f"message type {msg_type!r} does not fit one byte")
    payload = json.dumps(body, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(payload) > MAX_BODY:
        raise WireError(f"body {len(payload)}B exceeds MAX_BODY {MAX_BODY}B")
    return HEADER.pack(MAGIC, int(msg_type), flags, len(payload)) + payload


def decode(frame: bytes) -> tuple[int, dict[str, Any]]:
    """Parse exactly one complete frame. Use FrameReader for stream input.

    The type byte is returned as a plain int; dispatching it against a
    protocol's own enum is the application's job (IntEnum == int compares
    fine). An unknown type is NOT a wire error — an old peer must be able to
    answer "unhandled" instead of tearing the stream down.
    """
    if len(frame) < HEADER_LEN:
        raise WireError("frame shorter than header")
    magic, typ, _flags, length = HEADER.unpack(frame[:HEADER_LEN])
    if magic != MAGIC:
        raise WireError(f"bad magic {magic!r} — not a ThreadLink stream")
    if len(frame) != HEADER_LEN + length:
        raise WireError("frame length does not match header")
    try:
        body = json.loads(frame[HEADER_LEN:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WireError(f"undecodable body: {exc}") from exc
    if not isinstance(body, dict):
        raise WireError("body must be a JSON object")
    return typ, body


class FrameReader:
    """Accumulates stream bytes and yields whole messages as they complete.

    QUIC hands us arbitrary chunks. Feed everything here; iterate what comes
    out. One reader per stream — never share one across streams, or two
    interleaved messages will be spliced into nonsense.
    """

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> Iterator[tuple[int, dict[str, Any]]]:
        self._buf.extend(data)
        while True:
            if len(self._buf) < HEADER_LEN:
                return
            magic, typ, _flags, length = HEADER.unpack(self._buf[:HEADER_LEN])
            if magic != MAGIC:
                raise WireError(f"bad magic {magic!r} — not a ThreadLink stream")
            if length > MAX_BODY:
                raise WireError(f"declared body {length}B exceeds MAX_BODY")
            total = HEADER_LEN + length
            if len(self._buf) < total:
                return                      # partial message; wait for more
            frame = bytes(self._buf[:total])
            del self._buf[:total]
            yield decode(frame)

    @property
    def pending(self) -> int:
        """Bytes buffered but not yet a complete frame (useful in tests)."""
        return len(self._buf)
