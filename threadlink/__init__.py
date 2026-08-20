"""ThreadLink — a QUIC comlink for agent swarms.

Transport only: framed messages over QUIC (RFC 9000) + TLS 1.3, point to
point, multiple independent streams per connection. Protocols ride on top —
ThreadHello (route-table gossip for ThreadRouter agents) is the first, and
lives with ThreadRouter, not here.
"""

from .wire import Control, MAX_BODY, encode, decode, FrameReader, WireError
from .link import dial, listen, Peer, LinkError, type_name, ALPN, DEFAULT_PORT
from .certs import ensure_cert, spki_pin

__version__ = "0.2.0"
__all__ = [
    "Control", "MAX_BODY", "encode", "decode", "FrameReader", "WireError",
    "dial", "listen", "Peer", "LinkError", "type_name", "ALPN", "DEFAULT_PORT",
    "ensure_cert", "spki_pin",
]
