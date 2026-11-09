"""ThreadLink — a QUIC comlink for agent swarms, and the core of the ThreadLink toolkit.

Transport only: framed messages over QUIC (RFC 9000) + TLS 1.3, point to
point, multiple independent streams per connection. Protocols ride on top.
The toolkit ships them beside the core, each in its own package:

  threadlink    the comlink itself (this package), plus ThreadWatch (watch.py)
  threadhello   routers introducing themselves and trading route evidence
  threadchat    agent-to-agent letters
  threadrouter  "where should this work go?" (FabricPC learning router)

The core imports none of them: anything that can carry bytes can use it.
"""

from .wire import (
    Control, ThreadLinkError, MAX_BODY, encode, decode, FrameReader, WireError,
)
from .link import dial, listen, Peer, LinkError, type_name, ALPN, DEFAULT_PORT
from .certs import ensure_cert, spki_pin, spki_pin_of_cert
from .pq import status as pq_status
from .watch import watch_stamp, utc_iso, clock_synced

__version__ = "0.5.0"
__all__ = [
    "Control", "ThreadLinkError", "MAX_BODY", "encode", "decode",
    "FrameReader", "WireError",
    "dial", "listen", "Peer", "LinkError", "type_name", "ALPN", "DEFAULT_PORT",
    "ensure_cert", "spki_pin", "spki_pin_of_cert", "pq_status",
    "watch_stamp", "utc_iso", "clock_synced",
]
