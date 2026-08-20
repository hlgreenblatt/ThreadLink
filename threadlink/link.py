"""
ThreadLink — a QUIC comlink for agents.

Transport only. This module moves framed messages between two processes over
QUIC (RFC 9000) with TLS 1.3, and knows nothing about OmegaClaw, ThreadRouter
or FabricPC. Anything that wants a fast encrypted agent-to-agent link can use
it; sharing route tables is just the first application we built on top.

WHY QUIC, CONCRETELY

  One round trip, not two. TCP needs a SYN/SYN-ACK/ACK before TLS 1.3 can even
  start its own round trip, so you pay 2 RTT before the first application byte
  (3 with TLS 1.2). QUIC folds the transport and crypto handshakes together:
  1 RTT cold, 0 RTT on resume. Encryption is not optional — there is no
  unencrypted QUIC to accidentally fall back to.

  Streams are independent. This is the part that matters most for a swarm and
  the part a benchmark rarely shows. A TCP connection is one byte pipe: if the
  segment carrying the front of a large route-table transfer is lost, every
  later byte — including a small urgent PING that was already delivered by the
  network — waits behind the retransmit. QUIC tracks loss per stream, so a
  stalled route table does not stall anything else. We lean on this by giving
  every exchange its own stream (see `request`), which means head-of-line
  isolation is structural here rather than something we have to remember.

  The connection outlives the path. A QUIC connection is identified by a
  Connection ID, not by the (src ip, src port, dst ip, dst port) four-tuple, so
  it survives NAT rebinding and network changes. For agents that may move
  between machines, networks and compute providers, that is the interesting
  property — see `migrate`.

CONCURRENCY MODEL

  Every request opens a fresh bidirectional stream, writes one frame, and
  half-closes. The peer replies on the same stream and half-closes in turn.
  One stream = one exchange, so requests are naturally concurrent and a slow
  reply cannot block a fast one. Stream ids are cheap; do not pool them.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Any, Awaitable, Callable, Optional

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    HandshakeCompleted,
    QuicEvent,
    StreamDataReceived,
    StreamReset,
)

from .wire import Control, FrameReader, WireError, encode

log = logging.getLogger("threadlink.link")

# ALPN identifies the application protocol inside the TLS handshake, so a
# ThreadLink peer and (say) an HTTP/3 peer refuse each other during the
# handshake instead of after exchanging confusing bytes.
ALPN = "threadlink/1"

# Default UDP port. 4433 is the conventional "QUIC/TLS demo" port and is easy
# to point Wireshark at: `udp port 4433`.
DEFAULT_PORT = 4433

# A handler takes (msg_type, body, peer) and returns the reply message, or None
# to close the stream without answering.
Handler = Callable[[int, dict[str, Any], "Peer"], Awaitable[Optional[tuple[int, dict[str, Any]]]]]


class LinkError(Exception):
    """Transport-level failure (handshake, timeout, reset)."""


def type_name(msg_type: int) -> str:
    """Readable form of a type byte for logs: enum name if it has one."""
    return getattr(msg_type, "name", None) or f"0x{int(msg_type):02X}"


class Peer:
    """The remote end of one ThreadLink connection.

    Wraps a live QUIC connection and exposes `request`, which is the only thing
    most callers need. Obtained from `dial()` or handed to a server handler.
    """

    def __init__(self, proto: "ThreadLinkProtocol") -> None:
        self._proto = proto

    async def request(
        self,
        msg_type: int,
        body: dict[str, Any],
        timeout: float = 20.0,
    ) -> tuple[int, dict[str, Any]]:
        """Send one message on a new stream; await the reply on that stream."""
        return await self._proto.request(msg_type, body, timeout=timeout)

    async def send(self, msg_type: int, body: dict[str, Any]) -> None:
        """Fire and forget on its own stream. No reply awaited (e.g. BYE)."""
        await self._proto.send_oneway(msg_type, body)

    def migrate(self) -> bytes:
        """Rotate to a fresh destination Connection ID on the live connection.

        The session, its keys and every open stream survive; only the identifier
        on the wire changes. This is the mechanism that lets a QUIC connection
        outlive a path change — exercised directly by demo/migration.py.

        Returns the new peer Connection ID.
        """
        return self._proto.migrate()

    @property
    def address(self) -> tuple[str, int]:
        return self._proto.peer_address

    @property
    def handshake_ms(self) -> Optional[float]:
        """Milliseconds from socket creation to HandshakeCompleted."""
        return self._proto.handshake_ms

    @property
    def connection_id(self) -> bytes:
        """Our own Connection ID."""
        return self._proto.connection_id

    @property
    def peer_connection_id(self) -> bytes:
        """The peer's Connection ID — the one that rotates on migration."""
        return self._proto.peer_connection_id


class ThreadLinkProtocol(QuicConnectionProtocol):
    """Frames ThreadLink messages onto QUIC streams.

    One FrameReader per stream. A stream is torn down as soon as its exchange
    completes, so the bookkeeping stays bounded no matter how long the
    connection lives.
    """

    def __init__(self, *args: Any, handler: Optional[Handler] = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._handler = handler
        self._readers: dict[int, FrameReader] = {}
        self._waiters: dict[int, asyncio.Future] = {}
        self._handshake = asyncio.Event()
        self._t0 = asyncio.get_event_loop().time()
        self.handshake_ms: Optional[float] = None
        self._peer = Peer(self)

    # ---------------------------------------------------------------- helpers
    @property
    def peer_address(self) -> tuple[str, int]:
        addr = self._quic._network_paths[0].addr if self._quic._network_paths else ("?", 0)
        return (addr[0], addr[1])

    @property
    def connection_id(self) -> bytes:
        """OUR Connection ID — what the peer writes on packets it sends us."""
        return bytes(self._quic.host_cid)

    @property
    def peer_connection_id(self) -> bytes:
        """THE PEER'S Connection ID — what we write on packets we send.

        This is the one that changes on migration. RFC 9000 §9.5: an endpoint
        moving to a new path switches to an unused destination CID so an
        on-path observer cannot trivially link the old path to the new one.

        Reaches into aioquic's `_peer_cid` because 1.3.0 exposes no public
        accessor. Used for observability only — never for protocol decisions —
        so if the attribute moves in a later aioquic, the demo output degrades
        and nothing on the data path breaks.
        """
        cid = getattr(self._quic, "_peer_cid", None)
        return bytes(getattr(cid, "cid", b"")) if cid is not None else b""

    def migrate(self) -> bytes:
        """Rotate to a fresh destination Connection ID on the live connection.

        Keys, streams and buffered data are all untouched — only the identifier
        on the wire changes. Returns the new peer CID.

        Note this needs a spare CID: the peer must have issued NEW_CONNECTION_ID
        frames, which it does automatically after the handshake. If none is
        available aioquic keeps the current one, so callers should compare the
        returned value rather than assume the rotation happened.
        """
        self.change_connection_id()
        self.transmit()
        return self.peer_connection_id

    async def wait_handshake(self, timeout: float = 10.0) -> None:
        try:
            await asyncio.wait_for(self._handshake.wait(), timeout)
        except asyncio.TimeoutError as exc:
            raise LinkError(f"QUIC handshake did not complete in {timeout}s") from exc

    # --------------------------------------------------------------- outbound
    async def request(
        self,
        msg_type: int,
        body: dict[str, Any],
        timeout: float = 20.0,
    ) -> tuple[int, dict[str, Any]]:
        stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._waiters[stream_id] = fut
        self._readers[stream_id] = FrameReader()

        # end_stream=True half-closes our side: we are done sending, but the
        # stream stays open for the peer's reply.
        self._quic.send_stream_data(stream_id, encode(msg_type, body), end_stream=True)
        self.transmit()

        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError as exc:
            raise LinkError(f"no reply to {type_name(msg_type)} within {timeout}s") from exc
        finally:
            self._waiters.pop(stream_id, None)
            self._readers.pop(stream_id, None)

    async def send_oneway(self, msg_type: int, body: dict[str, Any]) -> None:
        stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
        self._quic.send_stream_data(stream_id, encode(msg_type, body), end_stream=True)
        self.transmit()

    # ---------------------------------------------------------------- inbound
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            self.handshake_ms = (asyncio.get_event_loop().time() - self._t0) * 1000.0
            self._handshake.set()

        elif isinstance(event, StreamDataReceived):
            reader = self._readers.get(event.stream_id)
            if reader is None:
                reader = FrameReader()
                self._readers[event.stream_id] = reader
            try:
                for msg_type, body in reader.feed(event.data):
                    self._dispatch(event.stream_id, msg_type, body)
            except WireError as exc:
                log.warning("stream %d: %s", event.stream_id, exc)
                self._quic.reset_stream(event.stream_id, error_code=1)
                self.transmit()
                self._readers.pop(event.stream_id, None)

            if event.end_stream:
                self._readers.pop(event.stream_id, None)

        elif isinstance(event, StreamReset):
            self._fail_waiter(event.stream_id, LinkError("stream reset by peer"))
            self._readers.pop(event.stream_id, None)

        elif isinstance(event, ConnectionTerminated):
            err = LinkError(f"connection closed: {event.reason_phrase or event.error_code}")
            for sid in list(self._waiters):
                self._fail_waiter(sid, err)
            self._handshake.set()

    def _dispatch(self, stream_id: int, msg_type: int, body: dict[str, Any]) -> None:
        waiter = self._waiters.get(stream_id)
        if waiter is not None:
            if not waiter.done():
                waiter.set_result((msg_type, body))
            return
        if self._handler is not None:
            asyncio.ensure_future(self._serve_one(stream_id, msg_type, body))

    async def _serve_one(self, stream_id: int, msg_type: int, body: dict[str, Any]) -> None:
        """Run the application handler and reply on the same stream."""
        try:
            reply = await self._handler(msg_type, body, self._peer)  # type: ignore[misc]
        except Exception as exc:                       # never kill the connection
            log.exception("handler raised on %s", type_name(msg_type))
            reply = (Control.ERROR, {"error": type(exc).__name__, "detail": str(exc)[:200]})
        if reply is None:
            self._quic.send_stream_data(stream_id, b"", end_stream=True)
        else:
            self._quic.send_stream_data(stream_id, encode(*reply), end_stream=True)
        self.transmit()

    def _fail_waiter(self, stream_id: int, exc: Exception) -> None:
        fut = self._waiters.get(stream_id)
        if fut is not None and not fut.done():
            fut.set_exception(exc)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def client_config(*, verify: bool = False, cafile: Optional[str] = None,
                  session_ticket: Any = None) -> QuicConfiguration:
    """QUIC config for dialing out.

    `verify=False` is the default because sprint agents use self-signed certs on
    a LAN. It is a real trade-off, not an oversight: the connection is still
    fully encrypted, but an active man-in-the-middle is not prevented. Point
    `cafile` at a shared CA (or pin the agent's SPKI) before this leaves a
    trusted network — see docs/SECURITY.md.
    """
    cfg = QuicConfiguration(
        is_client=True,
        alpn_protocols=[ALPN],
        idle_timeout=30.0,
        session_ticket=session_ticket,       # set to enable 0-RTT resumption
    )
    if verify:
        if cafile:
            cfg.load_verify_locations(cafile=cafile)
    else:
        cfg.verify_mode = ssl.CERT_NONE
    return cfg


def server_config(certfile: str, keyfile: str) -> QuicConfiguration:
    """QUIC config for listening."""
    cfg = QuicConfiguration(
        is_client=False,
        alpn_protocols=[ALPN],
        idle_timeout=30.0,
    )
    cfg.load_cert_chain(certfile, keyfile)
    return cfg


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------
async def dial(
    host: str,
    port: int = DEFAULT_PORT,
    *,
    config: Optional[QuicConfiguration] = None,
    timeout: float = 10.0,
):
    """Async context manager yielding a connected `Peer`.

        async with dial("192.168.86.41") as peer:
            await peer.request(Control.PING, {})
    """
    cfg = config or client_config()

    class _Ctx:
        async def __aenter__(self) -> Peer:
            self._cm = connect(host, port, configuration=cfg,
                               create_protocol=ThreadLinkProtocol)
            try:
                self._proto: ThreadLinkProtocol = await self._cm.__aenter__()
                await self._proto.wait_handshake(timeout)
            except LinkError:
                raise
            except (ConnectionError, OSError) as exc:
                raise LinkError(f"could not reach {host}:{port}: {exc}") from exc
            return Peer(self._proto)

        async def __aexit__(self, *exc: Any) -> None:
            await self._cm.__aexit__(*exc)

    return _Ctx()


async def listen(
    handler: Handler,
    host: str = "0.0.0.0",
    port: int = DEFAULT_PORT,
    *,
    certfile: str,
    keyfile: str,
):
    """Start a ThreadLink listener. Returns the aioquic server object."""

    def _factory(*args: Any, **kwargs: Any) -> ThreadLinkProtocol:
        return ThreadLinkProtocol(*args, handler=handler, **kwargs)

    return await serve(
        host, port,
        configuration=server_config(certfile, keyfile),
        create_protocol=_factory,
    )
