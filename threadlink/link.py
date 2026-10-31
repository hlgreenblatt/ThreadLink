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
import json
import logging
import os
import ssl
from typing import Any, Awaitable, Callable, Optional

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.tls import CipherSuite
from aioquic.quic.events import (
    ConnectionTerminated,
    HandshakeCompleted,
    QuicEvent,
    StreamDataReceived,
    StreamReset,
)

from . import pq
from .certs import spki_pin_of_cert
from .wire import (
    Control, FrameReader, ThreadLinkError, WireError,
    encode, encode_raw, json_body,
)

log = logging.getLogger("threadlink.link")

# Post-quantum handshake (X25519MLKEM768 + ML-DSA) - see pq.py. Installed at import so
# every dial/listen in this process uses it; THREADLINK_PQ=off is the rollback switch.
PQ_STATUS = pq.install()

# ALPN identifies the application protocol inside the TLS handshake, so a
# ThreadLink peer and (say) an HTTP/3 peer refuse each other during the
# handshake instead of after exchanging confusing bytes.
ALPN = "threadlink/1"

# Default UDP port. 4433 is the conventional "QUIC/TLS demo" port and is easy
# to point Wireshark at: `udp port 4433`.
DEFAULT_PORT = 4433

# A handler takes (msg_type, body, peer) and returns the reply message, or None
# to close the stream without answering.
Handler = Callable[[int, Any, "Peer"], Awaitable[Optional[tuple[int, Any]]]]

# A riding protocol's body codec: (bytes -> object) for inbound, (object -> bytes)
# for outbound. The default is JSON; the transport applies whatever the riding
# protocol registered, so it moves the bytes without understanding them.
Codec = tuple[Callable[[bytes], Any], Callable[[Any], bytes]]

_JSON_CODEC: "Codec" = (
    json_body,
    lambda obj: json.dumps(obj, separators=(",", ":"), allow_nan=False).encode("utf-8"),
)

# Reserved riding-protocol id for the transport's own control stream.
CONTROL_PROTO = "threadlink.control/1"


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
        proto: str,
        msg_type: int,
        body: Any,
        timeout: float = 20.0,
    ) -> tuple[int, Any]:
        """Open a new data stream BOUND to `proto`, send one message, await the
        reply on that stream. `proto` is the riding-protocol id (e.g.
        "threadhello/1"); its opening BIND frame makes the stream self-describing."""
        return await self._proto.request(proto, msg_type, body, timeout=timeout)

    async def send(self, proto: str, msg_type: int, body: Any) -> None:
        """Fire and forget on its own bound stream. No reply awaited."""
        await self._proto.send_oneway(proto, msg_type, body)

    async def ping(self, timeout: float = 5.0) -> dict[str, Any]:
        """Liveness probe on the connection's control stream. Returns the PONG
        body (echoes the ping id). Control messages never ride a data stream."""
        return await self._proto.ping(timeout=timeout)

    async def bye(self, agent: str = "") -> None:
        """Graceful goodbye on the control stream; the peer may drop state."""
        await self._proto.bye(agent)

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
    def crypto(self) -> dict[str, Any]:
        """What this connection's handshake actually negotiated: key exchange group
        (X25519MLKEM768 when both ends are post-quantum), cipher, and the signature
        algorithm each side proved its identity with (mldsa65 = Dilithium)."""
        return self._proto.crypto

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

    def __init__(self, *args: Any,
                 registry: Optional[dict[str, Any]] = None,
                 **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # riding-protocol id -> (handler, codec). A listener registers one or more;
        # a stream's BIND frame selects which handler and codec serve it.
        self._registry: dict[str, tuple[Handler, "Codec"]] = {}
        for proto, entry in (registry or {}).items():
            self._register(proto, entry)
        self._readers: dict[int, FrameReader] = {}
        self._waiters: dict[int, asyncio.Future] = {}
        self._stream_proto: dict[int, str] = {}   # stream_id -> bound riding proto
        self._handshake = asyncio.Event()
        self._t0 = asyncio.get_event_loop().time()
        self.handshake_ms: Optional[float] = None
        self.peer_key_id: Optional[str] = None    # SPKI pin of the peer's cert
        self.crypto: dict[str, Any] = {}          # what the handshake used (pq.describe)
        self._close_reason: Optional[str] = None  # why the connection ended
        # control stream (PING/PONG/BYE/ERROR): opened by the client post-handshake
        self._control_stream_id: Optional[int] = None
        self._ping_waiters: dict[int, asyncio.Future] = {}
        self._ping_seq = 0
        self._peer = Peer(self)
        # ThreadLink requires MUTUAL authentication. A listener (server role) must
        # ask the initiator for a certificate AND reject one that sends none. aioquic
        # exposes both only via the TLS context, built lazily in _initialize(), so we
        # wrap that to arm the request and the certificate_required alert.
        if not self._quic.configuration.is_client:
            _enable_client_cert_request(self._quic)

    def _register(self, proto: str, entry: Any) -> None:
        """Accept a registry entry as either `handler` or `(handler, codec)`."""
        if isinstance(entry, tuple):
            handler, codec = entry
        else:
            handler, codec = entry, _JSON_CODEC
        self._registry[proto] = (handler, codec)

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
        # The handshake event is also set when the connection is TERMINATED (e.g.
        # the server aborted with certificate_required because we sent no cert).
        # Distinguish success from that: if we never completed, surface the reason.
        if self.handshake_ms is None:
            raise LinkError(self._close_reason or "connection closed before handshake")

    # --------------------------------------------------------------- outbound
    def _encode_body(self, proto: str, msg_type: int, body: Any) -> bytes:
        """Encode a riding-protocol frame using that protocol's codec (JSON by
        default). We opened the stream, so we know its proto and its codec."""
        _handler, codec = self._registry.get(proto, (None, _JSON_CODEC))
        _to_bytes = codec[1]
        return encode_raw(msg_type, _to_bytes(body))

    async def request(
        self,
        proto: str,
        msg_type: int,
        body: Any,
        timeout: float = 20.0,
    ) -> tuple[int, Any]:
        stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._waiters[stream_id] = fut
        self._readers[stream_id] = FrameReader(raw=True)
        self._stream_proto[stream_id] = proto

        # First frame BINDs the stream to its riding protocol (self-describing);
        # then the request frame. end_stream=True on the request half-closes our
        # side — done sending, stream stays open for the peer's reply.
        self._quic.send_stream_data(
            stream_id, encode(Control.BIND, {"proto": proto}), end_stream=False)
        self._quic.send_stream_data(
            stream_id, self._encode_body(proto, msg_type, body), end_stream=True)
        self.transmit()

        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError as exc:
            raise LinkError(f"no reply to {type_name(msg_type)} within {timeout}s") from exc
        finally:
            self._waiters.pop(stream_id, None)
            self._readers.pop(stream_id, None)
            self._stream_proto.pop(stream_id, None)

    async def send_oneway(self, proto: str, msg_type: int, body: Any) -> None:
        stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
        self._stream_proto[stream_id] = proto
        self._quic.send_stream_data(
            stream_id, encode(Control.BIND, {"proto": proto}), end_stream=False)
        self._quic.send_stream_data(
            stream_id, self._encode_body(proto, msg_type, body), end_stream=True)
        self.transmit()

    # ------------------------------------------------------------ control stream
    def open_control_stream(self) -> None:
        """Open the connection's single control stream (client side, post-auth).
        BIND'd to the reserved control proto and never end_stream'd for the life
        of the connection. PING/PONG/BYE/ERROR travel here and nowhere else."""
        if self._control_stream_id is not None:
            return
        sid = self._quic.get_next_available_stream_id(is_unidirectional=False)
        self._control_stream_id = sid
        self._stream_proto[sid] = CONTROL_PROTO
        self._readers[sid] = FrameReader(raw=True)
        self._quic.send_stream_data(
            sid, encode(Control.BIND, {"proto": CONTROL_PROTO}), end_stream=False)
        self.transmit()

    def _send_control(self, msg_type: int, body: dict[str, Any]) -> None:
        if self._control_stream_id is None:
            raise LinkError("no control stream open")
        self._quic.send_stream_data(
            self._control_stream_id, encode(msg_type, body), end_stream=False)
        self.transmit()

    async def ping(self, timeout: float = 5.0) -> dict[str, Any]:
        self._ping_seq += 1
        pid = self._ping_seq
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._ping_waiters[pid] = fut
        self._send_control(Control.PING, {"id": pid})
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError as exc:
            raise LinkError(f"no PONG within {timeout}s") from exc
        finally:
            self._ping_waiters.pop(pid, None)

    async def bye(self, agent: str = "") -> None:
        self._send_control(Control.BYE, {"agent": agent})

    # ---------------------------------------------------------------- inbound
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            self.handshake_ms = (asyncio.get_event_loop().time() - self._t0) * 1000.0
            # Mutual auth is enforced DURING the handshake now: a client that sent
            # no certificate triggers a native TLS certificate_required alert (see
            # _enable_client_cert_request), so by the time we get here on the server
            # the peer certificate is guaranteed present.
            if not self._quic.configuration.is_client:
                peer_cert = getattr(self._quic.tls, "_peer_certificate", None)
                if peer_cert is not None:
                    self.peer_key_id = spki_pin_of_cert(peer_cert)
            self.crypto = pq.describe(getattr(self._quic, "tls", None))
            log.info("handshake %s: kex=%s cipher=%s sig ours=%s peer=%s",
                     "server" if not self._quic.configuration.is_client else "client",
                     self.crypto.get("key_exchange"), self.crypto.get("cipher"),
                     self.crypto.get("our_signature"), self.crypto.get("peer_signature"))
            self._handshake.set()

        elif isinstance(event, StreamDataReceived):
            reader = self._readers.get(event.stream_id)
            if reader is None:
                reader = FrameReader(raw=True)
                self._readers[event.stream_id] = reader
            try:
                for msg_type, payload in reader.feed(event.data):
                    self._on_frame(event.stream_id, msg_type, payload)
            except WireError as exc:
                log.warning("stream %d: %s", event.stream_id, exc)
                self._quic.reset_stream(event.stream_id,
                                        error_code=ThreadLinkError.MALFORMED)
                self.transmit()
                self._readers.pop(event.stream_id, None)
                self._stream_proto.pop(event.stream_id, None)

            if event.end_stream:
                self._readers.pop(event.stream_id, None)
                self._stream_proto.pop(event.stream_id, None)

        elif isinstance(event, StreamReset):
            self._fail_waiter(event.stream_id, LinkError("stream reset by peer"))
            self._readers.pop(event.stream_id, None)
            self._stream_proto.pop(event.stream_id, None)

        elif isinstance(event, ConnectionTerminated):
            self._close_reason = event.reason_phrase or str(event.error_code)
            err = LinkError(f"connection closed: {event.reason_phrase or event.error_code}")
            for sid in list(self._waiters):
                self._fail_waiter(sid, err)
            self._handshake.set()

    def _on_frame(self, stream_id: int, msg_type: int, payload: bytes) -> None:
        """One frame arrived on `stream_id`. Bind the stream on its first (BIND)
        frame; route control frames to the control handler; otherwise decode with
        the stream's codec and dispatch to a waiter (our reply) or a handler."""
        # A stream we opened for a request: the reply comes back here. It is
        # already bound (we set _stream_proto when we sent), so decode + resolve.
        waiter = self._waiters.get(stream_id)
        if waiter is not None:
            proto = self._stream_proto.get(stream_id, "")
            _h, codec = self._registry.get(proto, (None, _JSON_CODEC))
            if not waiter.done():
                waiter.set_result((msg_type, codec[0](payload)))
            return

        # Control stream: its frames are transport control messages.
        if stream_id == self._control_stream_id:
            self._handle_control(msg_type, json_body(payload))
            return

        # An inbound stream the peer opened. Its FIRST frame MUST be BIND.
        proto = self._stream_proto.get(stream_id)
        if proto is None:
            if msg_type != Control.BIND:
                log.warning("stream %d: first frame not BIND (0x%02X)", stream_id, msg_type)
                self._quic.reset_stream(stream_id, error_code=ThreadLinkError.MALFORMED)
                self.transmit()
                return
            bound = json_body(payload).get("proto", "")
            if bound == CONTROL_PROTO:
                self._control_stream_id = stream_id
                self._stream_proto[stream_id] = bound
                return
            if bound not in self._registry:
                log.warning("stream %d: unknown riding protocol %r", stream_id, bound)
                self._quic.send_stream_data(
                    stream_id,
                    encode(Control.ERROR, {"error": "unsupported_protocol", "detail": bound}),
                    end_stream=False)
                self._quic.reset_stream(stream_id, error_code=ThreadLinkError.UNSUPPORTED)
                self.transmit()
                return
            self._stream_proto[stream_id] = bound
            return                                   # BIND consumed, not dispatched

        # Subsequent frames on a bound inbound stream -> the riding handler.
        handler, codec = self._registry[proto]
        asyncio.ensure_future(
            self._serve_one(stream_id, proto, handler, codec, msg_type, codec[0](payload)))

    def _handle_control(self, msg_type: int, body: dict[str, Any]) -> None:
        if msg_type == Control.PING:
            self._send_control(Control.PONG, {"id": body.get("id")})
        elif msg_type == Control.PONG:
            fut = self._ping_waiters.get(body.get("id"))
            if fut is not None and not fut.done():
                fut.set_result(body)
        elif msg_type == Control.BYE:
            log.info("peer %s said BYE", body.get("agent", "?"))
        elif msg_type == Control.ERROR:
            log.warning("control ERROR from peer: %s", body)

    async def _serve_one(self, stream_id: int, proto: str, handler: "Handler",
                         codec: "Codec", msg_type: int, body: Any) -> None:
        """Run a riding handler and reply on the same (already-bound) stream.
        The reply inherits the stream's codec — a handler cannot answer in a
        different protocol than the one that owns its stream."""
        try:
            reply = await handler(msg_type, body, self._peer)
        except Exception as exc:                       # never kill the connection
            log.exception("handler raised on %s (%s)", type_name(msg_type), proto)
            reply = (Control.ERROR, {"error": type(exc).__name__, "detail": str(exc)[:200]})
        if reply is None:
            self._quic.send_stream_data(stream_id, b"", end_stream=True)
        else:
            rtype, rbody = reply
            self._quic.send_stream_data(
                stream_id, encode_raw(rtype, codec[1](rbody)), end_stream=True)
        self.transmit()

    def _fail_waiter(self, stream_id: int, exc: Exception) -> None:
        fut = self._waiters.get(stream_id)
        if fut is not None and not fut.done():
            fut.set_exception(exc)


def _keylog_file():
    """If SSLKEYLOGFILE is set, return an append-mode handle so aioquic writes
    TLS 1.3 traffic secrets in the NSS key-log format Wireshark reads natively.
    Standard convention (curl, browsers). Unset in production; the capture story
    is opt-in and leaves no trace when the env var is absent."""
    path = os.environ.get("SSLKEYLOGFILE")
    if not path:
        return None
    try:
        return open(path, "a")
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def _enable_client_cert_request(quic: Any) -> None:
    """Make a server QuicConnection REQUIRE the client's certificate.

    Two effects, both reached only through aioquic's TLS Context, which is built
    lazily inside `QuicConnection._initialize(peer_cid)`. We wrap `_initialize` so
    that the instant `quic.tls` exists we:

      1. set `_request_client_certificate` — QUIC's optional client auth is now
         requested; and
      2. wrap the TLS Context's `_server_handle_certificate` so that a client
         which answers CertificateRequest with an EMPTY certificate raises a TLS
         `certificate_required` alert. aioquic turns that alert into a QUIC
         CONNECTION_CLOSE with error code CRYPTO_ERROR + 116 (0x174) and reason
         "mutual authentication required", DURING the handshake — the clean,
         native layering, rather than an application-level close afterwards.

    Reaches into aioquic 1.3.0 internals (`_server_handle_certificate`,
    `pull_certificate`, `State`, `AlertDescription`); pinned by the venv. If a
    later aioquic renames these, the wrap no-ops and mutual auth would silently
    weaken, so this is covered by the "anonymous client rejected" test.
    """
    from aioquic import tls as _tls

    class _AlertCertificateRequired(_tls.Alert):
        description = _tls.AlertDescription.certificate_required

    orig = quic._initialize

    def wrapped(peer_cid: bytes) -> None:
        orig(peer_cid)
        tls = getattr(quic, "tls", None)
        if tls is None:
            return
        tls._request_client_certificate = True

        cert_orig = tls._server_handle_certificate

        def cert_wrapped(input_buf: Any, output_buf: Any) -> None:
            # Mirror aioquic's own _server_handle_certificate, but on an empty
            # certificate raise the alert instead of proceeding to Finished.
            certificate = _tls.pull_certificate(input_buf)
            tls.key_schedule.update_hash(input_buf.data)
            if certificate.certificates:
                tls._set_peer_certificate(certificate)
                tls._set_state(_tls.State.SERVER_EXPECT_CERTIFICATE_VERIFY)
            else:
                raise _AlertCertificateRequired("mutual authentication required")

        tls._server_handle_certificate = cert_wrapped

    quic._initialize = wrapped


# Captain's order 2026-09-11: ChaCha20-Poly1305 FIRST, AES-GCM as the negotiated fallback.
# TLS 1.3 picks the first suite both sides offer, so a ThreadLink peer talking to an
# AES-only stack still connects; two ThreadLinks talk ChaCha20.
CIPHER_SUITES = [
    CipherSuite.CHACHA20_POLY1305_SHA256,
    CipherSuite.AES_256_GCM_SHA384,
    CipherSuite.AES_128_GCM_SHA256,
]

def client_config(*, certfile: Optional[str] = None, keyfile: Optional[str] = None,
                  verify: bool = False, cafile: Optional[str] = None,
                  session_ticket: Any = None) -> QuicConfiguration:
    """QUIC config for dialing out.

    ThreadLink is mutually authenticated: the client MUST present its own
    certificate so the listener can prove the initiator holds a private key.
    `certfile`/`keyfile` are the client's own credential; when omitted the caller
    is expected to supply one via `dial(..., certfile=...)`, which fills them in.

    `verify=False` (the default) means proof-of-possession WITHOUT binding the
    peer's key to a trust root — appropriate for self-signed agents on a trusted
    LAN, where the connection is encrypted and both sides prove key possession,
    but the *binding* of a key to an identity is a separate deployment policy
    (trust-on-first-use pin, a CA via `cafile`, or an external/decentralized PKI).
    Set `verify=True` with `cafile` to validate the peer's certificate to a root.
    """
    cfg = QuicConfiguration(
        is_client=True,
        cipher_suites=CIPHER_SUITES,
        alpn_protocols=[ALPN],
        idle_timeout=30.0,
        session_ticket=session_ticket,       # set to enable 0-RTT resumption
        secrets_log_file=_keylog_file(),     # SSLKEYLOGFILE -> Wireshark decrypt
    )
    if certfile and keyfile:
        cfg.load_cert_chain(certfile, keyfile)   # the client's OWN cert (mutual auth)
    if verify:
        if cafile:
            cfg.load_verify_locations(cafile=cafile)
    else:
        cfg.verify_mode = ssl.CERT_NONE
    return cfg


def server_config(certfile: str, keyfile: str, *,
                  verify: bool = False, cafile: Optional[str] = None) -> QuicConfiguration:
    """QUIC config for listening.

    The listener presents its own certificate (mandatory) and — because
    ThreadLink requires mutual authentication — also requests one from the
    initiator (see `_enable_client_cert_request`, wired in ThreadLinkProtocol).

    `verify`/`cafile` govern only whether the presented client certificate is
    validated to a trust root; possession of the key is proven either way.
    """
    cfg = QuicConfiguration(
        is_client=False,
        cipher_suites=CIPHER_SUITES,
        alpn_protocols=[ALPN],
        idle_timeout=30.0,
        secrets_log_file=_keylog_file(),     # SSLKEYLOGFILE -> Wireshark decrypt
    )
    cfg.load_cert_chain(certfile, keyfile)
    if verify and cafile:
        cfg.load_verify_locations(cafile=cafile)
    else:
        cfg.verify_mode = ssl.CERT_NONE      # accept the cert, prove possession only
    return cfg


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------
async def dial(
    host: str,
    port: int = DEFAULT_PORT,
    *,
    config: Optional[QuicConfiguration] = None,
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
    registry: Optional[dict[str, Any]] = None,
    timeout: float = 10.0,
):
    """Async context manager yielding a connected `Peer`.

        async with dial("192.168.86.41", certfile=c, keyfile=k) as peer:
            await peer.request("threadhello/1", HELLO, {...})
            await peer.ping()

    ThreadLink is mutually authenticated, so the initiator presents its own
    certificate. Pass `certfile`/`keyfile` (or a fully-built `config` that already
    loaded a client cert chain). Omitting both yields an anonymous client, which a
    conforming ThreadLink listener rejects at the certificate step.

    A dialing client may also serve inbound streams (ThreadLink is peer-to-peer):
    pass `registry` to answer riding-protocol requests the peer opens back to us.
    The control stream is opened automatically once the handshake completes.
    """
    cfg = config or client_config(certfile=certfile, keyfile=keyfile)

    def _factory(*args: Any, **kwargs: Any) -> ThreadLinkProtocol:
        return ThreadLinkProtocol(*args, registry=registry, **kwargs)

    class _Ctx:
        async def __aenter__(self) -> Peer:
            self._cm = connect(host, port, configuration=cfg,
                               create_protocol=_factory)
            try:
                self._proto: ThreadLinkProtocol = await self._cm.__aenter__()
                await self._proto.wait_handshake(timeout)
                # A mutual-auth abort arrives as a CONNECTION_CLOSE a few ms AFTER
                # the client's own handshake completes, so an anonymous client can
                # pass wait_handshake and only then learn it was rejected. Open the
                # control stream immediately and confirm the connection with one
                # PING: a live peer PONGs in well under the timeout, a rejected one
                # never answers because the connection is already closing. This
                # doubles as readiness (the control plane is proven up) and adds no
                # fixed delay to a healthy dial.
                self._proto.open_control_stream()
                try:
                    await self._proto.ping(timeout=min(timeout, 5.0))
                except LinkError:
                    # The PONG never came: the peer is rejecting us. Let the
                    # CONNECTION_CLOSE land so we can report WHY (e.g. mutual auth).
                    for _ in range(10):
                        if self._proto._close_reason is not None:
                            break
                        await asyncio.sleep(0.02)
                    raise LinkError(self._proto._close_reason
                                    or "connection closed during setup")
            except LinkError:
                raise
            except (ConnectionError, OSError) as exc:
                # If the peer closed the connection with a reason (e.g. rejected
                # our missing certificate), report THAT rather than a generic
                # unreachable — the close reason is the actionable message. The
                # CONNECTION_CLOSE may still be in flight, so drain briefly first.
                proto = getattr(self, "_proto", None)
                if proto is not None:
                    for _ in range(10):
                        if proto._close_reason is not None:
                            raise LinkError(proto._close_reason) from exc
                        await asyncio.sleep(0.02)
                raise LinkError(f"could not reach {host}:{port}: {exc}") from exc
            return Peer(self._proto)

        async def __aexit__(self, *exc: Any) -> None:
            await self._cm.__aexit__(*exc)

    return _Ctx()


async def listen(
    registry: dict[str, Any],
    host: str = "0.0.0.0",
    port: int = DEFAULT_PORT,
    *,
    certfile: str,
    keyfile: str,
):
    """Start a ThreadLink listener hosting one or more riding protocols.

    `registry` maps a riding-protocol id to its handler (or to a
    `(handler, codec)` pair). A stream's BIND frame selects which handler serves
    it, so one listener can host many protocols on independent streams without a
    global type-byte registry. A single-protocol node passes a one-entry dict::

        await listen({"threadhello/1": agent.handle}, host, port, certfile=c, keyfile=k)
    """

    def _factory(*args: Any, **kwargs: Any) -> ThreadLinkProtocol:
        return ThreadLinkProtocol(*args, registry=registry, **kwargs)

    return await serve(
        host, port,
        configuration=server_config(certfile, keyfile),
        create_protocol=_factory,
    )
