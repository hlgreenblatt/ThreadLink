"""ThreadChat protocol + node.

A ChatNode fronts exactly one local agent. It:
  - listens on QUIC for CHAT_MSG / CHAT_WHO from other nodes,
  - hands an inbound message to the local agent (via a pluggable sink),
  - dials a peer node to deliver an outbound message the agent produced.

The node knows nothing about *how* the agent reads or writes — that is the
`deliver` sink and the `outbox` source, injected at construction. For OmegaClaw
this is the local HTTP channel (POST /send, GET /messages); for a test it is a
list. That boundary is what keeps ThreadChat host-agnostic.
"""

from __future__ import annotations

import inspect
import logging
import os
import time
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Awaitable, Callable, Optional

from threadlink import Control, Peer, dial, listen

log = logging.getLogger("threadchat")

CHAT_VERSION = 1

# ThreadChat's riding-protocol id on ThreadLink (named in each stream's BIND).
THREADCHAT = "threadchat/1"

# CHECK YOUR WATCH FIRST (Captain 2026-11-08). A model has no clock; it guesses the time from whatever
# text it was given. So the NODE, whose host clock is NTP-synced, puts the real time on every letter it
# hands its agent: delivered UTC + unix seconds, and when the sender's clock is in the letter (body.ts,
# always sent) the UTC time it was sent. Opt-in per node (TC_WATCH=1 in the agent's node env), so
# collectors that save replies verbatim (threadchat-send, the desk) never get a stamp in a saved piece.
WATCH = os.environ.get("TC_WATCH", "0") == "1"


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def watch_stamp(sent_ts: Any = None, now: Optional[float] = None) -> str:
    """One line: the real time now (UTC + unix) and when the letter was sent."""
    now = time.time() if now is None else float(now)
    line = f"⌚ {_utc(now)} · unix {int(now)}"
    try:
        sent = float(sent_ts)
    except (TypeError, ValueError):
        sent = None
    if sent is not None and abs(now - sent) < 7 * 86400:      # a sane sender clock only
        age = now - sent
        line += f" · sent {_utc(sent)}" + (f", {age:.0f} s ago" if age >= 2 else "")
    return line + " · real time, UTC, from the node's NTP clock"


class ChatMsg(IntEnum):
    """ThreadChat's slice of ThreadLink's opaque type byte."""

    CHAT_MSG = 0x10   # a letter: from, to, text, msg_id, ts, [in_reply_to]
    CHAT_ACK = 0x11   # received by the node (not necessarily read by the agent)
    CHAT_WHO = 0x12   # who do you front? -> {agents: [...]}
    CHAT_SEEN = 0x13  # the agent's loop consumed msg_id (optional receipt)


# A sink receives an inbound letter and hands it to the local agent. Returns
# nothing; delivery is fire-and-forget from the protocol's view (the agent
# answers later, on its own clock, through the outbox). May be async.
DeliverSink = Callable[[dict], Any]


class ChatNode:
    """One agent's presence on the ThreadChat mesh.

    Parameters
    ----------
    agent_id : the local agent this node speaks for (e.g. "agent_33").
    deliver  : callable(letter_dict) -> injects an inbound letter into the
               local agent. `letter_dict` has from/text/msg_id/ts/to.
    directory: {agent_id: (host, port)} — where peer nodes listen. Used to
               route an outbound CHAT_MSG to the named recipient, and to
               fan out a to=="all" group message.
    """

    def __init__(
        self,
        agent_id: str,
        deliver: DeliverSink,
        directory: Optional[dict[str, tuple[str, int]]] = None,
        certfile: Optional[str] = None,
        keyfile: Optional[str] = None,
        pins: Optional[dict[str, str]] = None,
        strict: bool = False,
        watch: Optional[bool] = None,
    ) -> None:
        self.agent_id = agent_id
        self.deliver = deliver
        self.directory = dict(directory or {})
        # Sender authentication (2026-10-08). The server accepts any client cert
        # (verify_mode=CERT_NONE, possession only), so a letter's "from" is merely
        # what the sender wrote. `pins` = {agent_id: SPKI pin of that agent's key}
        # (threadlink.spki_pin). A letter claiming a pinned sender must come over a
        # connection whose client key matches the pin. strict=True also refuses
        # every sender that has no pin. pins=None keeps the old behaviour.
        self.pins = dict(pins or {})
        self.strict = strict
        self.watch = WATCH if watch is None else bool(watch)
        self.seen: set[str] = set()   # msg_ids already delivered (dedup + loop guard)
        # identity cert — presented both when serving and (ThreadLink is mutually
        # authenticated) when dialing another node. serve() may also set these.
        self._certfile = certfile
        self._keyfile = keyfile

    def _client_creds(self) -> dict[str, str]:
        cf, kf = getattr(self, "_certfile", None), getattr(self, "_keyfile", None)
        return {"certfile": cf, "keyfile": kf} if cf and kf else {}

    # ------------------------------------------------------------------ serve
    async def handle(self, msg_type: int, body: dict[str, Any],
                     peer: Peer) -> Optional[tuple[int, dict[str, Any]]]:
        """Server-side dispatch, passed to threadlink.listen()."""

        if msg_type == ChatMsg.CHAT_WHO:
            return ChatMsg.CHAT_ACK, {"agents": [self.agent_id], "proto": CHAT_VERSION}

        if msg_type == ChatMsg.CHAT_MSG:
            if int(body.get("proto", 0)) != CHAT_VERSION:
                return Control.ERROR, {"error": "proto_mismatch",
                                       "detail": f"we speak v{CHAT_VERSION}"}
            frm = str(body.get("from", "?"))
            if self.pins or self.strict:
                want = self.pins.get(frm)
                got = getattr(getattr(peer, "_proto", None), "peer_key_id", None)
                if want is None and self.strict:
                    log.warning("CHAT_MSG refused: sender %s has no pin", frm)
                    return Control.ERROR, {"error": "unknown_sender"}
                if want is not None and got != want:
                    log.warning("CHAT_MSG refused: key does not match the pin for %s", frm)
                    return Control.ERROR, {"error": "sender_key_mismatch"}
            mid = str(body.get("msg_id", ""))
            # dedup: a group message may reach us more than once via fan-out
            if mid and mid in self.seen:
                return ChatMsg.CHAT_ACK, {"msg_id": mid, "dup": True}
            if mid:
                self.seen.add(mid)
            to = str(body.get("to", self.agent_id))
            text = str(body.get("text", ""))
            log.info("CHAT_MSG from %s -> %s (%d chars)", frm, to, len(text))
            now = time.time()
            stamp = watch_stamp(body.get("ts"), now)
            if self.watch:                                  # the agent reads the real time first
                text = stamp + "\n" + text
            try:
                res = self.deliver({
                    "from": frm, "to": to, "text": text,
                    "msg_id": mid, "ts": body.get("ts"),
                    "in_reply_to": body.get("in_reply_to"),
                    # 10-18: a per-task conversation (ThreadTask). Absent = the old per-sender thread.
                    "thread": body.get("thread"),
                    "meta": body.get("meta"),
                    "delivered_ts": now, "watch": stamp,
                })
                # Await a coroutine (a deliver that does quick async work), but
                # NOT a Task: a Task is already scheduled fire-and-forget, and a
                # sync adapter deliberately returns one so the ACK returns now
                # while the slow agent turn runs in the background. Awaiting the
                # Task here would stall the ACK until the turn finished.
                if inspect.iscoroutine(res):
                    await res
            except Exception as exc:                       # never kill the stream
                log.warning("deliver failed: %s", exc)
                return Control.ERROR, {"error": "deliver_failed", "detail": str(exc)}
            return ChatMsg.CHAT_ACK, {"msg_id": mid, "by": self.agent_id}

        # PING/PONG/BYE are transport control messages, answered by ThreadLink on
        # the connection's control stream; they never reach this riding handler.
        return Control.ERROR, {"error": "unhandled", "detail": f"0x{int(msg_type):02X}"}

    async def serve(self, host: str, port: int, *, certfile: str, keyfile: str):
        self._certfile, self._keyfile = certfile, keyfile   # reuse when we dial
        log.info("%s chat node listening on udp/%s:%d", self.agent_id, host, port)
        return await listen({THREADCHAT: self.handle}, host, port,
                            certfile=certfile, keyfile=keyfile)

    # ----------------------------------------------------------------- client
    async def send_to(self, recipient: str, text: str, *,
                      msg_id: str, in_reply_to: Optional[str] = None,
                      host: Optional[str] = None, port: Optional[int] = None,
                      thread: Optional[str] = None, meta: Optional[dict] = None
                      ) -> dict[str, Any]:
        """Deliver one letter to a single peer node (dial + CHAT_MSG)."""
        if host is None or port is None:
            if recipient not in self.directory:
                raise KeyError(f"no directory entry for {recipient!r}")
            host, port = self.directory[recipient]
        body = {
            "from": self.agent_id, "to": recipient, "text": text,
            "msg_id": msg_id, "ts": time.time(), "proto": CHAT_VERSION,
        }
        if in_reply_to:
            body["in_reply_to"] = in_reply_to
        if thread:                       # 10-18: the receiving node opens a conversation just for this thread
            body["thread"] = str(thread)[:120]
        if meta:
            body["meta"] = meta
        async with await dial(host, port, **self._client_creds()) as peer:
            _t, ack = await peer.request(THREADCHAT, ChatMsg.CHAT_MSG, body)
            await peer.bye(self.agent_id)
            return {"recipient": recipient, "ack": ack,
                    "handshake_ms": round(peer.handshake_ms or 0, 2)}

    async def broadcast(self, text: str, *, msg_id: str,
                        exclude: Optional[set[str]] = None) -> list[dict[str, Any]]:
        """Fan a group message out to every agent in the directory.

        The group-chat primitive: one call, one msg_id, delivered to all. The
        shared msg_id means each recipient's dedup drops repeats, so a later
        gossip/relay of the same message never doubles it.
        """
        exclude = (exclude or set()) | {self.agent_id}
        out = []
        for recipient, (host, port) in self.directory.items():
            if recipient in exclude:
                continue
            try:
                out.append(await self.send_to(recipient, text, msg_id=msg_id,
                                              host=host, port=port))
            except Exception as exc:
                log.warning("broadcast to %s failed: %s", recipient, exc)
                out.append({"recipient": recipient, "error": str(exc)})
        return out
