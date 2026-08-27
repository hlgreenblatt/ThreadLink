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
import time
from enum import IntEnum
from typing import Any, Awaitable, Callable, Optional

from threadlink import Control, Peer, dial, listen

log = logging.getLogger("threadchat")

CHAT_VERSION = 1


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
    ) -> None:
        self.agent_id = agent_id
        self.deliver = deliver
        self.directory = dict(directory or {})
        self.seen: set[str] = set()   # msg_ids already delivered (dedup + loop guard)

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
            mid = str(body.get("msg_id", ""))
            # dedup: a group message may reach us more than once via fan-out
            if mid and mid in self.seen:
                return ChatMsg.CHAT_ACK, {"msg_id": mid, "dup": True}
            if mid:
                self.seen.add(mid)
            frm = str(body.get("from", "?"))
            to = str(body.get("to", self.agent_id))
            text = str(body.get("text", ""))
            log.info("CHAT_MSG from %s -> %s (%d chars)", frm, to, len(text))
            try:
                res = self.deliver({
                    "from": frm, "to": to, "text": text,
                    "msg_id": mid, "ts": body.get("ts"),
                    "in_reply_to": body.get("in_reply_to"),
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

        if msg_type == Control.PING:
            return Control.PONG, {"agent": self.agent_id}

        if msg_type == Control.BYE:
            return None

        return Control.ERROR, {"error": "unhandled", "detail": f"0x{int(msg_type):02X}"}

    async def serve(self, host: str, port: int, *, certfile: str, keyfile: str):
        log.info("%s chat node listening on udp/%s:%d", self.agent_id, host, port)
        return await listen(self.handle, host, port,
                            certfile=certfile, keyfile=keyfile)

    # ----------------------------------------------------------------- client
    async def send_to(self, recipient: str, text: str, *,
                      msg_id: str, in_reply_to: Optional[str] = None,
                      host: Optional[str] = None, port: Optional[int] = None
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
        async with await dial(host, port) as peer:
            _t, ack = await peer.request(ChatMsg.CHAT_MSG, body)
            await peer.send(Control.BYE, {"agent": self.agent_id})
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
