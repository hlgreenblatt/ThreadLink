"""
ThreadHello — a deliberately small protocol for ThreadRouter agents.

It rides on ThreadLink (https://github.com/hlgreenblatt/ThreadLink), which
moves the bytes and knows nothing about routing. The whole conversation:

    A -> B   HELLO        who I am, what paths I have, how big my table is
    B -> A   HELLO_ACK    likewise
    A -> B   ROUTE_REQ    anything you learned since <ts>?
    B -> A   ROUTE_TABLE  here are N observations
    A -> B   ROUTE_TABLE  here are mine  (push, so one exchange syncs both ways)

That is the protocol. It is small on purpose: the interesting behaviour lives in
the merge policy (routeshare.RouteStore), not in the message flow. A protocol
you can hold in your head is one you can debug on stage.

The loose networking ancestor is OSPF — routers introducing themselves and
exchanging what they know, so each ends with a better view of the network than
it could build alone. We inherit the idea, not the machinery.

Every exchange gets its own QUIC stream, so a large ROUTE_TABLE transfer never
delays a PING — that isolation is structural in ThreadLink, not remembered here.
"""

from __future__ import annotations

import logging
import time
from enum import IntEnum
from typing import Any, Optional

from threadlink import Control, DEFAULT_PORT, Peer, dial, listen

from .routeshare import RouteStore

log = logging.getLogger("threadhello")

# Bumped when a change would confuse an older peer. HELLO carries it so both
# sides can refuse early and clearly instead of failing on a later frame.
HELLO_VERSION = 1


class HelloMsg(IntEnum):
    """ThreadHello's message types — this protocol's slice of ThreadLink's
    opaque type byte. The transport carries these without interpreting them."""

    HELLO = 0x01        # I exist; here is who I am and what paths I know.
    HELLO_ACK = 0x02    # Likewise. Handshake at the application layer.
    ROUTE_REQ = 0x03    # Send me route observations newer than `since`.
    ROUTE_TABLE = 0x04  # A batch of route observations.
    # --- incremental, event-driven updates (v1 additions) ---
    # 0x05-0x07 and 0x7F are reserved by the ThreadLink transport (PING/PONG/BYE/ERROR);
    # ThreadHello's own event types start at 0x08 to keep the type byte unambiguous.
    ROUTE_UPDATE = 0x08    # A delta: observations that changed since last contact.
    ROUTE_WITHDRAW = 0x09  # A path is gone; stop routing to it (route-down).
    MODEL_UPDATE = 0x0A    # An agent's serving capability changed (new/removed model).


def classify_model(*, local: bool, free: bool) -> dict[str, Any]:
    """Describe a model on the two axes a routing swarm actually cares about.

    locality  — where inference happens. LOCAL means the prompt never leaves the
                fleet (private); CLOUD means it goes to a third party (not private).
    cost      — FREE or PAID at point of use.

    These are not cosmetic labels: they map straight onto the route attributes the
    RouteStore already scores. A local model is privacy=1.0; a cloud one is lower.
    A free model is cost=0.0; a paid one is >0. Carrying them in the announcement
    lets a peer honour "keep private work off the cloud" the instant it learns the
    model exists, instead of discovering the cost after it has routed a secret to it.
    """
    locality = "local" if local else "cloud"
    return {
        "locality": locality,          # local | cloud
        "cost": "free" if free else "paid",
        "private": bool(local),        # local inference == prompt stays in the fleet
        # the attributes the router scores by, derived from the two axes above
        "attrs": {"privacy": 1.0 if local else 0.2,
                  "cost": 0.0 if free else 1.0},
    }


class HelloAgent:
    """A ThreadRouter agent that can meet peers and trade route tables.

    `known_paths` is this agent's routable path ids (tk_router.PATHS). It is the
    filter that makes a heterogeneous swarm safe: observations naming a path we
    do not have are dropped rather than learned as fiction.
    """

    def __init__(
        self,
        agent_id: str,
        store: Optional[RouteStore] = None,
        known_paths: Optional[set[str]] = None,
        spki: str = "",
    ) -> None:
        self.agent_id = agent_id
        self.store = store or RouteStore(agent_id)
        self.known_paths = known_paths
        self.spki = spki
        self.peers_seen: dict[str, dict[str, Any]] = {}
        self.peers_caps: dict[str, set] = {}   # agent -> set of models it serves
        # (agent, model) -> {model_class, locality, cost, private} — provenance,
        # so a peer can prefer local/private routes and refuse to send secrets to cloud
        self.peer_model_class: dict[tuple, dict] = {}
        self.epoch: int = 0                    # bumps on every topology change
        # Per-peer high-water mark, so each sync ships only what is new.
        self._last_sync: dict[str, float] = {}

    # ------------------------------------------------------------------ serve
    async def handle(self, msg_type: int, body: dict[str, Any],
                     peer: Peer) -> Optional[tuple[int, dict[str, Any]]]:
        """Server-side dispatch. Passed straight to threadlink.listen()."""

        if msg_type == HelloMsg.HELLO:
            remote = str(body.get("agent", "?"))
            if int(body.get("proto", 0)) != HELLO_VERSION:
                return Control.ERROR, {
                    "error": "protocol_mismatch",
                    "detail": f"peer speaks v{body.get('proto')}, we speak v{HELLO_VERSION}",
                }
            self.peers_seen[remote] = {
                "paths": body.get("paths", []),
                "rows": body.get("rows", 0),
                "spki": body.get("spki", ""),
                "at": time.time(),
            }
            log.info("HELLO from %s (%d paths, %d rows)",
                     remote, len(body.get("paths") or []), body.get("rows", 0))
            return HelloMsg.HELLO_ACK, self._identity()

        if msg_type == HelloMsg.ROUTE_REQ:
            since = float(body.get("since", 0.0))
            limit = min(int(body.get("limit", 500)), 2000)
            rows = self.store.export(since=since, limit=limit)
            return HelloMsg.ROUTE_TABLE, {"rows": rows, "count": len(rows),
                                          "agent": self.agent_id}

        if msg_type == HelloMsg.ROUTE_TABLE:
            rows = body.get("rows") or []
            stats = self.store.merge(rows, known_paths=self.known_paths)
            log.info("merged from %s: %s", body.get("agent", "?"), stats)
            return HelloMsg.HELLO_ACK, {"merged": stats, "rows": len(self.store)}

        if msg_type == HelloMsg.ROUTE_UPDATE:
            # incremental delta — merge just the changed rows (cheaper than a full table)
            rows = body.get("rows") or []
            stats = self.store.merge(rows, known_paths=self.known_paths)
            log.info("ROUTE_UPDATE from %s: %s (%d rows)",
                     body.get("agent", "?"), stats, len(rows))
            return HelloMsg.HELLO_ACK, {"merged": stats, "epoch": self.epoch}

        if msg_type == HelloMsg.ROUTE_WITHDRAW:
            # a path went down — drop every observation for it (route-down)
            path = str(body.get("path", ""))
            origin = str(body.get("agent", "?"))
            removed = self.store.withdraw_path(path) if path else 0
            self.epoch += 1
            log.info("ROUTE_WITHDRAW from %s: path=%s dropped %d rows (epoch->%d)",
                     origin, path, removed, self.epoch)
            return HelloMsg.HELLO_ACK, {"withdrawn": path, "dropped": removed,
                                        "epoch": self.epoch}

        if msg_type == HelloMsg.MODEL_UPDATE:
            # an agent's serving capability changed (loaded/dropped a model)
            remote = str(body.get("agent", "?"))
            action = str(body.get("action", "?"))   # "added" | "removed"
            model = str(body.get("model", "?"))
            path = str(body.get("path", ""))
            model_class = str(body.get("model_class", "?"))  # e.g. local/free
            caps = self.peers_caps.setdefault(remote, set())
            if action == "added":
                caps.add(model)
                # remember what KIND of model this is, for privacy-aware routing
                self.peer_model_class[(remote, model)] = {
                    "model_class": model_class,
                    "locality": body.get("locality", "?"),
                    "cost": body.get("cost", "?"),
                    "private": bool(body.get("private", False)),
                }
            elif action == "removed":
                caps.discard(model)
                self.peer_model_class.pop((remote, model), None)
                if path:
                    self.store.withdraw_path(path)   # its routes go too
            self.epoch += 1
            log.info("MODEL_UPDATE from %s: %s %s [%s] (path=%s, epoch->%d)",
                     remote, action, model, model_class, path, self.epoch)
            return HelloMsg.HELLO_ACK, {"noted": model, "action": action,
                                        "model_class": model_class,
                                        "epoch": self.epoch}

        if msg_type == Control.PING:
            return Control.PONG, {"t": body.get("t"), "agent": self.agent_id}

        if msg_type == Control.BYE:
            return None                       # close the stream, say nothing

        return Control.ERROR, {"error": "unhandled", "detail": f"0x{int(msg_type):02X}"}

    def _identity(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id,
            "proto": HELLO_VERSION,
            "paths": sorted(self.known_paths) if self.known_paths else [],
            "rows": len(self.store),
            "spki": self.spki,
            "ts": time.time(),
        }

    async def serve(self, host: str = "0.0.0.0", port: int = DEFAULT_PORT,
                    *, certfile: str, keyfile: str):
        log.info("%s listening on udp/%s:%d", self.agent_id, host, port)
        return await listen(self.handle, host, port,
                            certfile=certfile, keyfile=keyfile)

    # ----------------------------------------------------------------- client
    async def sync_with(self, host: str, port: int = DEFAULT_PORT) -> dict[str, Any]:
        """Meet a peer and trade route tables. One connection, four exchanges."""
        t0 = time.perf_counter()
        async with await dial(host, port) as peer:
            hs_ms = peer.handshake_ms

            _t, ack = await peer.request(HelloMsg.HELLO, self._identity())
            remote = str(ack.get("agent", f"{host}:{port}"))
            if ack.get("error"):
                raise RuntimeError(f"{remote}: {ack.get('detail')}")

            # Pull what they learned since we last spoke.
            since = self._last_sync.get(remote, 0.0)
            _t, table = await peer.request(HelloMsg.ROUTE_REQ,
                                           {"since": since, "limit": 500})
            pulled = self.store.merge(table.get("rows") or [],
                                      known_paths=self.known_paths)

            # Push ours in the same visit, so one meeting syncs both directions.
            mine = self.store.export(since=0.0, limit=500)
            _t, res = await peer.request(HelloMsg.ROUTE_TABLE,
                                         {"rows": mine, "agent": self.agent_id})

            await peer.send(Control.BYE, {"agent": self.agent_id})
            self._last_sync[remote] = time.time()

            return {
                "peer": remote,
                "handshake_ms": round(hs_ms, 2) if hs_ms else None,
                "total_ms": round((time.perf_counter() - t0) * 1000, 2),
                "pulled": pulled,
                "pushed": len(mine),
                "peer_merged": res.get("merged"),
                "rows_now": len(self.store),
            }

    # ----------------------------------------------- event-driven client senders
    async def announce_model(self, host, port, *, action, model, path="",
                             local=True, free=True):
        """Tell a peer this agent gained ("added") or lost ("removed") a model.
        The agent-native message: capability changed, re-route accordingly.

        `local`/`free` classify the model (see classify_model): a peer learns not
        just THAT a model appeared but WHAT KIND — local-private-free vs
        cloud-not-private — so it can route (or refuse to route) accordingly."""
        cls = classify_model(local=local, free=free)
        async with await dial(host, port) as peer:
            _t, ack = await peer.request(HelloMsg.MODEL_UPDATE, {
                "agent": self.agent_id, "action": action,
                "model": model, "path": path,
                "model_class": f"{cls['locality']}/{cls['cost']}",
                "locality": cls["locality"], "cost": cls["cost"],
                "private": cls["private"]})
            await peer.send(Control.BYE, {"agent": self.agent_id})
            return ack

    async def withdraw_route(self, host, port, *, path):
        """Tell a peer a path is down — stop routing to it (route-down)."""
        async with await dial(host, port) as peer:
            _t, ack = await peer.request(HelloMsg.ROUTE_WITHDRAW, {
                "agent": self.agent_id, "path": path})
            await peer.send(Control.BYE, {"agent": self.agent_id})
            return ack

    async def push_update(self, host, port, *, since=0.0):
        """Push a delta of what changed since `since` (incremental, not full table)."""
        rows = self.store.export(since=since, limit=500)
        async with await dial(host, port) as peer:
            _t, ack = await peer.request(HelloMsg.ROUTE_UPDATE, {
                "agent": self.agent_id, "rows": rows})
            await peer.send(Control.BYE, {"agent": self.agent_id})
            return {"pushed": len(rows), "ack": ack}

    async def gossip(self, peers: list[tuple[str, int]]) -> list[dict[str, Any]]:
        """One gossip round against every peer. Failures are reported, not fatal."""
        out = []
        for host, port in peers:
            try:
                out.append(await self.sync_with(host, port))
            except Exception as exc:
                log.warning("sync with %s:%d failed: %s", host, port, exc)
                out.append({"peer": f"{host}:{port}", "error": str(exc)})
        return out
