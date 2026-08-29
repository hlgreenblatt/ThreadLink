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


# Assurance ladder — how much the CONTROLS around a model are backed, ordered
# weakest to strongest. This is deliberately separate from `locality`: a cloud
# processor under a signed DPA + a 3PAO attestation can be MORE defensible than
# an unvetted local box, so the two questions must not be collapsed into one flag.
#   unverified    — nothing known / no basis claimed
#   self_attested — the operator asserts controls, no third party involved
#   contractual   — a binding data-processing agreement (GDPR Art.28 processor)
#   certified     — independently assessed (3PAO / FedRAMP / ISO 27001 / SOC 2)
ASSURANCE_LADDER = ("unverified", "self_attested", "contractual", "certified")


def assurance_rank(level: str) -> int:
    """Position on the ladder (higher = stronger). Unknown terms rank lowest."""
    try:
        return ASSURANCE_LADDER.index(level)
    except ValueError:
        return 0


def classify_model(*, local: bool, free: bool,
                   assurance: str = "", basis: str = "") -> dict[str, Any]:
    """Describe a model on the axes a routing swarm actually acts on.

    locality  — where inference happens. LOCAL means the prompt never leaves the
                fleet; CLOUD means it goes to a third party.
    cost      — FREE or PAID at point of use.
    assurance — how well the controls around the model are BACKED, on the
                ASSURANCE_LADDER (unverified < self_attested < contractual <
                certified). `basis` is the free-text ground for it, e.g.
                "DPA / GDPR Art.28" or "3PAO / FedRAMP Moderate".

    Locality and assurance are orthogonal on purpose. "Did the prompt leave the
    fleet?" is a data-flow fact; "is the party that received it under an assessed
    control regime?" is a governance fact (data controller vs processor, 3PAO
    attestation, risk-acceptance of controls). A router may keep secret work
    local AND require assurance>=contractual before it will use any cloud route —
    two independent gates, not one boolean.

    These map onto the RouteStore attributes: privacy reflects locality lifted by
    assurance (a certified cloud processor scores better than a raw one), cost
    reflects free/paid.
    """
    # a sensible default assurance if the caller doesn't state one: a local model
    # is self-attested by the operator; a cloud model with no stated basis is
    # unverified until a DPA or attestation is claimed.
    if not assurance:
        assurance = "self_attested" if local else "unverified"
    rank = assurance_rank(assurance)
    # privacy: local starts high; cloud starts low but is lifted by assurance,
    # so certified-cloud is not treated the same as unverified-cloud.
    if local:
        privacy = 1.0
    else:
        privacy = 0.1 + 0.25 * rank        # unverified 0.10 .. certified 0.85
    return {
        "locality": "local" if local else "cloud",
        "cost": "free" if free else "paid",
        "assurance": assurance,            # unverified|self_attested|contractual|certified
        "assurance_rank": rank,
        "basis": basis,                    # free text: what backs the assurance
        "attrs": {"privacy": round(privacy, 3),
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
            assurance = str(body.get("assurance", "unverified"))
            basis = str(body.get("basis", ""))
            caps = self.peers_caps.setdefault(remote, set())
            if action == "added":
                caps.add(model)
                # remember what KIND of model this is, for assurance-aware routing:
                # locality (data-flow) AND assurance (controls) are stored apart.
                self.peer_model_class[(remote, model)] = {
                    "model_class": model_class,
                    "locality": body.get("locality", "?"),
                    "cost": body.get("cost", "?"),
                    "assurance": assurance,
                    "assurance_rank": assurance_rank(assurance),
                    "basis": basis,
                }
            elif action == "removed":
                caps.discard(model)
                self.peer_model_class.pop((remote, model), None)
                if path:
                    self.store.withdraw_path(path)   # its routes go too
            self.epoch += 1
            log.info("MODEL_UPDATE from %s: %s %s [%s, assurance=%s] (path=%s, epoch->%d)",
                     remote, action, model, model_class, assurance, path, self.epoch)
            return HelloMsg.HELLO_ACK, {"noted": model, "action": action,
                                        "model_class": model_class,
                                        "assurance": assurance,
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
                             local=True, free=True, assurance="", basis=""):
        """Tell a peer this agent gained ("added") or lost ("removed") a model.
        The agent-native message: capability changed, re-route accordingly.

        classify_model puts the model on the axes a peer routes by: `local`/`free`
        say WHERE it runs and what it costs; `assurance`/`basis` say how well the
        controls around it are BACKED (unverified < self_attested < contractual <
        certified — e.g. a cloud processor under a DPA, or a 3PAO attestation). A
        peer can then keep secrets local AND require assurance>=contractual before
        touching any cloud route — the instant it learns the model exists."""
        cls = classify_model(local=local, free=free,
                             assurance=assurance, basis=basis)
        async with await dial(host, port) as peer:
            _t, ack = await peer.request(HelloMsg.MODEL_UPDATE, {
                "agent": self.agent_id, "action": action,
                "model": model, "path": path,
                "model_class": f"{cls['locality']}/{cls['cost']}",
                "locality": cls["locality"], "cost": cls["cost"],
                "assurance": cls["assurance"], "basis": cls["basis"]})
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
