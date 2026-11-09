"""
The shareable FabricPC route table.

WHAT WE SHARE, AND WHY IT IS NOT WEIGHTS
========================================
The obvious way to let two ThreadRouters share what they know is to ship the
FabricPC network's weights. We deliberately do not, for three reasons:

1. They do not fit each other. In tk_router the output layer is
   `N_OUT = len(PATHS) * len(ATTRS)`, and `PATHS` is derived from that agent's
   own ROSTER. An agent with a 3090 on the LAN has paths an agent on a laptop
   has never heard of. Weight tensors from a 9-path net are meaningless to a
   4-path net, and silently wrong if forced.

2. Weights are not inspectable. "Why did you start routing code to GLM?" has no
   answer you can read. Observations answer it directly, which matters for a
   governance story and for debugging a swarm at 2am.

3. Averaging weights across agents that saw different traffic is a known way to
   make every agent slightly worse. Averaging *evidence* is well defined.

So the unit of exchange is an OBSERVATION:

    (fingerprint, path_id, outcome bundle, how many times, when, who saw it)

which reads as: "for requests shaped like this, this path produced this
outcome." The receiver replays it through its own `Router.learn_outcome`, for
the paths it actually has, and ignores the rest. Heterogeneous fleets just work.

THE PRIVACY PROPERTY WE GET FOR FREE
====================================
`tk_router.fingerprint()` already documents itself as "No LLM, no raw text out"
— 8 floats of word shape (has_code_fence, is_question, length_norm, …). An
observation therefore contains no user text, no prompt, no reply. Agents can
pool routing experience across trust boundaries without pooling their users'
data. That was true before ThreadLink existed; it is what makes sharing safe,
and it is the reason this is a route table rather than a transcript.

THE TABLE
=========
Fingerprints are continuous, so raw ones would never repeat and the table would
grow forever. We quantize each fingerprint into a CELL — 6 binary shape flags
plus 2 bucketed continuous features — giving at most 2^6 * 4 * 4 = 1024 rows.
That is the route table: request-shape cell -> per-path expected outcome.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

# Mirrors tk_router.ATTRS. Duplicated rather than imported so threadhello does
# not drag the router (and its FabricPC/jax dependency) into every process;
# demo/with_threadrouter.py asserts the two lists agree before doing anything.
ATTRS = ["completed", "format_valid", "task_fit", "privacy", "cost", "latency"]

# Which fingerprint indices are continuous (see tk_router.FEATURES).
_CONTINUOUS = {2, 3}          # length_norm, numeric_density
_BUCKETS = 4

# Second-hand evidence is discounted: an observation relayed by a peer counts
# for less than one we measured ourselves. A swarm should be persuadable, not
# credulous — and this is the single knob that decides which.
DEFAULT_TRUST = 0.5

# Cap on how much a single cell/path can accumulate, so an agent that has been
# running for a month cannot drown out everyone else's fresher evidence.
MAX_WEIGHT = 50.0


def cell_key(fp: list[float]) -> str:
    """Quantize an 8-float fingerprint into a stable, low-cardinality cell id."""
    parts: list[str] = []
    for i, v in enumerate(fp):
        if i in _CONTINUOUS:
            b = min(_BUCKETS - 1, max(0, int(float(v) * _BUCKETS)))
            parts.append(str(b))
        else:
            parts.append("1" if float(v) >= 0.5 else "0")
    return "".join(parts)


@dataclass
class Observation:
    """Evidence about one (request shape, path) pair."""

    cell: str
    path: str
    bundle: dict[str, float]
    weight: float = 1.0                  # accumulated evidence, capped
    updated: float = field(default_factory=time.time)
    origin: str = "local"                # agent id that first measured it

    def to_wire(self) -> dict[str, Any]:
        return {
            "cell": self.cell,
            "path": self.path,
            "bundle": {a: round(float(self.bundle.get(a, 0.0)), 4) for a in ATTRS},
            "w": round(self.weight, 3),
            "ts": round(self.updated, 3),
            "origin": self.origin,
        }

    @classmethod
    def from_wire(cls, d: dict[str, Any]) -> "Observation":
        bundle = d.get("bundle") or {}
        if not isinstance(bundle, dict):
            raise ValueError("bundle must be an object")
        clean = {}
        for a in ATTRS:
            v = float(bundle.get(a, 0.0))
            if not (0.0 <= v <= 1.0):        # tk_router guarantees [0,1]
                raise ValueError(f"attr {a}={v} out of range")
            clean[a] = v
        cell = str(d["cell"])
        if len(cell) != 8 or not cell.isdigit():
            raise ValueError(f"malformed cell {cell!r}")
        return cls(
            cell=cell,
            path=str(d["path"]),
            bundle=clean,
            weight=max(0.0, min(MAX_WEIGHT, float(d.get("w", 1.0)))),
            updated=float(d.get("ts", time.time())),
            origin=str(d.get("origin", "unknown")),
        )


class RouteStore:
    """An agent's shareable route table.

    Holds first-hand observations and merged second-hand ones, exports deltas
    for gossip, and can replay everything into a live FabricPC router.
    """

    def __init__(self, agent_id: str, trust: float = DEFAULT_TRUST) -> None:
        self.agent_id = agent_id
        self.trust = trust
        self._obs: dict[tuple[str, str], Observation] = {}

    # ------------------------------------------------------------ first-hand
    def observe(self, fp: list[float], path: str, bundle: dict[str, float],
                weight: float = 1.0) -> Observation:
        """Record something this agent measured itself."""
        return self._absorb(Observation(
            cell=cell_key(fp), path=path,
            bundle={a: float(bundle.get(a, 0.0)) for a in ATTRS},
            weight=weight, origin=self.agent_id,
        ), factor=1.0)

    def withdraw_path(self, path):
        """Drop every observation for a path that has gone down (route-down).
        Returns how many rows were removed. Used by ROUTE_WITHDRAW / MODEL_UPDATE."""
        gone = [k for k in self._obs if k[1] == path]
        for k in gone:
            del self._obs[k]
        return len(gone)

    # ------------------------------------------------------------ second-hand
    def merge(self, records: Iterable[dict[str, Any]], *,
              known_paths: Optional[set[str]] = None) -> dict[str, int]:
        """Fold a peer's observations in. Returns a small audit summary.

        Three things are refused on purpose:
          * our own observations coming back around a gossip ring (origin == us)
          * paths this agent does not have (a laptop cannot route to your 3090)
          * anything malformed — one bad record must not poison a batch
        """
        stats = {"accepted": 0, "unknown_path": 0, "loop": 0, "malformed": 0}
        for rec in records:
            try:
                obs = Observation.from_wire(rec)
            except (KeyError, ValueError, TypeError):
                stats["malformed"] += 1
                continue
            if obs.origin == self.agent_id:
                stats["loop"] += 1
                continue
            if known_paths is not None and obs.path not in known_paths:
                stats["unknown_path"] += 1
                continue
            self._absorb(obs, factor=self.trust)
            stats["accepted"] += 1
        return stats

    def _absorb(self, obs: Observation, *, factor: float) -> Observation:
        """Weighted-average an observation into the table."""
        key = (obs.cell, obs.path)
        incoming_w = max(0.0, obs.weight * factor)
        cur = self._obs.get(key)
        if cur is None:
            obs.weight = min(MAX_WEIGHT, incoming_w)
            self._obs[key] = obs
            return obs
        total = cur.weight + incoming_w
        if total > 0:
            cur.bundle = {
                a: (cur.bundle.get(a, 0.0) * cur.weight
                    + obs.bundle.get(a, 0.0) * incoming_w) / total
                for a in ATTRS
            }
        cur.weight = min(MAX_WEIGHT, total)
        cur.updated = max(cur.updated, obs.updated)
        return cur

    # ---------------------------------------------------------------- export
    def export(self, since: float = 0.0, limit: int = 500) -> list[dict[str, Any]]:
        """Observations updated after `since`, newest first."""
        rows = [o for o in self._obs.values() if o.updated > since]
        rows.sort(key=lambda o: o.updated, reverse=True)
        return [o.to_wire() for o in rows[:limit]]

    # ------------------------------------------------------------ into router
    def teach(self, router: Any, epochs: int = 8) -> int:
        """Replay the table into a live tk_router.Router.

        The router keeps its own net; we only hand it evidence. `fp_of_cell`
        reconstructs a representative fingerprint from the cell id — exact for
        the binary features, bucket-centre for the two continuous ones, which is
        all the net needs to place the cell.
        """
        taught = 0
        for (cell, path), obs in self._obs.items():
            fp = fp_of_cell(cell)
            try:
                router.learn_outcome(fp, path, obs.bundle, epochs=epochs)
                taught += 1
            except Exception:
                continue          # an unknown path or cold net must not abort the batch
        return taught

    # ----------------------------------------------------------------- sundry
    def __len__(self) -> int:
        return len(self._obs)

    def summary(self) -> dict[str, Any]:
        first = sum(1 for o in self._obs.values() if o.origin == self.agent_id)
        return {
            "agent": self.agent_id,
            "rows": len(self._obs),
            "first_hand": first,
            "second_hand": len(self._obs) - first,
            "cells": len({c for c, _ in self._obs}),
            "paths": sorted({p for _, p in self._obs}),
        }


def fp_of_cell(cell: str) -> list[float]:
    """Inverse of `cell_key` — a representative fingerprint for a cell."""
    fp: list[float] = []
    for i, ch in enumerate(cell):
        if i in _CONTINUOUS:
            fp.append((int(ch) + 0.5) / _BUCKETS)     # bucket centre
        else:
            fp.append(float(int(ch)))
    return fp
