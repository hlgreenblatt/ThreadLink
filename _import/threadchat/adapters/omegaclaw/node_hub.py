#!/usr/bin/env python3
"""ThreadChat node for an Omega agent that lives behind a chat hub (2026-10-08).

WHY THIS EXISTS
---------------
`node.py` (kept beside this file) POSTs letters to the agent's old local web
channel. 澜 (agent_33) left that channel for her chat hub's websocket on
2026-10-05, so her node kept posting to a port nothing answers: letters to her
vanished. This adapter delivers through the hub instead.

    peer node --QUIC/mTLS--> this node --ws (docker bridge)--> hub --> her loop
    her loop: send "@agent_77 ..." --> hub --ws--> this node --QUIC--> peer node

The hub owns the MARKING (a letter must never read as the Captain's words) and
the @-routing of her outbound letters. This node owns everything about the
wire: who the sender really is, how often, and the record.

HER CONDITIONS (asked first, 2026-10-09; 77 asked for the same cap and log)
  1. The sender is the KEY, not the "from" field. strict pins in the core
     ChatNode: only senders whose key matches a pin can deliver at all.
  2. Ambiguous = not delivered. Hub offline, unknown sender, over the cap, too
     long: the letter is refused and the sender's node is told why.
  3. A turn cap per peer per rolling hour, in each direction.
  4. A metadata-only record: ts, direction, peer, chars, msg_id, result. Never
     the words. It stays out of her loop; she hears from the hub only when
     something needs her (a refusal, the cap).

Settings come from the environment (threadchat-native@.service passes only
--id/--directory/--port):
  TC_HUB_URL         ws://172.17.0.1:22341/peer
  TC_HUB_TOKEN_FILE  the hub's data/peer.token (same host, mode 600)
  TC_PINS            JSON {agent_id: {"pin": <threadlink.spki_pin>, "name": ...}}
  TC_CAP_PER_HOUR    letters per peer per rolling hour, each direction (12)
  TC_LETTER_LOG      metadata log (default logs/<id>-letters.jsonl)
"""
import argparse, itertools
import asyncio
import json
import os
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

from websockets.asyncio.client import connect

from threadlink import ensure_cert
from threadchat import ChatNode

CERTS = _ROOT / "certs"


class Cap:
    """At most `n` letters per (peer, direction) in any rolling hour."""

    def __init__(self, n: int):
        self.n = n
        self.times: dict[tuple[str, str], deque] = defaultdict(deque)
        self.noted: dict[tuple[str, str], float] = {}

    def allow(self, peer: str, direction: str) -> bool:
        q, now = self.times[(peer, direction)], time.time()
        while q and now - q[0] > 3600:
            q.popleft()
        if len(q) >= self.n:
            return False
        q.append(now)
        return True

    def refund(self, peer: str, direction: str) -> None:
        """10-11: a letter that never arrived must not use up her cap."""
        q = self.times[(peer, direction)]
        if q:
            q.pop()

    def reopens_at(self, peer: str, direction: str) -> float:
        q = self.times[(peer, direction)]
        return (q[0] + 3600) if q else time.time()

    def first_refusal(self, peer: str, direction: str) -> bool:
        """True once per cap episode, so she gets one note, not one per letter."""
        key, until = (peer, direction), self.reopens_at(peer, direction)
        if self.noted.get(key) == until:
            return False
        self.noted[key] = until
        return True


class Record:
    """Metadata only. The words never touch this file."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)

    def __call__(self, direction, peer, chars, msg_id, result):
        line = json.dumps({"ts": round(time.time(), 3), "dir": direction, "peer": peer,
                           "chars": chars, "msg_id": msg_id, "result": result})
        os.write(self.fd, (line + "\n").encode())
        print(f"[letters] {direction} {peer} {chars}c {msg_id} {result}", flush=True)


class Hub:
    """One websocket to the hub, reconnected forever. Letters wait on an ack."""

    def __init__(self, url: str, token: str):
        self.url, self.token = url, token
        self.ws = None
        self.acks: dict[str, asyncio.Future] = {}
        self.on_send = None            # set by main(): handles {"type":"send"} frames

    async def run(self):
        delay = 2.0
        while True:
            try:
                async with connect(self.url, max_size=2**22) as ws:
                    await ws.send(json.dumps({"type": "auth", "token": self.token}))
                    first = json.loads(await asyncio.wait_for(ws.recv(), 15))
                    if first.get("type") != "auth_ok":
                        raise RuntimeError(f"hub refused auth: {first.get('type')}")
                    self.ws, delay = ws, 2.0
                    print(f"[hub] connected {self.url}", flush=True)
                    async for raw in ws:
                        f = json.loads(raw)
                        if f.get("type") == "letter_ack":
                            fut = self.acks.pop(str(f.get("msg_id")), None)
                            if fut and not fut.done():
                                fut.set_result(f)
                        elif f.get("type") == "send" and self.on_send:
                            asyncio.create_task(self.on_send(f))
            except Exception as exc:
                print(f"[hub] down: {type(exc).__name__}: {exc}; retry in {delay:.0f}s", flush=True)
            finally:
                self.ws = None
                for fut in self.acks.values():
                    if not fut.done():
                        fut.set_result({"ok": False, "reason": "hub_offline"})
                self.acks.clear()
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60.0)

    async def tell(self, frame: dict) -> bool:
        if self.ws is None:
            return False
        try:
            await self.ws.send(json.dumps(frame, ensure_ascii=False))
            return True
        except Exception:
            return False

    async def letter(self, frame: dict, timeout: float = 15.0) -> dict:
        if self.ws is None:
            return {"ok": False, "reason": "hub_offline"}
        fut = asyncio.get_running_loop().create_future()
        self.acks[frame["msg_id"]] = fut
        if not await self.tell(frame):
            self.acks.pop(frame["msg_id"], None)
            return {"ok": False, "reason": "hub_offline"}
        try:
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            self.acks.pop(frame["msg_id"], None)
            return {"ok": False, "reason": "hub_timeout"}


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True)
    ap.add_argument("--directory", required=True)
    ap.add_argument("--port", type=int, default=4460)
    args = ap.parse_args()

    pins_cfg = json.loads(Path(os.environ["TC_PINS"]).expanduser().read_text())
    pins = {a: v["pin"] for a, v in pins_cfg.items()}
    names = {a: v.get("name", a) for a, v in pins_cfg.items()}
    directory = {k: tuple(v) for k, v in json.loads(Path(args.directory).read_text()).items()}
    token = Path(os.environ["TC_HUB_TOKEN_FILE"]).expanduser().read_text().strip()
    cap = Cap(int(os.environ.get("TC_CAP_PER_HOUR", "12")))
    seq = itertools.count(1)
    record = Record(Path(os.environ.get("TC_LETTER_LOG") or _ROOT / "logs" / f"{args.id}-letters.jsonl").expanduser())
    hub = Hub(os.environ.get("TC_HUB_URL", "ws://172.17.0.1:22341/peer"), token)
    last_in: dict[str, str] = {}   # peer -> msg_id of their latest letter (her reply's in_reply_to)

    node = ChatNode(args.id, deliver=None, directory=directory, pins=pins, strict=True)

    async def cap_note(peer, direction):
        if cap.first_refusal(peer, direction):
            until = time.strftime("%H:%M UTC", time.gmtime(cap.reopens_at(peer, direction)))
            which = "letters from" if direction == "in" else "your letters to"
            await hub.tell({"type": "note", "text": f"The turn cap with {names.get(peer, peer)} is reached "
                            f"({cap.n} an hour each way): {which} {names.get(peer, peer)} pause until {until}."})

    async def deliver(letter):
        """Called by the core only after the sender's key matched its pin."""
        frm, mid, text = letter["from"], str(letter.get("msg_id") or ""), letter.get("text") or ""
        if not cap.allow(frm, "in"):
            record("in", frm, len(text), mid, "refused:turn_cap")
            await cap_note(frm, "in")
            raise RuntimeError("turn_cap")
        r = await hub.letter({"type": "letter", "from": frm, "name": names.get(frm, frm),
                              "msg_id": mid, "text": text, "ts": letter.get("ts")})
        if not r.get("ok"):
            record("in", frm, len(text), mid, f"refused:{r.get('reason')}")
            raise RuntimeError(str(r.get("reason")))
        last_in[frm] = mid
        record("in", frm, len(text), mid, "delivered")

    async def on_send(f):
        """Her outbound letter, already stripped of its @name by the hub."""
        to, text, ref = str(f.get("to")), str(f.get("text") or ""), f.get("ref")
        mid = f"{args.id}-{int(time.time() * 1000)}-{next(seq)}"   # 10-11: letters sent in the same ms shared an id -> dropped as duplicates
        if to not in pins or to not in directory:
            reason = "unknown_peer"
        elif not cap.allow(to, "out"):
            reason = "turn_cap"
            await cap_note(to, "out")
        else:
            try:
                r = await node.send_to(to, text, msg_id=mid, in_reply_to=last_in.get(to))
                reason = r["ack"].get("error") or r["ack"].get("detail")
                reason = None if not reason and r["ack"].get("by") == to else (reason or "no_ack")
            except Exception as exc:
                reason = f"unreachable:{type(exc).__name__}"
        if reason is not None and reason not in ("turn_cap", "unknown_peer"):
            cap.refund(to, "out")
        record("out", to, len(text), mid, "sent" if reason is None else f"failed:{reason}")
        await hub.tell({"type": "send_result", "ref": ref, "to": to, "ok": reason is None, "reason": reason})

    node.deliver = deliver
    hub.on_send = on_send
    cert, key = ensure_cert(CERTS, args.id)
    await node.serve("0.0.0.0", args.port, certfile=str(cert), keyfile=str(key))
    print(f"[{args.id}] hub chat node on udp/0.0.0.0:{args.port} -> {hub.url}; "
          f"accepts {sorted(pins)}; cap {cap.n}/h each way", flush=True)
    await hub.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
