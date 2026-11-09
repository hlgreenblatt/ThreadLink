#!/usr/bin/env python3
"""threadchat_node — run ONE agent's ThreadChat presence on its host.

Fronts a local OmegaClaw agent through its local HTTP channel:
  - inbound  CHAT_MSG  --> POST /send   (lands in her loop as a message,
                                          tagged so she knows who is asking)
  - her reply on GET /messages  --> CHAT_MSG back to the agent who asked
                                    (in_reply_to set), so a question returns
                                    an answer with no human in the loop.

The directory (who lives where) is a small JSON file so all three hosts share
one map. Certs are the same per-agent TLS identities ThreadHello already uses.

Run (one per host), e.g. on .29 for 澜:
    python threadchat_node.py --id agent_33 \
        --local http://127.0.0.1:22333 --secret ~/agents/agent_33/.auth-secret \
        --directory chat_directory.json --port 4460
"""

import argparse
import asyncio
import json
import re
import time
import urllib.request
from pathlib import Path
import sys

# adapters/omegaclaw/node.py -> repo root is three levels up
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

from threadlink import ensure_cert
from threadchat import ChatNode

CERTS = _ROOT / "certs"

# A reply is "for" a chat question if it lands while we are waiting on one. We
# tag inbound chat text with a marker the agent is asked to keep, then match her
# outbound against the pending asker. Simple, and honest about its limits: if
# two askers are pending at once the newer wins (documented, not hidden).
CHAT_TAG = "[threadchat]"


class LocalAgent:
    """Thin client for one OmegaClaw local HTTP channel."""

    def __init__(self, base: str, secret: str):
        self.base = base.rstrip("/")
        self.secret = secret

    def _req(self, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        r = urllib.request.Request(
            self.base + path, data=data,
            headers={"Authorization": "Bearer " + self.secret,
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(r, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))

    def claim(self):
        """Bind this node as the channel's authenticated session (first POST with
        the header wins the single-session lock). Safe to call repeatedly."""
        try:
            self._req("/send", {"message": "[threadchat] node online"})
            return True
        except Exception as e:
            print(f"[claim] {e}", flush=True)
            return False

    def send(self, text):
        self._req("/send", {"message": text})

    def outbound_since(self, seq):
        d = self._req(f"/messages?since={seq}")
        msgs = d if isinstance(d, list) else d.get("messages", [])
        out = []
        for m in msgs:
            try:
                out.append((int(m.get("seq", 0)), str(m.get("text", ""))))
            except Exception:
                continue
        return sorted(out)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True)
    ap.add_argument("--local", required=True, help="local channel base URL")
    ap.add_argument("--secret", required=True, help="path to the agent's auth secret")
    ap.add_argument("--directory", required=True, help="chat_directory.json path")
    ap.add_argument("--port", type=int, default=4460)
    ap.add_argument("--poll", type=float, default=3.0, help="reply-watch interval s")
    args = ap.parse_args()

    secret = Path(args.secret).expanduser().read_text().strip()
    agent = LocalAgent(args.local, secret)
    directory = {k: tuple(v) for k, v in
                 json.loads(Path(args.directory).read_text()).items()}

    # pending[asker] = (their host, their port, original msg_id) — who is
    # awaiting an answer from us right now.
    pending = {}

    def deliver(letter):
        """Inbound letter -> the local agent's loop, tagged with the asker."""
        frm = letter["from"]
        text = letter["text"]
        mid = letter.get("msg_id") or ""
        if frm in directory:
            h, p = directory[frm]
            pending[frm] = (h, p, mid)
        # she sees who is asking and is nudged to answer plainly.
        agent.send(f"{CHAT_TAG} {frm} asks: {text}  "
                   f"(reply in one message; it will be sent back to {frm}.)")

    # Claim the local channel session up front so every subsequent /send and
    # /messages call is authorized. Without this the channel resets our polls.
    agent.claim()

    node = ChatNode(args.id, deliver, directory=directory)
    cert, key = ensure_cert(CERTS, args.id)
    await node.serve("0.0.0.0", args.port, certfile=str(cert), keyfile=str(key))
    print(f"[{args.id}] threadchat node on udp/0.0.0.0:{args.port} "
          f"fronting {args.local}", flush=True)

    # watch the agent's outbound; when she speaks while someone is pending,
    # relay her words back as a CHAT_MSG reply.
    seq = 0
    try:
        first = agent.outbound_since(0)
        seq = first[-1][0] if first else 0
    except Exception:
        seq = 0

    while True:
        await asyncio.sleep(args.poll)
        if not pending:
            # still advance seq so we do not relay backlog once a question lands
            try:
                cur = agent.outbound_since(seq)
                if cur:
                    seq = cur[-1][0]
            except Exception:
                pass
            continue
        try:
            new = agent.outbound_since(seq)
        except Exception as e:
            print(f"[{args.id}] outbound poll failed: {e}", flush=True)
            continue
        for s, text in new:
            seq = s
            clean = text.strip()
            if not clean or clean.startswith(CHAT_TAG):
                continue  # skip the echo of our own injected prompt
            # answer the most recent pending asker
            asker = next(reversed(pending))
            h, p, orig = pending.pop(asker)
            mid = f"{args.id}-{int(time.time()*1000)}"
            try:
                res = await node.send_to(asker, clean, msg_id=mid,
                                         in_reply_to=orig, host=h, port=p)
                print(f"[{args.id}] replied to {asker}: {clean[:80]} "
                      f"({res['handshake_ms']}ms)", flush=True)
            except Exception as e:
                print(f"[{args.id}] reply to {asker} failed: {e}", flush=True)
            break  # one answer per pending question


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
