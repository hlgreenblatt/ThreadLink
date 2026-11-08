#!/usr/bin/env python3
"""threadchat_node (OpenClaw adapter) — put an OpenClaw agent on the mesh.

OpenClaw differs from OmegaClaw in one structural way, and the adapter shape
follows it: OpenClaw is SYNCHRONOUS. A message posted to griff-proxy
(`POST /peer/<name>/agent`) runs the agent's turn and returns its reply in the
SAME HTTP response. So there is no inject-then-poll and no outbox to watch: when
a CHAT_MSG arrives, we ask the agent and relay the answer straight back.

That makes this the reference "sync adapter" (OmegaClaw is the "async adapter").
Both satisfy the same ThreadChat contract; only the wiring to the local agent
differs.

Run on the host that can reach griff-proxy (the .41 workstation):
    python node.py --id agent_griff \
        --proxy http://127.0.0.1:18895 \
        --token ~/ishtar/griff-proxy/secrets/callers/sparks.token \
        --peer-name agent_griff \
        --directory chat_directory.json --port 4461
"""

import argparse
import asyncio
import json
import time
import urllib.request
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

from threadlink import ensure_cert
from threadchat import ChatNode

CERTS = _ROOT / "certs"


class OpenClawAgent:
    """Synchronous client for one OpenClaw agent via griff-proxy.

    ask(text) -> the agent's reply text, in one call. The proxy runs the turn
    server-side; we just carry the question in and the answer out.
    """

    def __init__(self, proxy: str, token: str, peer_name: str, timeout: float = 240.0):
        self.proxy = proxy.rstrip("/")
        self.token = token
        self.peer_name = peer_name
        self.timeout = timeout

    def ask(self, text: str) -> str:
        body = json.dumps({"message": text, "agent": "main"}).encode()
        req = urllib.request.Request(
            f"{self.proxy}/peer/{self.peer_name}/agent", data=body,
            headers={"X-Proxy-Token": self.token, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            d = json.loads(resp.read().decode("utf-8", errors="replace"))
        # proxy -> outer .result -> openclaw -> inner .result.finalAssistantRawText
        inner = d.get("result", {}).get("result", {})
        text_out = inner.get("finalAssistantRawText")
        if not text_out:
            try:
                text_out = inner.get("payloads", [{}])[0].get("text", "")
            except Exception:
                text_out = ""
        return text_out or ""


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True, help="this agent's id on the mesh")
    ap.add_argument("--proxy", required=True, help="griff-proxy base URL")
    ap.add_argument("--token", required=True, help="path to the caller token")
    ap.add_argument("--peer-name", required=True,
                    help="the agent's peer name at the proxy (e.g. agent_griff)")
    ap.add_argument("--directory", required=True)
    ap.add_argument("--port", type=int, default=4461)
    args = ap.parse_args()

    token = Path(args.token).expanduser().read_text().strip()
    agent = OpenClawAgent(args.proxy, token, args.peer_name)
    directory = {k: tuple(v) for k, v in
                 json.loads(Path(args.directory).read_text()).items()}

    node = ChatNode(args.id, deliver=None, directory=directory)

    async def _answer(frm, text, orig_mid):
        """Do the slow turn and send the reply as a SEPARATE CHAT_MSG.

        Kept off the request handler on purpose: a sync agent's turn can take
        tens of seconds, but the CHAT_ACK for the incoming letter must return
        promptly. So deliver() schedules this and returns; the answer arrives
        later as its own letter, with in_reply_to set. (This is exactly the
        async-letter model the protocol is built around.)
        """
        try:
            reply = await asyncio.to_thread(agent.ask, text)
        except Exception as e:
            reply = f"[adapter error: {e}]"
        if not reply.strip():
            reply = "[no reply]"
        h, p = directory[frm]
        mid = f"{args.id}-{int(time.time()*1000)}"
        try:
            await node.send_to(frm, reply, msg_id=mid, in_reply_to=orig_mid,
                               host=h, port=p)
            print(f"[{args.id}] answered {frm}: {len(reply)} chars", flush=True)   # never the words (10-09)
        except Exception as e:
            print(f"[{args.id}] reply to {frm} failed: {e}", flush=True)

    def deliver(letter):
        """Ack fast, answer later: schedule the slow turn, return immediately."""
        frm = letter["from"]
        if frm not in directory:
            return
        asyncio.create_task(_answer(frm, letter["text"], letter.get("msg_id")))

    node.deliver = deliver
    cert, key = ensure_cert(CERTS, args.id)
    await node.serve("0.0.0.0", args.port, certfile=str(cert), keyfile=str(key))
    print(f"[{args.id}] openclaw chat node on udp/0.0.0.0:{args.port} "
          f"-> {args.proxy}/peer/{args.peer_name}", flush=True)

    while True:
        await asyncio.sleep(3600)  # serve forever; all work is event-driven


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
