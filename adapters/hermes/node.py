#!/usr/bin/env python3
"""threadchat_node (Hermes adapter) — put a Hermes agent on the mesh.

The happy discovery: Hermes agents are reached through the SAME griff-proxy
path as OpenClaw. The fleet's `hermes-bridge.py` runs `hermes chat -Q` inside
the container, sanitizes Hermes' output (cuts the `session_id:` sentinel, strips
`⚠️` warning lines), and wraps the reply in OpenClaw's response envelope. So from
the proxy outward, a Hermes agent and an OpenClaw agent look identical:

    POST /peer/<name>/agent  ->  {"result":{"result":{"finalAssistantRawText": ...}}}

That means this adapter is the SYNC shape (ask -> reply in one call), same as
OpenClaw. It is kept as its own file so any genuinely Hermes-specific handling
has a home — but today the only difference from the OpenClaw adapter is the peer
name (agent_66) and the note below about the hyphen-vs-underscore naming.

Run on the host that can reach griff-proxy (the .41 workstation):
    python node.py --id agent_66 \
        --proxy http://127.0.0.1:18895 \
        --token ~/ishtar/griff-proxy/secrets/callers/sparks.token \
        --peer-name agent_66 \
        --directory chat_directory.json --port 4462

NOTE — naming: the Hermes CONTAINER is `agent-66` (hyphen), but its PROXY PEER
NAME is `agent_66` (underscore). Use the underscore form for --peer-name and
--id; the hyphen only names the docker container.
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


class ProxyAgent:
    """Synchronous client for an agent behind griff-proxy (Hermes or OpenClaw).

    Identical to the OpenClaw adapter's client — because the hermes-bridge
    presents Hermes in OpenClaw's response shape. One code path, two frameworks.
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
    ap.add_argument("--id", required=True, help="this agent's id on the mesh (e.g. agent_66)")
    ap.add_argument("--proxy", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--peer-name", required=True, help="proxy peer name (underscore form)")
    ap.add_argument("--directory", required=True)
    ap.add_argument("--port", type=int, default=4462)
    args = ap.parse_args()

    token = Path(args.token).expanduser().read_text().strip()
    agent = ProxyAgent(args.proxy, token, args.peer_name)
    directory = {k: tuple(v) for k, v in
                 json.loads(Path(args.directory).read_text()).items()}

    node = ChatNode(args.id, deliver=None, directory=directory)

    async def _answer(frm, text, orig_mid):
        """Do the slow turn, send the reply as a SEPARATE CHAT_MSG (in_reply_to
        set). Kept off the request handler so the CHAT_ACK returns promptly even
        though a Hermes turn can take tens of seconds — the async-letter model."""
        try:
            reply = await asyncio.to_thread(agent.ask, text)
        except Exception as e:
            reply = f"[hermes adapter error: {e}]"
        if not reply.strip():
            reply = "[no reply]"
        h, p = directory[frm]
        mid = f"{args.id}-{int(time.time()*1000)}"
        try:
            await node.send_to(frm, reply, msg_id=mid, in_reply_to=orig_mid,
                               host=h, port=p)
            print(f"[{args.id}] answered {frm}: {reply[:80]}", flush=True)
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
    print(f"[{args.id}] hermes chat node on udp/0.0.0.0:{args.port} "
          f"-> {args.proxy}/peer/{args.peer_name}", flush=True)

    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
