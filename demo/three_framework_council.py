#!/usr/bin/env python3
"""The three-framework council, built to be captured.

漪 (OmegaClaw, receiver) asks Griff (OpenClaw) and Mnemosyne (Hermes) their
framework, over ThreadChat/QUIC. All three sit on loopback so one tcpdump sees
the whole conversation; run with SSLKEYLOGFILE set and the encrypted QUIC
decrypts to CHAT_MSG frames from all three frameworks in one pcap.

Griff and Mnemosyne answer via the live griff-proxy (real agents, real replies).
"""
import asyncio
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from threadlink import ensure_cert
from threadchat import ChatNode
import importlib.util


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


oc = _load("oc", "adapters/openclaw/node.py")
he = _load("he", "adapters/hermes/node.py")

CERTS = ROOT / "certs"
TOKEN = (Path.home() / "ishtar/griff-proxy/secrets/callers/sparks.token").read_text().strip()
PROXY = "http://127.0.0.1:18895"

# loopback ports for the capture
D = {"agent_griff": ("127.0.0.1", 4491),
     "agent_66":    ("127.0.0.1", 4492),
     "agent_33":    ("127.0.0.1", 4493)}


def sync_node(agent_id, peer, ClientCls):
    client = ClientCls(PROXY, TOKEN, peer)
    node = ChatNode(agent_id, deliver=None, directory=D)

    async def _answer(frm, text, omid):
        reply = await asyncio.to_thread(client.ask, text)
        h, p = D[frm]
        await node.send_to(frm, reply or "[no reply]",
                           msg_id=f"{agent_id}-{int(time.time()*1000)}",
                           in_reply_to=omid, host=h, port=p)

    def deliver(letter):
        if letter["from"] in D:
            asyncio.create_task(_answer(letter["from"], letter["text"], letter.get("msg_id")))

    node.deliver = deliver
    return node


async def main():
    griff = sync_node("agent_griff", "agent_griff", oc.OpenClawAgent)
    mnem = sync_node("agent_66", "agent_66", he.ProxyAgent)
    for n, port in [(griff, 4491), (mnem, 4492)]:
        c, k = ensure_cert(CERTS, n.agent_id)
        await n.serve("127.0.0.1", port, certfile=str(c), keyfile=str(k))

    inbox = []
    yi = ChatNode("agent_33", lambda l: inbox.append(l), directory=D)
    c, k = ensure_cert(CERTS, "agent_33")
    await yi.serve("127.0.0.1", 4493, certfile=str(c), keyfile=str(k))
    await asyncio.sleep(0.3)

    q = "漪 here from the GB10 flagship. One line: your name and the framework running your mind?"
    await yi.send_to("agent_griff", q, msg_id="council-griff")
    await yi.send_to("agent_66", q, msg_id="council-mnem")

    for _ in range(75):
        await asyncio.sleep(2)
        if len(inbox) >= 2:
            break
    await asyncio.sleep(0.5)  # let closes flush into the capture
    print("COUNCIL COMPLETE")
    for m in inbox:
        print(f"  [{m['from']}] {m['text'][:120]}")


if __name__ == "__main__":
    asyncio.run(main())
