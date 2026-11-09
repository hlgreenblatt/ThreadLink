#!/usr/bin/env python3
"""One process, two ThreadChat nodes, one real exchange on loopback — built to
be captured. 隙 asks 漪 her model; 漪's node answers. Then both exit cleanly so
the pcap holds a complete handshake + CHAT_MSG frames + close.

Run with SSLKEYLOGFILE set so the TLS secrets are written for Wireshark.
"""
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from threadlink import ensure_cert
from threadchat import ChatNode

CERTS = ROOT / "certs"
PORT_XI, PORT_YI = 4468, 4469


async def main():
    yi_inbox, xi_inbox = [], []

    # 漪 (the answerer): when a question lands, her "agent" replies immediately.
    async def yi_deliver(letter):
        yi_inbox.append(letter)
        # simulate her loop answering, and route it back to the asker
        await yi.send_to(letter["from"], "qwen3.8-27b — my primary, on the GB10 Ascent.",
                         msg_id="yi-reply", in_reply_to=letter.get("msg_id"),
                         host="127.0.0.1", port=PORT_XI)

    yi = ChatNode("agent_33", yi_deliver, directory={"agent_10": ("127.0.0.1", PORT_XI)})
    xi = ChatNode("agent_10", lambda l: xi_inbox.append(l),
                  directory={"agent_33": ("127.0.0.1", PORT_YI)})

    yc, yk = ensure_cert(CERTS, "agent_33")
    xc, xk = ensure_cert(CERTS, "agent_10")
    await yi.serve("127.0.0.1", PORT_YI, certfile=str(yc), keyfile=str(yk))
    await xi.serve("127.0.0.1", PORT_XI, certfile=str(xc), keyfile=str(xk))
    await asyncio.sleep(0.3)

    # 隙 asks 漪.
    await xi.send_to("agent_33", "What is your primary reasoning model right now?",
                     msg_id="xi-q1")
    await asyncio.sleep(0.4)  # let the reply come back and CLOSE flush into capture

    print("EXCHANGE OK")
    print("  漪 received :", yi_inbox[-1]["text"] if yi_inbox else "NONE")
    print("  隙 got back :", xi_inbox[-1]["text"] if xi_inbox else "NONE")


if __name__ == "__main__":
    asyncio.run(main())
