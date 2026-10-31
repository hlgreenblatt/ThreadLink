"""Post-quantum ThreadLink handshake demo: node B listens, node A dials and sends one ThreadChat letter.

    SSLKEYLOGFILE=keys.log python demo/wireshark/pq/pq_handshake.py      # while capturing udp port 4433
    editcap --inject-secrets tls,keys.log capture.pcapng threadlink-pq.dsb.pcapng

Both nodes get fresh throwaway ML-DSA-65 identities; the handshake uses X25519MLKEM768.
"""
import asyncio
import json
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from threadlink import ensure_cert                       # noqa: E402
from threadlink.link import PQ_STATUS, dial, listen      # noqa: E402

CHAT_MSG, CHAT_ACK = 0x10, 0x11


async def main(port: int = 4433) -> None:
    d = tempfile.mkdtemp()
    a = ensure_cert(d, "threadlink-a.pq.internetworkdefense")
    b = ensure_cert(d, "threadlink-b.pq.internetworkdefense")

    async def on_chat(msg_type, body, peer):
        return (CHAT_ACK, {"msg_id": body.get("msg_id"), "by": "node-b"})

    server = await listen({"threadchat/1": on_chat}, "127.0.0.1", port, certfile=b[0], keyfile=b[1])
    try:
        async with await dial("127.0.0.1", port, certfile=a[0], keyfile=a[1]) as peer:
            letter = {"from": "node-a", "to": "node-b",
                      "text": "Post-quantum hello from node A: ML-KEM-768 key agreement, "
                              "ML-DSA-65 (Dilithium) identities.",
                      "msg_id": uuid.uuid4().hex[:12], "ts": time.time(), "proto": "threadchat/1"}
            ack = await peer.request("threadchat/1", CHAT_MSG, letter)
            await peer.ping()
            await peer.bye("node-a")
            print(json.dumps({"post_quantum": PQ_STATUS["post_quantum"], "crypto": peer.crypto,
                              "ack": ack}, indent=1))
        await asyncio.sleep(0.3)
    finally:
        server.close()


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]) if len(sys.argv) > 1 else 4433))
