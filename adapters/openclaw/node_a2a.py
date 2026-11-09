#!/usr/bin/env python3
"""ThreadChat node for an OpenClaw agent, delivering over A2A instead of griff-proxy.

WHY THIS EXISTS (2026-09-30)
----------------------------
`node.py` (kept beside this file for rollback) delivered a letter by POSTing to
griff-proxy, which POSTed to a per-container bridge, which **forked a cold CLI per
message**:

    openclaw agent --agent main --session-id lingxi-bridge --message "<text>" --json

Three consequences, all of which this file removes:

  1. NO SESSION CONTINUITY. Every letter reused one fixed session id, and the reply
     was recovered by brace-scanning stdout+stderr. On 2026-09-30 观照 truthfully
     answered "No" when asked whether she had received a letter she had answered
     68 seconds earlier — a different invocation, so no shared history.
  2. LETTERS ARRIVED AS PROMPT TEXT, not as chat events (CAMPAIGN.md BUG-1: Ellie
     read one as a system note). The agent had no sender identity to attribute.
  3. Two extra network hops and a shared caller secret for the whole fleet.

A2A (Linux Foundation Agent2Agent 1.0) is bundled with OpenClaw 2026.9.6 and was
simply switched off. It gives us, on the gateway port that is ALREADY published:
  * `POST /a2a/v1` JSON-RPC `SendMessage` that waits for the real reply
  * `message.contextId` -> a persistent conversation, so we key it on the SENDER
    and every peer gets its own continuous, isolated thread with this agent
    (verified: same contextId recalls a number, a different one cannot see it)
  * per-peer bearer tokens instead of one fleet-wide caller secret
  * the authenticated peer becomes the sender identity for normal channel ingress
    policy, so a letter is a real chat event

SCOPE — READ THIS BEFORE "SIMPLIFYING"
--------------------------------------
A2A can also send OUTBOUND straight to another agent's HTTP endpoint. We deliberately
do NOT use that: it would make plain HTTP the agent-to-agent transport and bypass
ThreadLink, which is the whole point of the mesh (CAMPAIGN.md:21-22, "NO central
broker ... That IS the P2P thesis"). A2A here is ONLY the loopback last mile into the
local gateway. The agent-to-agent hop stays ThreadChat over QUIC/mutual-TLS.
"""
import argparse
import asyncio
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

from threadlink import ensure_cert
from threadchat import ChatNode

CERTS = _ROOT / "certs"

# A2A allows letters, digits, '.', '_', ':', '-' in a contextId, max 128 chars.
_CTX_BAD = re.compile(r"[^A-Za-z0-9._:-]")


class A2AAgent:
    """Synchronous A2A client for one local OpenClaw gateway.

    ask(text, sender) -> the agent's reply text. `sender` becomes the A2A
    contextId, which is what buys per-peer conversation continuity.
    """

    def __init__(self, url: str, token: str, timeout: float = 240.0,
                 poll_deadline: float = 600.0):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout
        # If the turn outruns the gateway's replyTimeoutMs it hands back a WORKING
        # task instead of cancelling it, so we poll rather than lose the answer.
        self.poll_deadline = poll_deadline

    # -- wire helpers ------------------------------------------------------
    def _rpc(self, method: str, params: dict, rpc_id: str) -> dict:
        body = json.dumps({"jsonrpc": "2.0", "id": rpc_id,
                           "method": method, "params": params}).encode()
        req = urllib.request.Request(
            f"{self.url}/a2a/v1", data=body,
            headers={"Authorization": f"Bearer {self.token}",
                     "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))

    @staticmethod
    def _context_for(sender: str) -> str:
        return _CTX_BAD.sub("_", sender or "unknown")[:128]

    @staticmethod
    def _text_of(task: dict) -> str:
        for art in task.get("artifacts") or []:
            for part in art.get("parts") or []:
                if part.get("text"):
                    return part["text"]
        return ""

    # -- the one call the node makes ---------------------------------------
    def ask(self, text: str, sender: str = "unknown", thread: str = "") -> str:
        rid = f"tc-{int(time.time()*1000)}"
        # 10-18: a letter carrying a thread (a ThreadTask) gets its own A2A context; none = the per-sender thread.
        ctx = self._context_for("task-" + thread) if thread else self._context_for(sender)
        res = self._rpc("SendMessage", {"message": {
            "messageId": rid,
            "contextId": ctx,
            "role": "ROLE_USER",
            "parts": [{"text": text}],
        }}, rid)
        if "error" in res:
            e = res["error"]
            return f"[a2a error {e.get('code')}: {str(e.get('message'))[:160]}]"
        task = (res.get("result") or {}).get("task") or {}
        state = (task.get("status") or {}).get("state", "")

        # Long turn: the gateway returned WORKING. Poll GetTask to the deadline.
        if state == "TASK_STATE_WORKING" and task.get("id"):
            start = time.time()
            while time.time() - start < self.poll_deadline:
                time.sleep(5)
                try:
                    p = self._rpc("GetTask", {"id": task["id"]}, f"{rid}-poll")
                except Exception:
                    continue
                task = (p.get("result") or {}).get("task") or task
                state = (task.get("status") or {}).get("state", "")
                if state != "TASK_STATE_WORKING":
                    break

        out = self._text_of(task)
        if out:
            return out
        if state and state != "TASK_STATE_COMPLETED":
            return f"[a2a task {state.replace('TASK_STATE_', '').lower()}]"
        return ""


def _env_or_flag(value, env_name):
    return value if value else os.environ.get(env_name, "")


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True, help="this agent's id on the mesh")
    # Flags fall back to env so the systemd unit's ExecStart stops encoding one
    # adapter's CLI shape (the old threadchat-proxy@.service hardcoded
    # --proxy/--token/--peer-name, which is why a new adapter needed a new unit).
    ap.add_argument("--a2a-url", default="", help="local gateway base URL (env TC_A2A_URL)")
    ap.add_argument("--a2a-token", default="", help="path to this agent's A2A peer token (env TC_A2A_TOKEN)")
    ap.add_argument("--directory", required=True)
    ap.add_argument("--port", type=int, default=4461)
    args = ap.parse_args()

    url = _env_or_flag(args.a2a_url, "TC_A2A_URL")
    tok_path = _env_or_flag(args.a2a_token, "TC_A2A_TOKEN")
    if not url or not tok_path:
        raise SystemExit("node_a2a: need --a2a-url/TC_A2A_URL and --a2a-token/TC_A2A_TOKEN")

    token = Path(tok_path).expanduser().read_text().strip()
    agent = A2AAgent(url, token)
    directory = {k: tuple(v) for k, v in
                 json.loads(Path(args.directory).read_text()).items()}

    node = ChatNode(args.id, deliver=None, directory=directory)

    async def _answer(frm, text, orig_mid, thread=""):
        """Do the slow turn and send the reply as a SEPARATE CHAT_MSG.

        Kept off the request handler on purpose: an agent turn takes tens of
        seconds, but the CHAT_ACK for the incoming letter must return promptly.
        deliver() schedules this and returns; the answer arrives later as its own
        letter with in_reply_to set — the async-letter model the protocol is built
        around. threadchat/chat.py:109-115 deliberately does NOT await a Task, so
        this must stay a task, not a coroutine the handler awaits.
        """
        try:
            reply = await asyncio.to_thread(agent.ask, text, frm, thread or "")
        except Exception as e:
            reply = f"[adapter error: {type(e).__name__}: {e}]"
        if not reply.strip():
            reply = "[no reply]"
        h, p = directory[frm]
        mid = f"{args.id}-{int(time.time()*1000)}"
        try:
            await node.send_to(frm, reply, msg_id=mid, in_reply_to=orig_mid,
                               host=h, port=p, thread=thread or None)
            print(f"[{args.id}] answered {frm}: {len(reply)} chars", flush=True)   # never the words (10-09 condition)
        except Exception as e:
            print(f"[{args.id}] reply to {frm} failed: {e}", flush=True)

    def deliver(letter):
        """Ack fast, answer later: schedule the slow turn, return immediately."""
        frm = letter["from"]
        # The core accepts a CHAT_MSG from ANY peer completing mutual TLS
        # (server_config runs verify_mode=CERT_NONE), so directory membership is
        # the only authorization there is. Keep this check.
        if frm not in directory:
            print(f"[{args.id}] dropped letter from unknown sender {frm!r}", flush=True)
            return
        asyncio.create_task(_answer(frm, letter["text"], letter.get("msg_id"), letter.get("thread") or ""))

    node.deliver = deliver
    cert, key = ensure_cert(CERTS, args.id)
    await node.serve("0.0.0.0", args.port, certfile=str(cert), keyfile=str(key))
    print(f"[{args.id}] openclaw A2A chat node on udp/0.0.0.0:{args.port} "
          f"-> {url}/a2a/v1 (contextId = sender)", flush=True)

    while True:
        await asyncio.sleep(3600)  # serve forever; all work is event-driven


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
