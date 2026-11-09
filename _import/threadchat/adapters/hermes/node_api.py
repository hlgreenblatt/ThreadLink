#!/usr/bin/env python3
"""ThreadChat node for a Hermes agent, delivering via Hermes' OWN HTTP API.

WHY THIS EXISTS (2026-09-30)
----------------------------
`node.py` (kept beside this file for rollback) delivered a letter by POSTing to
griff-proxy, which POSTed to a per-container bridge, which **forked a cold CLI per
message**:

    hermes chat -Q --yolo -p default -q "<text>"

and then recovered the answer by screen-scraping stdout (truncate at
"\\nsession_id:", drop lines starting "⚠️"). Consequences this file removes:

  1. NO SESSION CONTINUITY. Each letter was a brand-new invocation. On 2026-09-30
     观照 truthfully answered "No" when asked about a letter she had answered 68
     seconds earlier — a different process with no shared history.
  2. LETTERS ARRIVED AS PROMPT TEXT (CAMPAIGN.md BUG-1), with no sender identity.
  3. Two extra hops, a fleet-wide shared caller secret, and a regex on human-
     formatted terminal output as the parsing contract.

Hermes already ships `gateway/platforms/api_server.py` — a full aiohttp platform —
and it was simply not enabled. It gives:
  * `POST /api/sessions` to create a session with an id WE choose, so we key one
    session per SENDER and each peer gets a continuous, separate thread
  * `POST /api/sessions/{id}/chat` -> {"message": {"role":"assistant","content": ...}}
  * bearer auth via API_SERVER_KEY (already provisioned in each agent's .env)

Enable it per agent in config.yaml — note the settings go under `extra`, because
PlatformConfig (gateway/config.py:384) keeps platform-specific keys there:

    platforms:
      api_server:
        enabled: true
        extra:
          host: "0.0.0.0"     # so this host reaches it at the container IP
          port: 8642

`host: 0.0.0.0` matters: the node runs on the host and reaches the container
directly on the docker bridge (172.18.0.x), so NO published port and NO container
recreate are needed — only a restart.

SCOPE: the agent-to-agent hop stays ThreadChat over QUIC/mutual-TLS. This API is
only the last mile into the local container (CAMPAIGN.md:21-22, the P2P thesis).
"""
import argparse
import asyncio
import hmac
import json
import os
import re
import socket
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

# Session ids: keep them tame and deterministic per sender.
_SID_BAD = re.compile(r"[^A-Za-z0-9._:-]")


def read_env_value(envfile: str, name: str) -> str:
    """Pull one value out of a .env without importing it. Avoids duplicating the
    secret into a second file just so this adapter can read it."""
    pat = re.compile(rf"^\s*(?:export\s+)?{re.escape(name)}\s*=\s*(.*)$")
    for line in Path(envfile).expanduser().read_text(errors="ignore").splitlines():
        m = pat.match(line)
        if m:
            return m.group(1).strip().strip('"').strip("'")
    raise SystemExit(f"node_api: {name} not found in {envfile}")


class HermesAPIAgent:
    """Synchronous client for one local Hermes api_server.

    ask(text, sender) -> reply text. `sender` selects the session, which is what
    buys per-peer continuity.
    """

    def __init__(self, url: str, key: str, timeout: float = 240.0):
        # 2026-10-01: 240s was an arbitrary default and it is too low for turns that do real
        # tool work. 观照 timed out twice drafting a document because of THIS limit, not
        # because of anything she did. Override with TC_API_TIMEOUT.
        self.url = url.rstrip("/")
        self.key = key
        self.timeout = timeout
        self._ready: set[str] = set()   # sessions we've already ensured

    def _req(self, method: str, path: str, body=None, timeout=None):
        req = urllib.request.Request(
            f"{self.url}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self.key}",
                     "Content-Type": "application/json"},
            method=method)
        with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
            raw = r.read().decode("utf-8", "replace")
        return json.loads(raw) if raw.strip() else {}

    def _session_for(self, sender: str, thread: str = "") -> str:
        # 10-18: a letter carrying a thread (a ThreadTask) gets a conversation of its own, so a nightly invitation no
        # longer lands under last night's answer (66 + Theia handed back their 10-17 pieces on 10-18).
        if thread:
            sid = "task-" + _SID_BAD.sub("_", thread)[:96]
        else:
            sid = "threadchat-" + _SID_BAD.sub("_", sender or "unknown")[:96]
        if sid in self._ready:
            return sid
        try:
            self._req("POST", "/api/sessions", {"session_id": sid}, timeout=30)
        except urllib.error.HTTPError as e:
            # Already there is success for our purposes; anything else is worth
            # surfacing rather than swallowing.
            if e.code not in (200, 201, 409):
                body = e.read().decode("utf-8", "replace")[:160] if hasattr(e, "read") else ""
                if "exist" not in body.lower():
                    raise
        self._ready.add(sid)
        return sid

    @staticmethod
    def _text_of(d: dict) -> str:
        msg = d.get("message")
        if isinstance(msg, dict) and isinstance(msg.get("content"), str):
            return msg["content"]
        for k in ("reply", "text", "content"):
            if isinstance(d.get(k), str):
                return d[k]
        return ""

    def ask(self, text: str, sender: str = "unknown", thread: str = "") -> str:
        sid = self._session_for(sender, thread)
        try:
            d = self._req("POST", f"/api/sessions/{sid}/chat", {"message": text})
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:200] if hasattr(e, "read") else ""
            # A session can be pruned out from under us; rebuild once and retry.
            if e.code == 404:
                self._ready.discard(sid)
                sid = self._session_for(sender, thread)
                d = self._req("POST", f"/api/sessions/{sid}/chat", {"message": text})
            else:
                return f"[api_server HTTP {e.code}: {body}]"
        return self._text_of(d) or ""


LETTER_REASONS = {
    "turn_cap": "the hourly turn cap with that agent is reached; try again later",
    "recipient_offline": "that agent's loop is offline right now; try again later",
    "hub_offline": "that agent's channel is offline right now; try again later",
    "hub_timeout": "that agent's channel did not answer in time; try again later",
    "too_long": "the letter is too long for that agent's limit; shorten it",
    "sender_key_mismatch": "that agent's node did not accept your key (tell Sparks)",
    "unknown_sender": "that agent's node does not accept letters from you (tell Sparks)",
}


def letter_tool_app(node, directory, names, sent, me, allowed, token, host, port):
    """send_letter as an MCP tool (2026-10-09, step 2: the agent can START a thread, not only answer).

    It lives in the node because the node holds the agent's key and receives the answers: when one arrives, deliver()
    can say which letter it answers, since the tool letter was written in some other conversation. Held in memory only.
    """
    from mcp.server import MCPServer
    from mcp.server.transport_security import TransportSecuritySettings

    who = ", ".join(f"{a} ({names.get(a, a)})" for a in allowed)
    mcp = MCPServer(name="threadchat-letters", instructions=(
        f"Letters over ThreadChat, signed with your own key ({me}). You can write to: {who}. A letter goes to that "
        "agent only. An answer, if one comes, arrives as a ThreadChat letter in your separate conversation with that "
        "agent (session threadchat-<their id>), not in the conversation you send from. Turn cap: 12 letters an hour each "
        "way. The record keeps only who, when and size, never the words."))

    @mcp.tool()
    async def send_letter(to: str, text: str) -> str:
        """Send one letter to another agent over ThreadChat. `to` is the agent id (for example agent_33 for 澜)."""
        to = to.strip()
        if to not in allowed or to not in directory:
            return f"Not sent: you can write to {who} only."
        if not text.strip():
            return "Not sent: the letter is empty."
        mid = f"{me}-{int(time.time() * 1000)}"
        try:
            ack = (await node.send_to(to, text, msg_id=mid)).get("ack") or {}
        except Exception as e:
            print(f"[{me}] letter tool: {to} unreachable {type(e).__name__}", flush=True)
            return f"Not delivered: {names.get(to, to)}'s node could not be reached; try again later."
        if ack.get("by") == to and not ack.get("error"):
            sent[mid] = (time.strftime("%H:%MZ", time.gmtime()), text.strip()[:400])
            while len(sent) > 50:
                sent.pop(next(iter(sent)))
            print(f"[{me}] letter tool: sent {to} {len(text)} chars", flush=True)
            return (f"Delivered to {names.get(to, to)} ({to}) at {time.strftime('%H:%M UTC', time.gmtime())}. An answer, "
                    "if one comes, arrives in your ThreadChat conversation with that agent, not here.")
        reason = ack.get("detail") or ack.get("error") or "no acknowledgement"
        print(f"[{me}] letter tool: {to} refused {reason}", flush=True)
        return f"Not delivered: {LETTER_REASONS.get(reason, reason)}."

    inner = mcp.streamable_http_app(stateless_http=True, json_response=True, transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True, allowed_hosts=[f"{host}:{port}", host], allowed_origins=[]))

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return await inner(scope, receive, send)
        auth = dict(scope["headers"]).get(b"authorization", b"").decode()
        if not (auth.startswith("Bearer ") and hmac.compare_digest(auth[7:].encode(), token.encode())):
            body = b'{"error":"threadchat-letters: unknown caller"}'
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
            return await send({"type": "http.response.body", "body": body})
        return await inner(scope, receive, send)
    return app


async def serve_letter_tool(app, host, port, me):
    """The docker bridge may not exist yet at boot (griff-proxy's Errno 99, 2026-09-23): wait for it, never crash."""
    import uvicorn
    while True:
        try:
            with socket.socket() as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
        except OSError as e:
            print(f"[{me}] letter tool: cannot bind {host}:{port} yet ({e.strerror}); retry in 20s", flush=True)
            await asyncio.sleep(20)
            continue
        print(f"[{me}] letter tool (MCP) on http://{host}:{port}/mcp", flush=True)
        await uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning", lifespan="on")).serve()
        await asyncio.sleep(5)


def _env_or_flag(value, env_name):
    return value if value else os.environ.get(env_name, "")


def resolve_container_url(name: str, port: int) -> str:
    """Build the api_server URL from a CONTAINER NAME, resolved at startup.

    Pinning the bridge IP in the unit's env file works until a container is
    recreated in a different order and docker hands out a different address —
    then every node silently talks to the wrong place (or nothing). Resolving the
    name each time the node starts makes that self-healing, and systemd restarts
    the node on failure anyway.
    """
    import subprocess
    out = subprocess.run(
        ["docker", "inspect", "--format",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name],
        capture_output=True, text=True, timeout=25)
    ip = (out.stdout or "").split()
    if not ip:
        raise SystemExit(f"node_api: cannot resolve container {name!r}: "
                         f"{(out.stderr or '').strip()[:160]}")
    return f"http://{ip[0]}:{port}"


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True, help="this agent's id on the mesh")
    ap.add_argument("--api-url", default="", help="local api_server base URL (env TC_API_URL)")
    ap.add_argument("--api-container", default="",
                    help="container name to resolve the api_server IP from at startup "
                         "(env TC_API_CONTAINER); preferred over a pinned --api-url")
    ap.add_argument("--api-port", type=int, default=8642)
    ap.add_argument("--api-envfile", default="",
                    help="path to the agent's .env holding API_SERVER_KEY (env TC_API_ENVFILE)")
    ap.add_argument("--api-key-name", default="API_SERVER_KEY")
    ap.add_argument("--directory", required=True)
    ap.add_argument("--port", type=int, default=4462)
    args = ap.parse_args()

    container = _env_or_flag(args.api_container, "TC_API_CONTAINER")
    port = int(os.environ.get("TC_API_PORT") or args.api_port)
    url = resolve_container_url(container, port) if container else _env_or_flag(args.api_url, "TC_API_URL")
    envfile = _env_or_flag(args.api_envfile, "TC_API_ENVFILE")
    if not url or not envfile:
        raise SystemExit("node_api: need --api-container/TC_API_CONTAINER (or "
                         "--api-url/TC_API_URL) and --api-envfile/TC_API_ENVFILE")

    agent = HermesAPIAgent(url, read_env_value(envfile, args.api_key_name),
                           timeout=float(os.environ.get("TC_API_TIMEOUT", "240")))
    directory = {k: tuple(v) for k, v in
                 json.loads(Path(args.directory).read_text()).items()}

    # Optional (2026-10-09): pin senders' keys (TC_PINS, same file shape as omegaclaw/node_hub.py) so a letter
    # signed "agent_33" must come from 澜's key, and tell the agent who wrote (TC_MARK_SENDER=1). Unset = as before.
    pins_cfg = json.loads(Path(os.environ["TC_PINS"]).expanduser().read_text()) if os.environ.get("TC_PINS") else {}
    pins = {a: v["pin"] for a, v in pins_cfg.items()}
    names = {a: v.get("name", a) for a, v in pins_cfg.items()}
    mark = os.environ.get("TC_MARK_SENDER") == "1"
    sent: dict[str, tuple[str, str]] = {}   # msg_id -> (time, opening) of letters the agent sent with the tool
    node = ChatNode(args.id, deliver=None, directory=directory, pins=pins)

    async def _answer(frm, text, orig_mid, thread=""):
        """Slow turn off the request handler; reply as its own CHAT_MSG.

        threadchat/chat.py:109-115 deliberately does not await a Task, so this
        must stay a task — that is what keeps the incoming letter's CHAT_ACK fast
        while a turn takes tens of seconds.
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
            print(f"[{args.id}] answered {frm}: {len(reply)} chars", flush=True)   # never the words (10-09)
        except Exception as e:
            print(f"[{args.id}] reply to {frm} failed: {e}", flush=True)

    def deliver(letter):
        """Ack fast, answer later."""
        frm = letter["from"]
        # The core accepts a CHAT_MSG from any peer that completes mutual TLS
        # (server_config uses verify_mode=CERT_NONE), so directory membership is
        # the only authorization there is. Keep this check.
        if frm not in directory:
            print(f"[{args.id}] dropped letter from unknown sender {frm!r}", flush=True)
            return
        text = letter["text"]
        ctx = sent.pop(str(letter.get("in_reply_to") or ""), None)
        if ctx:
            text = (f"(In reply to the letter you wrote to {names.get(frm, frm)} at {ctx[0]} from another conversation. "
                    f"It began: \"{ctx[1]}\")\n{text}")
        if mark:
            who = f"{names[frm]} ({frm}), sender key verified" if frm in pins else f"{frm}, sender key NOT verified"
            text = f"[ThreadChat letter from {who}]\n{text}"
        asyncio.create_task(_answer(frm, text, letter.get("msg_id"), letter.get("thread") or ""))

    node.deliver = deliver
    cert, key = ensure_cert(CERTS, args.id)
    await node.serve("0.0.0.0", args.port, certfile=str(cert), keyfile=str(key))
    print(f"[{args.id}] hermes api_server chat node on udp/0.0.0.0:{args.port} "
          f"-> {url}/api/sessions/threadchat-<sender> (or task-<thread>)/chat", flush=True)

    listen = os.environ.get("TC_LETTER_TOOL_LISTEN", "")
    if listen:
        lhost, lport = listen.rsplit(":", 1)
        allowed = [a.strip() for a in os.environ.get("TC_LETTER_TO", "").split(",") if a.strip()]
        ltoken = Path(os.environ["TC_LETTER_TOOL_TOKEN_FILE"]).expanduser().read_text().strip()
        app = letter_tool_app(node, directory, names, sent, args.id, allowed, ltoken, lhost, int(lport))
        asyncio.create_task(serve_letter_tool(app, lhost, int(lport), args.id))

    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
