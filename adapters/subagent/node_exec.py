#!/usr/bin/env python3
"""ThreadChat node for a SUB-AGENT that has no API of its own (2026-10-18, ThreadTask).

77's companions (Hermes profiles 77s1 Sakura, 77s2 Momo) and 99's five consorts (OpenClaw agents xuetei, huitei, mofei,
jingpin, shuchangzai) live INSIDE their owner's container. Until today Sparks reached them by `docker exec` from scripts,
so they were not on the mesh at all. This node gives each one a ThreadLink address and key of its own; the last mile is
still the owner's own CLI inside the owner's container:

    hermes profile : docker exec -u 1000:1000 -e HOME=/opt/data agent-77 hermes -p 77s1 -z "<text>"   (one-shot session)
    openclaw agent : docker exec agent_99 openclaw agent --agent <id> --session-key agent:<id>:<key> --json -m "<text>"

WHO MAY WRITE: only the senders in TC_ALLOW (the task desk = agent_sparks, and the OWNER). The owner rules: consorts are
reached through 99, Sakura and Momo through 77. A letter from anyone else is dropped and logged (who + size, never words).

A letter carrying a thread (a ThreadTask) gets a conversation of its own (OpenClaw session key agent:<id>:task-<thread>);
a Hermes -z call is a fresh session every time anyway, so a follow-up must carry its own context.
"""
import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

from threadlink import ensure_cert
from threadchat import ChatNode

CERTS = _ROOT / "certs"
_BAD = re.compile(r"[^A-Za-z0-9._:-]")


def ask(kind, container, target, text, sender, thread, timeout):
    if kind == "hermes-profile":
        p = subprocess.run(["docker", "exec", "-u", "1000:1000", "-e", "HOME=/opt/data", container, "hermes", "-p", target,
                            "-z", text], capture_output=True, text=True, timeout=timeout)
        return (p.stdout.strip() or f"[hermes exit {p.returncode}: {p.stderr.strip()[-200:]}]"), ""
    if kind == "openclaw-agent":
        key = "task-" + _BAD.sub("_", thread)[:96] if thread else "threadchat-" + _BAD.sub("_", sender)[:96]
        p = subprocess.run(["docker", "exec", container, "openclaw", "agent", "--agent", target, "--session-key",
                            f"agent:{target}:{key}", "--timeout", str(int(timeout) - 30), "--json", "-m", text],
                           capture_output=True, text=True, timeout=timeout)
        raw = p.stdout + p.stderr
        try:
            r = json.loads(raw[raw.find("{"):])["result"]
            m = (r.get("meta") or {}).get("agentMeta") or {}
            text = "\n\n".join(x.get("text", "") for x in r.get("payloads", [])).strip() or "[no reply]"
            return text, f"{m.get('provider')}/{m.get('model')}"
        except Exception:
            return f"[openclaw exit {p.returncode}: {raw.strip()[-200:]}]", ""
    raise SystemExit(f"node_exec: unknown kind {kind!r}")


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True)
    ap.add_argument("--directory", required=True)
    ap.add_argument("--port", type=int, required=True)
    args = ap.parse_args()
    kind, container, target = os.environ["TC_EXEC_KIND"], os.environ["TC_EXEC_CONTAINER"], os.environ["TC_EXEC_TARGET"]
    allow = {a.strip() for a in os.environ.get("TC_ALLOW", "agent_sparks").split(",") if a.strip()}
    timeout = float(os.environ.get("TC_EXEC_TIMEOUT", "930"))
    directory = {k: tuple(v) for k, v in json.loads(Path(args.directory).read_text()).items()}
    node = ChatNode(args.id, deliver=None, directory=directory)
    busy = asyncio.Lock()      # one turn at a time per sub-agent

    async def _answer(frm, text, orig_mid, thread):
        async with busy:
            try:
                reply, engine = await asyncio.to_thread(ask, kind, container, target, text, frm, thread, timeout)
            except Exception as e:
                reply, engine = f"[adapter error: {type(e).__name__}: {e}]", ""
        h, p = directory[frm]
        try:
            await node.send_to(frm, reply or "[no reply]", msg_id=f"{args.id}-{int(time.time() * 1000)}",
                               in_reply_to=orig_mid, host=h, port=p, thread=thread or None,
                               meta={"engine": engine} if engine else None)
            print(f"[{args.id}] answered {frm}: {len(reply)} chars", flush=True)   # never the words
        except Exception as e:
            print(f"[{args.id}] reply to {frm} failed: {e}", flush=True)

    def deliver(letter):
        frm = letter["from"]
        if frm not in directory or frm not in allow:
            print(f"[{args.id}] dropped letter from {frm!r} ({len(letter.get('text') or '')} chars): not an allowed sender",
                  flush=True)
            return
        asyncio.create_task(_answer(frm, letter["text"], letter.get("msg_id"), letter.get("thread") or ""))

    node.deliver = deliver
    cert, key = ensure_cert(CERTS, args.id)
    await node.serve("0.0.0.0", args.port, certfile=str(cert), keyfile=str(key))
    print(f"[{args.id}] sub-agent node on udp/0.0.0.0:{args.port} -> {kind} {container}:{target} (allow {sorted(allow)})",
          flush=True)
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
