"""ThreadWatch — check your watch first.

A model has no clock. It guesses the time from whatever text it was given, and
it guesses wrong more often than anyone would like. A node's host does have a
clock, kept honest by NTP, so the node is the one that tells the time.

ThreadWatch is that one line: the real time now, in UTC and in Unix seconds,
and, when a message carries its sender's clock, when it was sent and how long
ago. Every tool in the ThreadLink toolkit can use it: ThreadChat puts it on
each letter it hands an agent (TC_WATCH=1), and `threadwatch` prints it at a
shell prompt.

UTC, because that is how people who read packet captures work: one shared
map of change, the same for every node, wherever it sits.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Optional

# A sender clock further than this from ours is not trusted for "sent N s ago".
SANE_SKEW_S = 7 * 86400


def utc_iso(ts: float) -> str:
    """Unix seconds -> ISO-8601 UTC with a Z, to the second."""
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def watch_stamp(sent_ts: Any = None, now: Optional[float] = None) -> str:
    """One line: the real time now (UTC + unix) and when the message was sent."""
    now = time.time() if now is None else float(now)
    line = f"⌚ {utc_iso(now)} · unix {int(now)}"
    try:
        sent = float(sent_ts)
    except (TypeError, ValueError):
        sent = None
    if sent is not None and abs(now - sent) < SANE_SKEW_S:      # a sane sender clock only
        age = now - sent
        line += f" · sent {utc_iso(sent)}" + (f", {age:.0f} s ago" if age >= 2 else "")
    return line + " · real time, UTC, from the node's NTP clock"


def clock_synced() -> Optional[bool]:
    """Is this host's clock NTP-synchronized? None when the OS will not say."""
    if not shutil.which("timedatectl"):
        return None
    try:
        out = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                             capture_output=True, text=True, timeout=3).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return {"yes": True, "no": False}.get(out)


def main(argv: Optional[list[str]] = None) -> int:
    """`threadwatch [SENT_UNIX_SECONDS]` — print the stamp and say whether the clock is synced."""
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in ("-h", "--help"):
        print("usage: threadwatch [SENT_UNIX_SECONDS]\n"
              "Prints the real time in UTC + Unix seconds; with a send time, how long ago it was.")
        return 0
    print(watch_stamp(argv[0] if argv else None))
    synced = clock_synced()
    print("clock: NTP synchronized" if synced else
          "clock: NOT NTP synchronized, do not trust this stamp" if synced is False else
          "clock: sync state unknown on this OS")
    return 0 if synced is not False else 1


if __name__ == "__main__":
    raise SystemExit(main())
