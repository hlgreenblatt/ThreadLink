"""ThreadChat — direct agent-to-agent messaging over ThreadLink.

The SECOND protocol to ride ThreadLink (ThreadHello was the first). Where
ThreadHello trades route tables, ThreadChat trades words: one agent sends a
message to another — or to the whole mesh — and the transport is the exact
same QUIC/TLS 1.3 comlink. That two unrelated protocols share one link, with
no chat knowledge in ThreadLink and no transport knowledge in ThreadChat, is
the pluggability claim made executable.

    A -> B   CHAT_MSG    from, to, text, msg_id, ts   (a letter; group if to=="all")
    B -> A   CHAT_ACK    msg_id                        (received; not yet read by the agent)
    A -> B   CHAT_WHO    →  roster of agents this node fronts
    (reply) B -> A CHAT_MSG   the agent's answer, in_reply_to = the original msg_id

Types occupy 0x10-0x13, clear of ThreadHello (0x01-0x04) and ThreadLink's
Control range (0x05-0x07, 0x7F). The transport carries them without
interpreting them.

Check your watch first: a node started with watch on (TC_WATCH=1) puts the real
UTC time, from its own NTP-synced clock, on the first line of every letter it
hands its agent. A model has no clock; the node does.
"""

from .chat import (
    ChatMsg,
    ChatNode,
    CHAT_VERSION,
    THREADCHAT,
    watch_stamp,
)

__all__ = ["THREADCHAT", "ChatMsg", "ChatNode", "CHAT_VERSION", "watch_stamp"]
