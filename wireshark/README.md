# Wireshark dissector for ThreadLink / ThreadHello / ThreadChat

`threadlink.lua` teaches Wireshark to read ThreadLink's wire format natively, so
decrypted QUIC stream data shows up as a labeled protocol tree instead of raw
`quic.stream_data` — and you can **filter on the fields**:

```
threadlink.msg == "CHAT_MSG"          all ThreadChat messages
threadchat.from == "agent_33"         letters from one agent
threadchat.in_reply_to                answers (frames that reply to something)
threadhello.msg == "ROUTE_TABLE"      route-table exchanges
threadlink.type == 0x07               BYEs
```

## Install

1. Find your plugin folder: Wireshark ▸ Help ▸ About Wireshark ▸ Folders ▸
   *Personal Lua Plugins* (typically `~/.local/lib/wireshark/plugins/`).
2. Copy `threadlink.lua` there.
3. Analyze ▸ Reload Lua Plugins (Ctrl+Shift+L), or restart Wireshark.

## Use

The stream must be **decrypted** first (ThreadLink runs over TLS 1.3), so either:
- open a pcapng with the keys embedded as a Decryption Secrets Block, or
- point Wireshark at an `SSLKEYLOGFILE` (Preferences ▸ Protocols ▸ TLS).

Then open the capture and filter `threadlink`. The dissector registers under
QUIC's ALPN table for `threadlink/1`, so it fires on any UDP port (no port
config), and a guarded heuristic fallback covers builds without ALPN routing.

## What it parses

The 10-byte ThreadLink header (`TL01` magic · type · flags · uint32 length) plus
the JSON body, breaking out the fields each protocol carries:

| Type | Protocol | Message | Fields surfaced |
|------|----------|---------|-----------------|
| 0x01-0x04 | ThreadHello | HELLO / HELLO_ACK / ROUTE_REQ / ROUTE_TABLE | agent, paths, rows |
| 0x05-0x07, 0x7F | ThreadLink | PING / PONG / BYE / ERROR | — |
| 0x10-0x13 | ThreadChat | CHAT_MSG / CHAT_ACK / CHAT_WHO / CHAT_SEEN | from, to, text, msg_id, in_reply_to |

The Info column summarizes each frame (e.g. `CHAT_MSG agent_33->agent_griff`).

Pure Lua, no build step; works with the Lua that ships in Wireshark 4.x.
