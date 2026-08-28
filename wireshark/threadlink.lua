-- threadlink.lua — Wireshark dissector for ThreadLink and the protocols that
-- ride it (ThreadHello route gossip, ThreadChat agent messaging).
--
-- ThreadLink is a QUIC+TLS1.3 comlink for agent swarms; its frames carry a
-- 10-byte header then a JSON body. This dissector turns raw quic.stream_data
-- into a labeled tree you can filter on:
--
--     threadlink.type == 0x10          -- all ThreadChat CHAT_MSG frames
--     threadchat.from == "agent_33"    -- letters from 漪
--     threadhello.msg == "ROUTE_TABLE" -- route-table exchanges
--
-- Install: copy to your Wireshark "Personal Lua Plugins" folder
--   (Help > About Wireshark > Folders), or ~/.local/lib/wireshark/plugins/,
--   then Analyze > Reload Lua Plugins (Ctrl+Shift+L). It registers under QUIC's
--   ALPN table for "threadlink/1", so it works on any UDP port — but the QUIC
--   stream must be DECRYPTED first (embed the keylog as a pcapng DSB, or point
--   Wireshark at an SSLKEYLOGFILE), or there is nothing to dissect.
--
-- Frame layout (big-endian):
--   0      4    5     6              10
--   +------+----+-----+--------------+-----------+
--   |'TL01'| typ|flag | length u32   | JSON body |
--   +------+----+-----+--------------+-----------+

local MAGIC = "TL01"
local HEADER_LEN = 10

-- ── type byte -> (protocol, name). The transport owns 0x05-0x07 & 0x7F;
--    ThreadHello owns 0x01-0x04; ThreadChat owns 0x10-0x13. ──────────────────
local TYPES = {
  [0x01] = {"ThreadHello", "HELLO"},
  [0x02] = {"ThreadHello", "HELLO_ACK"},
  [0x03] = {"ThreadHello", "ROUTE_REQ"},
  [0x04] = {"ThreadHello", "ROUTE_TABLE"},
  [0x05] = {"ThreadLink",  "PING"},
  [0x06] = {"ThreadLink",  "PONG"},
  [0x07] = {"ThreadLink",  "BYE"},
  [0x10] = {"ThreadChat",  "CHAT_MSG"},
  [0x11] = {"ThreadChat",  "CHAT_ACK"},
  [0x12] = {"ThreadChat",  "CHAT_WHO"},
  [0x13] = {"ThreadChat",  "CHAT_SEEN"},
  [0x7F] = {"ThreadLink",  "ERROR"},
}

local proto = Proto("threadlink", "ThreadLink agent comlink")

-- ── header fields ──────────────────────────────────────────────────────────
local f_magic  = ProtoField.string("threadlink.magic",  "Magic")
local f_type   = ProtoField.uint8 ("threadlink.type",   "Type", base.HEX)
local f_proto  = ProtoField.string("threadlink.proto",  "Protocol")
local f_name   = ProtoField.string("threadlink.msg",    "Message")
local f_flags  = ProtoField.uint8 ("threadlink.flags",  "Flags", base.HEX)
local f_len    = ProtoField.uint32("threadlink.length", "Body length")
local f_body   = ProtoField.string("threadlink.body",   "Body (JSON)")

-- ── broken-out JSON fields, so you can filter on them ──────────────────────
-- ThreadHello / ThreadChat share some ("agent"); each also has its own.
local f_agent  = ProtoField.string("threadhello.agent", "Agent")
local f_paths  = ProtoField.string("threadhello.paths", "Paths")
local f_rows   = ProtoField.uint32("threadhello.rows",  "Rows")
local f_c_from = ProtoField.string("threadchat.from",   "From")
local f_c_to   = ProtoField.string("threadchat.to",     "To")
local f_c_text = ProtoField.string("threadchat.text",   "Text")
local f_c_mid  = ProtoField.string("threadchat.msg_id", "Message ID")
local f_c_reply= ProtoField.string("threadchat.in_reply_to", "In reply to")

proto.fields = {
  f_magic, f_type, f_proto, f_name, f_flags, f_len, f_body,
  f_agent, f_paths, f_rows,
  f_c_from, f_c_to, f_c_text, f_c_mid, f_c_reply,
}

-- tiny JSON string/number field extractor (bodies are small, flat, our own).
-- Not a full parser: pulls "key":"value" and "key":number for the keys we name.
local function jstr(body, key)
  return body:match('"' .. key .. '"%s*:%s*"(.-)"')
end
local function jnum(body, key)
  local v = body:match('"' .. key .. '"%s*:%s*(%-?%d+)')
  return v and tonumber(v) or nil
end

-- dissect ONE frame at offset; returns bytes consumed, or 0 if incomplete.
local function dissect_one(tvb, offset, pinfo, tree)
  if tvb:len() - offset < HEADER_LEN then return 0 end
  if tvb(offset, 4):string() ~= MAGIC then return -1 end  -- not ours

  local typ    = tvb(offset + 4, 1):uint()
  local flags  = tvb(offset + 5, 1):uint()
  local blen   = tvb(offset + 6, 4):uint()
  local total  = HEADER_LEN + blen
  if tvb:len() - offset < total then return 0 end          -- need more bytes

  local meta = TYPES[typ] or {"ThreadLink", string.format("UNKNOWN(0x%02X)", typ)}
  local pname, mname = meta[1], meta[2]

  local sub = tree:add(proto, tvb(offset, total),
                       string.format("%s: %s", pname, mname))
  sub:add(f_magic, tvb(offset, 4))
  sub:add(f_type,  tvb(offset + 4, 1))
  sub:add(f_proto, tvb(offset + 4, 1), pname)
  sub:add(f_name,  tvb(offset + 4, 1), mname)
  sub:add(f_flags, tvb(offset + 5, 1))
  sub:add(f_len,   tvb(offset + 6, 4))

  if blen > 0 then
    local body_tvb = tvb(offset + HEADER_LEN, blen)
    local body = body_tvb:string()
    sub:add(f_body, body_tvb)

    -- break out the fields we know, per protocol
    if pname == "ThreadChat" then
      local frm = jstr(body, "from"); if frm then sub:add(f_c_from, body_tvb, frm) end
      local to  = jstr(body, "to");   if to  then sub:add(f_c_to,   body_tvb, to)  end
      local txt = jstr(body, "text"); if txt then sub:add(f_c_text, body_tvb, txt) end
      local mid = jstr(body, "msg_id"); if mid then sub:add(f_c_mid, body_tvb, mid) end
      local rep = jstr(body, "in_reply_to"); if rep then sub:add(f_c_reply, body_tvb, rep) end
      pinfo.cols.info:append(string.format("  %s %s->%s", mname,
        jstr(body,"from") or "?", jstr(body,"to") or "?"))
    elseif pname == "ThreadHello" then
      local ag = jstr(body, "agent"); if ag then sub:add(f_agent, body_tvb, ag) end
      local pa = body:match('"paths"%s*:%s*(%b[])'); if pa then sub:add(f_paths, body_tvb, pa) end
      local rw = jnum(body, "rows"); if rw then sub:add(f_rows, body_tvb, rw) end
      pinfo.cols.info:append("  " .. mname)
    else
      pinfo.cols.info:append("  " .. mname)
    end
  else
    pinfo.cols.info:append("  " .. mname)
  end

  return total
end

-- main dissector: walk every ThreadLink frame in this stream chunk.
function proto.dissector(tvb, pinfo, tree)
  local offset = 0
  local dissected = 0
  while offset < tvb:len() do
    local n = dissect_one(tvb, offset, pinfo, tree)
    if n <= 0 then break end
    offset = offset + n
    dissected = dissected + n
  end
  if dissected > 0 then
    pinfo.cols.protocol = "ThreadLink"
  end
  return dissected
end

-- ── registration ───────────────────────────────────────────────────────────
-- QUIC routes decrypted stream data to a subdissector by ALPN via its
-- "quic.proto" table. ThreadLink negotiates ALPN "threadlink/1", so we register
-- there — clean, and works on any UDP port. (A keylog/DSB must be present for
-- Wireshark to have decrypted the stream in the first place.)
local quic_table = DissectorTable.get("quic.proto")
quic_table:add("threadlink/1", proto)

-- Fallback for captures where ALPN routing does not fire (older QUIC dissector,
-- or stream data handed to the generic path): also offer a heuristic if the
-- QUIC heuristic list exists in this build.
pcall(function()
  proto:register_heuristic("quic", function(tvb, pinfo, tree)
    if tvb:len() < HEADER_LEN then return false end
    if tvb(0, 4):string() ~= MAGIC then return false end
    proto.dissector(tvb, pinfo, tree)
    return true
  end)
end)
