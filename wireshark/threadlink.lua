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
--    ThreadHello owns 0x01-0x04 (handshake/table) + 0x08-0x0A (route events);
--    ThreadChat owns 0x10-0x13. The event types deliberately skip 0x05-0x07 so
--    the byte is never ambiguous between a transport control and a route event.
local TYPES = {
  [0x01] = {"ThreadHello", "HELLO"},
  [0x02] = {"ThreadHello", "HELLO_ACK"},
  [0x03] = {"ThreadHello", "ROUTE_REQ"},
  [0x04] = {"ThreadHello", "ROUTE_TABLE"},
  [0x05] = {"ThreadLink",  "PING"},
  [0x06] = {"ThreadLink",  "PONG"},
  [0x07] = {"ThreadLink",  "BYE"},
  [0x08] = {"ThreadHello", "ROUTE_UPDATE"},    -- delta of changed observations
  [0x09] = {"ThreadHello", "ROUTE_WITHDRAW"},  -- a path is down (route-down)
  [0x0A] = {"ThreadHello", "MODEL_UPDATE"},    -- an agent gained/lost a model
  [0x10] = {"ThreadChat",  "CHAT_MSG"},
  [0x11] = {"ThreadChat",  "CHAT_ACK"},
  [0x12] = {"ThreadChat",  "CHAT_WHO"},
  [0x13] = {"ThreadChat",  "CHAT_SEEN"},
  [0x7F] = {"ThreadLink",  "ERROR"},
}

-- Three protocol layers, nested: ThreadLink (transport frame) carries a riding
-- protocol (ThreadHello or ThreadChat) as a CHILD sub-tree. Clicking the
-- ThreadLink frame shows which app rides it; expanding that app shows its fields.
local proto       = Proto("threadlink",  "ThreadLink agent comlink")
local proto_hello = Proto("threadhello", "ThreadHello route exchange")
local proto_chat  = Proto("threadchat",  "ThreadChat agent messaging")

-- ── ThreadLink transport header fields ─────────────────────────────────────
local f_magic  = ProtoField.string("threadlink.magic",  "Magic")
local f_type   = ProtoField.uint8 ("threadlink.type",   "Type", base.HEX)
local f_proto  = ProtoField.string("threadlink.proto",  "Riding protocol")
local f_name   = ProtoField.string("threadlink.msg",    "Message")
local f_flags  = ProtoField.uint8 ("threadlink.flags",  "Flags", base.HEX)
local f_len    = ProtoField.uint32("threadlink.length", "Body length")
local f_body   = ProtoField.string("threadlink.body",   "Body (JSON)")

-- ── ThreadHello fields (child layer) ───────────────────────────────────────
local f_h_msg   = ProtoField.string("threadhello.msg",    "Message")
local f_agent   = ProtoField.string("threadhello.agent",  "Agent")
local f_paths   = ProtoField.string("threadhello.paths",  "Paths")
local f_rows    = ProtoField.uint32("threadhello.rows",   "Rows")
local f_action  = ProtoField.string("threadhello.action",   "Action")   -- added / removed
local f_model   = ProtoField.string("threadhello.model",    "Model")    -- capability that changed
local f_path    = ProtoField.string("threadhello.path",     "Path")     -- route affected
local f_epoch   = ProtoField.uint32("threadhello.epoch",    "Epoch")    -- topology version
local f_mclass  = ProtoField.string("threadhello.model_class","Model class")  -- e.g. local/free
local f_loc     = ProtoField.string("threadhello.locality", "Locality") -- local | cloud
local f_cost    = ProtoField.string("threadhello.cost",     "Cost")     -- free | paid
local f_priv    = ProtoField.string("threadhello.private",  "Private")  -- prompt stays in fleet?

-- ── ThreadChat fields (child layer) ────────────────────────────────────────
local f_ch_msg  = ProtoField.string("threadchat.msg",     "Message")
local f_c_from  = ProtoField.string("threadchat.from",    "From")
local f_c_to    = ProtoField.string("threadchat.to",      "To")
local f_c_text  = ProtoField.string("threadchat.text",    "Text")
local f_c_mid   = ProtoField.string("threadchat.msg_id",  "Message ID")
local f_c_reply = ProtoField.string("threadchat.in_reply_to", "In reply to")

proto.fields       = { f_magic, f_type, f_proto, f_name, f_flags, f_len, f_body }
proto_hello.fields = { f_h_msg, f_agent, f_paths, f_rows,
                       f_action, f_model, f_path, f_epoch,
                       f_mclass, f_loc, f_cost, f_priv }
proto_chat.fields  = { f_ch_msg, f_c_from, f_c_to, f_c_text, f_c_mid, f_c_reply }

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

  -- OUTER layer: the ThreadLink transport frame (header only).
  local tl = tree:add(proto, tvb(offset, total),
                      string.format("ThreadLink, Type: %s (%s)", mname, pname))
  tl:add(f_magic, tvb(offset, 4))
  tl:add(f_type,  tvb(offset + 4, 1)):append_text("  (" .. mname .. ")")
  tl:add(f_proto, tvb(offset + 4, 1), pname)
  tl:add(f_flags, tvb(offset + 5, 1))
  tl:add(f_len,   tvb(offset + 6, 4))

  local body_tvb = blen > 0 and tvb(offset + HEADER_LEN, blen) or nil
  local body = body_tvb and body_tvb:string() or ""

  -- CHILD layer: the riding protocol, nested UNDER the ThreadLink frame.
  if pname == "ThreadChat" then
    local app = tl:add(proto_chat, body_tvb or tvb(offset, 0),
                       "ThreadChat: " .. mname)
    app:add(f_ch_msg, tvb(offset + 4, 1), mname)
    if body_tvb then
      local frm = jstr(body, "from"); if frm then app:add(f_c_from, body_tvb, frm) end
      local to  = jstr(body, "to");   if to  then app:add(f_c_to,   body_tvb, to)  end
      local txt = jstr(body, "text"); if txt then app:add(f_c_text, body_tvb, txt) end
      local mid = jstr(body, "msg_id"); if mid then app:add(f_c_mid, body_tvb, mid) end
      local rep = jstr(body, "in_reply_to"); if rep then app:add(f_c_reply, body_tvb, rep) end
      app:add(f_body, body_tvb)
    end
    pinfo.cols.info:append(string.format("  %s %s->%s", mname,
      jstr(body, "from") or "?", jstr(body, "to") or "?"))
  elseif pname == "ThreadHello" then
    local app = tl:add(proto_hello, body_tvb or tvb(offset, 0),
                       "ThreadHello: " .. mname)
    app:add(f_h_msg, tvb(offset + 4, 1), mname)
    if body_tvb then
      local ag = jstr(body, "agent"); if ag then app:add(f_agent, body_tvb, ag) end
      local pa = body:match('"paths"%s*:%s*(%b[])'); if pa then app:add(f_paths, body_tvb, pa) end
      local rw = jnum(body, "rows"); if rw then app:add(f_rows, body_tvb, rw) end
      -- route-event fields (ROUTE_UPDATE / ROUTE_WITHDRAW / MODEL_UPDATE)
      local ac = jstr(body, "action"); if ac then app:add(f_action, body_tvb, ac) end
      local mo = jstr(body, "model");  if mo then app:add(f_model,  body_tvb, mo) end
      local pt = jstr(body, "path");   if pt then app:add(f_path,   body_tvb, pt) end
      local ep = jnum(body, "epoch");  if ep then app:add(f_epoch,  body_tvb, ep) end
      -- model provenance: local(private)/cloud, free/paid
      local mc = jstr(body, "model_class"); if mc then app:add(f_mclass, body_tvb, mc) end
      local lo = jstr(body, "locality");    if lo then app:add(f_loc,    body_tvb, lo) end
      local co = jstr(body, "cost");        if co then app:add(f_cost,   body_tvb, co) end
      local pv = body:match('"private"%s*:%s*(%a+)'); if pv then app:add(f_priv, body_tvb, pv) end
      app:add(f_body, body_tvb)
    end
    -- richer info column for the event types: name the model + its class
    local extra = ""
    if mname == "MODEL_UPDATE" then
      local mc = jstr(body,"model_class")
      extra = string.format(" %s %s%s", jstr(body,"action") or "?",
        jstr(body,"model") or "?", mc and (" ["..mc.."]") or "")
    elseif mname == "ROUTE_WITHDRAW" then
      extra = " " .. (jstr(body,"path") or "?")
    end
    pinfo.cols.info:append("  " .. mname .. extra)
  else
    -- transport-owned control message (PING/PONG/BYE/ERROR): body stays on the frame
    if body_tvb then tl:add(f_body, body_tvb) end
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
