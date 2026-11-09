"""watchfilm.py — 隙 watches her OWN film and gets a critique, through her router.

MeTTa surface:  (watch-film "path/to/film.mp4")

This is the seam that lets 隙 SEE her own work. It is a *vision* task — it must
go to a vision-capable model (Gemini). Gemini is a PAID path, so this module
does NOT quietly spend money. It runs the request through 隙's own ThreadRouter:

  1. classify: this is a paid vision path (cloud_gemini)
  2. spend-cap check  (tk_router.paid_allowed)
  3. approval gate    (tk_router.paid_approved) — one-shot token Larry grants
       * if NOT yet approved: write a pending request (tk_router.request_paid_approval),
         log a router-decision row, and RETURN an "awaiting approval" status.
         隙 sees that, waits, and re-calls (watch-film ...) after Larry says yes.
         NO network call, NO money spent on this tick.
       * if approved: fire the real Gemini call with 隙's OWN key, record the
         real cost to the spend ledger, log the decision row, return the critique.

Every path logs one line to memory/router.jsonl so the hackathon demo has real
routing telemetry: what 隙 asked, which path the router picked, the privacy
gate, the spend gate, the approval gate, and the measured cost.

Env (all already in agent_10.env):
  GEMINI_API_KEY, GEMINI_BASE_URL (…/v1beta), GEMINI_MODEL (gemini-flash-latest)
  MEMORY_DIR (default /PeTTa/repos/OmegaClaw-Core/memory)

Returns a single string (critique, status, or error). Never raises.
Patterned on hailuo.py (submit->poll->return) — self-contained, stdlib + requests.
"""

import json
import os
import sys
import time

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

# Deployed, this file sits next to tk_router.py inside the agent (src/).
# In the repo it lives in adapters/omegaclaw/, so put the repo root (where
# tk_router.py lives) on the path too.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    import tk_router as _tk
except Exception:  # pragma: no cover — router is the whole point; degrade loudly
    _tk = None

_PATH_ID = "cloud_gemini"          # the vision path this skill routes to
_EST_COST = 0.01                   # pre-fire estimate (real ~$0.006 for 3 min)
_MEMDIR = os.environ.get("MEMORY_DIR", "/PeTTa/repos/OmegaClaw-Core/memory")
_ROUTER_LOG = os.path.join(_MEMDIR, "router.jsonl")

_BASE = os.environ.get("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta")
_MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-latest")

# Media roots 隙 can name a film relative to (same convenience filmcraft gives).
_MEDIA_ROOTS = [
    "/run/media/maxquasar/arc-261/agents-media/agent_10",
    "/run/media/maxquasar/arc-261/agents-media/agent_10/seen-trailer",
    "/run/media/maxquasar/arc-261/agents-media/agent_10/hailuo-videos",
    "/run/media/maxquasar/arc-261/agents-media/agent_10/hailuo-videos/pitch",
    os.getcwd(),
]

_CRITIQUE_PROMPT = (
    "You are a film-trailer editor reviewing a short sci-fi trailer called SEEN, "
    "directed by an AI filmmaker. Watch the whole thing. Give the director 1 to 5 "
    "SPECIFIC, actionable improvements, ranked most-important first. Focus on: "
    "pacing, motion (many shots may be too static), title timing/readability, "
    "music-to-visual sync, and emotional arc. Be concrete and cite timestamps. "
    "Return ONLY JSON: "
    '{"critiques":[{"rank":1,"issue":"...","fix":"...","timestamp":"m:ss"}]}'
)


def _key():
    return (os.environ.get("GEMINI_API_KEY") or "").strip()


def _resolve(path):
    """Let 隙 name a film naturally (bare filename or relative). Return abs path or None."""
    path = (path or "").strip().strip('"').strip("'")
    if not path:
        return None
    if os.path.isabs(path) and os.path.exists(path):
        return path
    for root in _MEDIA_ROOTS:
        cand = os.path.join(root, path)
        if os.path.exists(cand):
            return cand
    return path if os.path.exists(path) else None


def _log(row):
    row.setdefault("skill", "watch-film")
    row.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%S"))
    if _tk is not None:
        try:
            _tk.log_row(_ROUTER_LOG, row)
            return
        except Exception:
            pass
    try:
        with open(_ROUTER_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Gemini File API: resumable upload -> wait ACTIVE -> generateContent
# ---------------------------------------------------------------------------
def _upload(film, key):
    size = os.path.getsize(film)
    mime = "video/mp4"
    # Resumable upload lives on the /upload/ endpoint, NOT /v1beta/files.
    # (…/v1beta -> …/upload/v1beta/files). This is what returns X-Goog-Upload-URL.
    upload_base = _BASE.replace("/v1beta", "") + "/upload/v1beta"
    start = requests.post(
        f"{upload_base}/files",
        headers={
            "x-goog-api-key": key,
            "X-Goog-Upload-Protocol": "resumable",
            "X-Goog-Upload-Command": "start",
            "X-Goog-Upload-Header-Content-Length": str(size),
            "X-Goog-Upload-Header-Content-Type": mime,
            "Content-Type": "application/json",
        },
        data=json.dumps({"file": {"display_name": os.path.basename(film)}}),
        timeout=60,
    )
    if start.status_code != 200:
        return None, "upload-start %s: %s" % (start.status_code, start.text[:200])
    up_url = start.headers.get("X-Goog-Upload-URL")
    if not up_url:
        return None, "no upload URL in start response"
    with open(film, "rb") as fh:
        blob = fh.read()
    fin = requests.post(
        up_url,
        headers={
            "x-goog-api-key": key,
            "Content-Length": str(size),
            "X-Goog-Upload-Offset": "0",
            "X-Goog-Upload-Command": "upload, finalize",
        },
        data=blob,
        timeout=600,
    )
    if fin.status_code != 200:
        return None, "upload-finalize %s: %s" % (fin.status_code, fin.text[:200])
    info = fin.json().get("file", {})
    name = info.get("name")
    if not name:
        return None, "no file name after finalize"
    # poll until ACTIVE (video files process before they're usable)
    for _ in range(60):
        g = requests.get(f"{_BASE}/{name}", headers={"x-goog-api-key": key}, timeout=30)
        st = g.json().get("state") if g.status_code == 200 else None
        if st == "ACTIVE":
            # ACTIVE can precede full indexing; generating too soon yields a
            # near-empty answer (out~35 tokens). Small settle delay fixes it
            # (the working external call sleeps 4s here).
            time.sleep(5)
            return g.json(), None
        if st == "FAILED":
            return None, "file processing FAILED"
        time.sleep(3)
    return None, "file never became ACTIVE (timeout)"


def _extract_text(cand):
    """Join ALL visible text parts, skipping thought parts.

    gemini-flash-latest is a THINKING model: a response can carry a 'thought'
    part plus the answer part. Grabbing parts[0] alone sometimes yields the
    (near-empty) thought and misses the answer — the out=35-token stall. Join
    every non-thought text part instead.
    """
    parts = (cand.get("content") or {}).get("parts") or []
    chunks = []
    for p in parts:
        if p.get("thought"):
            continue
        t = p.get("text")
        if t:
            chunks.append(t)
    return "".join(chunks)


def _generate(file_obj, key):
    uri = file_obj.get("uri")
    mime = file_obj.get("mimeType", "video/mp4")
    # VIDEO first, prompt AFTER. Give the answer real headroom so the model's
    # internal thinking tokens don't starve the visible reply. gemini-flash is
    # occasionally flaky on this video (returns a near-empty answer), so we
    # RETRY when the visible text comes back thin.
    body = {
        "contents": [{
            "parts": [
                {"file_data": {"mime_type": mime, "file_uri": uri}},
                {"text": _CRITIQUE_PROMPT},
            ]
        }],
        "generationConfig": {"temperature": 0.5, "maxOutputTokens": 4096},
    }
    last_err = None
    for attempt in range(3):
        try:
            r = requests.post(
                f"{_BASE}/models/{_MODEL}:generateContent",
                headers={"x-goog-api-key": key, "Content-Type": "application/json"},
                data=json.dumps(body),
                timeout=180,
            )
        except Exception as e:
            last_err = "request error: %s" % str(e)[:150]
            time.sleep(3)
            continue
        if r.status_code != 200:
            last_err = "generateContent %s: %s" % (r.status_code, r.text[:250])
            time.sleep(3)
            continue
        j = r.json()
        cand = (j.get("candidates") or [{}])[0]
        text = _extract_text(cand)
        usage = j.get("usageMetadata", {})
        tin = usage.get("promptTokenCount", 0)
        tout = usage.get("candidatesTokenCount", 0)
        cost = (tin / 1_000_000) * 0.075 + (tout / 1_000_000) * 0.30
        # thin answer => the flaky near-empty roll; retry.
        if len(text.strip()) < 200 and attempt < 2:
            last_err = "thin answer (%d chars, finish=%s) — retrying" % (
                len(text.strip()), cand.get("finishReason"))
            continue
        if not text.strip():
            return None, None, "empty answer after retries: %s" % json.dumps(j)[:250]
        return text, {"in": tin, "out": tout, "cost": round(cost, 6)}, None
    return None, None, (last_err or "generate failed after retries")


# ---------------------------------------------------------------------------
# public skill entry — (watch-film "film.mp4")
# ---------------------------------------------------------------------------
def watch(path):
    if requests is None:
        return "watch-film: requests unavailable in container."
    film = _resolve(path)
    if not film:
        return ("watch-film: can't find '%s'. Give a path under agent_10/ "
                "or an absolute path." % path)
    if _tk is None:
        return "watch-film: ThreadRouter unavailable — refusing to spend un-routed."

    # ---- route the PAID vision decision through 隙's own router ----
    if not _tk.is_paid_path(_PATH_ID):
        # (shouldn't happen — Gemini is paid — but stay honest if roster changes)
        pass

    ss = _tk.spend_status()
    if not _tk.paid_allowed():
        _log({"request": "watch own film", "film": os.path.basename(film),
              "path": _PATH_ID, "gate": "spend-cap", "decision": "REFUSED",
              "spend": ss})
        return ("watch-film: paid spend cap reached ($%.2f/$%.2f). Ask the Captain "
                "to raise TK_SPEND_CAP_USD, then re-call (watch-film ...)."
                % (ss["spent"], ss["cap"]))

    # approval gate — one-shot token Larry grants out of band
    if not _tk.paid_approved(_PATH_ID):
        _tk.request_paid_approval(_PATH_ID, _EST_COST,
                                  reason="watch own film: %s" % os.path.basename(film))
        _log({"request": "watch own film", "film": os.path.basename(film),
              "path": _PATH_ID, "gate": "approval", "decision": "AWAIT_APPROVAL",
              "est_cost_usd": _EST_COST, "spend": ss})
        return ("watch-film: this needs the paid vision path (%s, ~$%.3f). "
                "I've filed an approval request with the Captain. Once he approves, "
                "re-call (watch-film \"%s\") and I'll watch it."
                % (_PATH_ID, _EST_COST, os.path.basename(film)))

    # ---- APPROVED: fire the real call with 隙's own key ----
    key = _key()
    if not key:
        return "watch-film: GEMINI_API_KEY not set in the container."

    t0 = time.time()
    file_obj, err = _upload(film, key)
    if err:
        _log({"request": "watch own film", "film": os.path.basename(film),
              "path": _PATH_ID, "gate": "approval", "decision": "APPROVED",
              "outcome": "upload-error", "error": err})
        return "watch-film: upload failed — %s" % err

    text, meta, err = _generate(file_obj, key)
    latency_ms = int((time.time() - t0) * 1000)
    if err:
        _log({"request": "watch own film", "film": os.path.basename(film),
              "path": _PATH_ID, "decision": "APPROVED", "outcome": "gen-error",
              "error": err, "latency_ms": latency_ms})
        return "watch-film: analysis failed — %s" % err

    cost = meta["cost"]
    new_total = _tk.record_paid_spend(cost)
    _log({"request": "watch own film", "film": os.path.basename(film),
          "path": _PATH_ID, "gate": "approval", "decision": "APPROVED",
          "outcome": "ok", "cost_usd": cost, "tokens": {"in": meta["in"], "out": meta["out"]},
          "latency_ms": latency_ms, "spend_total_usd": round(new_total, 4)})

    # pretty-format the critique for 隙's reasoning stream
    header = ("I watched %s via %s (cost $%.4f, %dms). Critique:\n"
              % (os.path.basename(film), _PATH_ID, cost, latency_ms))
    try:
        # unwrap ```json fences if present
        raw = text.strip()
        if raw.startswith("```"):
            raw = raw.split("```", 2)[1]
            if raw.startswith("json"):
                raw = raw[4:]
        cj = json.loads(raw)
        lines = []
        for c in cj.get("critiques", []):
            lines.append("  #%s [%s] %s" % (c.get("rank"), c.get("timestamp", ""), c.get("issue", "")))
            lines.append("     FIX: %s" % c.get("fix", ""))
        return header + "\n".join(lines) if lines else header + text
    except Exception:
        return header + text
