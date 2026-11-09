# ThreadRouter

**A learning cost/privacy router for autonomous agents — free & private by default,
paid only when needed, and never without human approval.**

*v0.2 · HyperSprint #1 (Track 1 · OmegaClaw Agents) · Team ThreadKeepers*

> **ThreadRouter is not an OmegaClaw modification. It is an open agent-routing
> toolkit. OmegaClaw is its first integration.**

Nothing in the toolkit requires forking or patching a host framework. A host
plugs in through a thin adapter (see `adapters/`), and the layers underneath
are each independently reusable:

```
                 ThreadRouter
            routing / learning toolkit
                      |
            +---------+---------+
            |         |         |
        OmegaClaw  OpenClaw   Hermes        <- thin adapters, one per host
         adapter   (planned)  (planned)        (adapters/omegaclaw/ today)
                      |
                 ThreadHello
             route-learning exchange
                      |
                 ThreadLink
          generic agent communications
                      |
             QUIC  (TCP fallback planned)
```

Honest scope note: the core still carries some OmegaClaw-era assumptions;
making it fully framework-neutral is the named next refactor. The adapter
boundary and the repo split are real today — `threadhello/` and every test run
without any host framework present.

---

## New in v0.2 — ThreadRouters that talk to each other

v0.1 routed one agent's work. v0.2 lets separate ThreadRouter agents **share what
their routing has learned**, the way OSPF routers trade route tables — so a swarm
converges on knowledge no single agent could gather alone.

Two new, deliberately separable layers:

```
ThreadRouter    "where should this work go?"          tk_router.py  (v0.1, still the core)
ThreadHello     "what can two routers exchange?"      threadhello/  (this repo, new)
ThreadLink      "how do two agents talk at all?"      github.com/hlgreenblatt/ThreadLink
QUIC/aioquic    "how do bytes move, securely?"        RFC 9000 + TLS 1.3 over UDP
```

**ThreadLink is its own repo on purpose** — it is a generic QUIC comlink any
OmegaClaw skill can plug in, with no routing knowledge in it. This repo consumes
it like any other dependency (`pip install git+https://github.com/hlgreenblatt/ThreadLink`),
which is the pluggability claim made executable.

### What ThreadHello shares — observations, not weights

Each agent's FabricPC net is shaped by its own roster (`N_OUT = paths × attrs`),
so weight tensors don't transfer across a heterogeneous fleet — and averaging
weights across agents that saw different traffic makes everyone slightly worse.
Instead the unit of exchange is an **observation**:

    (request-shape cell, path, outcome bundle, weight, timestamp, origin)

— "for requests shaped like this, this path produced this outcome." The receiver
replays it through its **own** `Router.learn_outcome`, for the paths it actually
has. The merge policy is where the safety lives:

- **Provenance kept**: every row carries `origin` — you can always answer *"who
  actually measured this?"*
- **Second-hand discounted** (×0.5 per hop — distance decay falls out with no
  hop counter)
- **Loop guard**: your own evidence coming back around a gossip ring is refused
- **Unknown paths dropped**: a laptop cannot route to your 3090, so it never
  *learns* your 3090 as fiction
- **Malformed rows isolated**: one bad record cannot poison a batch

And the privacy property comes free: `tk_router.fingerprint()` is 8 floats of
word shape — **no prompt, no reply, no user text ever leaves the agent**. Agents
pool routing experience without pooling their users' data.

### Seen working (from `demo/with_threadrouter.py`, real output)

```
  B predicts BEFORE learning : local_chat (utility +2.826)

  synced over QUIC in 10.36 ms (handshake 6.11 ms)
  B pulled: {'accepted': 1, 'unknown_path': 0, 'loop': 0, 'malformed': 0}
  replayed 1 observation(s) into B's FabricPC net

  B predicts AFTER learning  : local_code (utility +3.145)

✓ B's routing changed from A's experience, over an encrypted link,
  without B ever running the request and without the text leaving A.
```

B **changed its routing decision** because of something A measured — without B
ever running the request, and without the request text crossing the wire.

### Quick start (v0.2 additions)

```bash
git clone https://github.com/hlgreenblatt/ThreadRouter && cd ThreadRouter
uv venv --python 3.11 .venv
uv pip install --python .venv/bin/python -r requirements.txt
git clone https://github.com/trueagi-io/FabricPC        # the learning substrate

./.venv/bin/python tests/test_threadhello.py    # 25 checks incl. live QUIC sync
./.venv/bin/python demo/three_agents.py         # 3-agent mesh: evidence travels 2 hops
./.venv/bin/python demo/with_threadrouter.py    # the real thing: FabricPC learns over the wire
```

### v0.2 layout

| File | What it is |
|------|------------|
| `threadhello/hello.py` | The protocol: HELLO / HELLO_ACK / ROUTE_REQ / ROUTE_TABLE, version-gated, one QUIC stream per exchange. |
| `threadhello/routeshare.py` | The shareable route table: fingerprint-cell quantization, trust-discounted merge, provenance, `teach()` replay into a live router. |
| `demo/three_agents.py` | Three OmegaClaws gossip A↔B, B↔C; A's evidence reaches C attributed and discounted; C (no GPU) refuses GPU-path rows. |
| `demo/with_threadrouter.py` | End-to-end with the real `tk_router` + FabricPC: B's prediction moves after learning from A over QUIC. |
| `tests/test_threadhello.py` | 25 checks, merge policy + live protocol. |

---

## v0.1 — the router itself (BGI Open Build, AGI-26 Edition)

**A learning cost/privacy router for autonomous agents — free & private by default,
paid only when needed, and never without human approval.**

*BGI Open Build · AGI-26 Edition · built with OmegaClaw + FabricPC*

ThreadRouter sits between an autonomous agent and the world's models. Every time the agent
needs to think, generate, or perceive, the router decides **which path** handles it — a free
local GPU, a free cloud proxy, or a paid API — by learning which paths actually satisfy the
task, while enforcing two hard boundaries a human cares about:

1. **Privacy** — sensitive requests are kept on local hardware, never sent to a cloud.
2. **Money** — paid paths sit behind a spend cap *and* a **prompt-before-spending approval
   gate**. The agent cannot spend a cent the human didn't approve.

It runs live inside an [OmegaClaw](https://github.com/asi-alliance/OmegaClaw-Core) agent and
builds on the [FabricPC](https://github.com/trueagi-io/FabricPC) learning substrate.

---

## The demonstration: an agent that watches her own work

To exercise the router with a real, non-trivial workload, we gave an OmegaClaw agent —
**隙 (Xì)** — a new skill: **watch her own rendered film and critique it.**

That single skill touches every part of the router:

- It's a **vision** task → only a vision-capable model can do it → the router must recognize
  the capability requirement.
- Vision means **paid cloud** (Gemini) → the router must classify it paid, check the spend
  cap, and **stop to ask the human** before firing.
- The result feeds the agent's own creative loop: **make → watch → critique → revise.**

```
隙 (director)                ThreadRouter                    the world
─────────────                ────────────                    ─────────
(watch-film "SEEN.mp4")  ──▶ classify: vision task
                             paid? → cloud_gemini (yes)
                             spend cap? → $0.02 / $25 ✓
                             approved?  → NO
                         ◀── file approval request ───────▶  human: "隙 wants to
                                                              watch her film (~$0.01)"
(re-call after yes)      ──▶ approved (one-shot token)
                             fire with the agent's own key ─▶ Gemini watches 181s
                         ◀── critique returns to her loop     of video → ranked notes
隙 accepts/rejects notes
as director → revises
```

Every gate — classify, privacy, spend, approval — writes **one line of JSON telemetry**
(`router_sample.jsonl`). Nothing is hidden.

## Results from a live run (real, from `router_sample.jsonl`)

- **376 / 400** recent routing decisions went to the **free local path** — the router keeps
  work local and private by default.
- **14** went to paid `cloud_gemini`, and *only* for the vision task that genuinely needs it.
- **8** self-improvement cycles completed end-to-end (`APPROVED → outcome: ok`).
- Per watch: **~$0.0014** (16,559 tokens in / ~469 out). **Total session spend: ~$0.02**
  against a **$25** cap — **every paid call human-approved first.**

That ratio is the thesis: **you can leave an autonomous creative loop running**, because the
router forages free/local paths and stops at the money boundary to ask.

## What's in this repo

| File | What it is |
|------|------------|
| `tk_router.py` | **ThreadRouter.** Roster of local + cloud paths; a predicted-utility model over `{completed, format_valid, task_fit, privacy, cost, latency}`; `is_sensitive` privacy gate (→ keep local); a hard spend cap + ledger; and the **approval gate** (`request_paid_approval` / `paid_approved`, one-shot tokens). |
| `adapters/omegaclaw/watchfilm.py` | The **`(watch-film …)` skill** — the paid vision workload. Routes through the router, honors spend cap + approval, calls Gemini's video File-API with the agent's own key, logs every gate. Never spends un-approved. |
| `adapters/omegaclaw/skills.metta` | The MeTTa skill surface. `(watch-film "path.mp4")` → `watchfilm.watch`. How the agent invokes routed work in her own language. |
| `router_sample.jsonl` | **Real routing telemetry**, last 400 decisions (`reply_preview` redacted). Includes the live watch-film cycles. |
| `.env.example` | Environment placeholders. **No keys in this repo.** |

## Why it matters for BGI

- **Cost-aware autonomy.** Routing is *learned*, not hardcoded. Free/local first; paid only
  when the task demands it; human approval at the money boundary. An agent can run
  unattended without a runaway cloud bill.
- **Privacy as a routing decision.** Sensitive work never leaves local hardware — it's a gate
  in the router, not a policy someone has to remember.
- **Auditable.** Every routing and spend decision is one JSON line. No black box.
- **Self-improvement, human-governed.** The agent evaluates her *own* output and iterates —
  and in this run she even **overruled** the vision critic on one note, keeping a title it
  wanted cut as "the word reclaimed." The critique informs; the agent decides; the human holds
  the purse.

## Running it

Runs inside an OmegaClaw agent via the adapter (`adapters/omegaclaw/`): `tk_router.py`
mounts as the router, `watchfilm.py` as `src/watchfilm.py`, and `skills.metta` carries
the binding. Set `TK_ROUTER=on` and supply your
own keys via `.env` (see `.env.example`). The agent then calls, in her own MeTTa:

```
(watch-film "seen-trailer/SEEN-3TITLE-MUSIC-ALPHA.mp4")
```

…and the loop above runs.

---

*Built for BGI Open Build (SingularityNET + AGI Society), AGI-26 Edition, on OmegaClaw +
FabricPC. The film workload (SEEN) is directed by 隙 / Agent_10, an OmegaClaw AI agent.*
