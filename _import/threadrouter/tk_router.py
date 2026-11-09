"""
tk_router — ThreadKeeper v2 learning router (production module, outcome-bundle design).

Imported by lib_llm_ext.routeAndChat() inside Agent_10. Pure-CPU FabricPC.

ARCHITECTURE (Captain's choice, 2026-07-14): the PC-net predicts, per path, a
BUNDLE of expected outcome attributes — not one opaque score. A thin, transparent
chooser then picks the path whose predicted bundle is best. Weights over the bundle
are learned from experience (a cold-start safety prior it can override), and every
raw attribute is logged, so "why did it route there?" is always answerable from the
predicted bundle + the JSONL history, never from hidden human weights.

  request -> fingerprint (word-shape, no LLM)
          -> PC-net -> per-path predicted bundle [completed, format, fit, cost, latency]
          -> transparent chooser -> chosen path
  (after execution) measure the REAL bundle -> teach the net for (fingerprint, path).

Degrades safely: if FabricPC is unavailable, predict() returns (None, ...) and the
caller stays on its normal provider. The router can never break the loop.
"""

import os
import re
import json
import time
import math

# ---------------------------------------------------------------------------
# ─────────────────────────────────────────────────────────────────────────
# ROSTER — the SINGLE SOURCE OF TRUTH for what models exist (Captain's design,
# 2026-07-14). The router routes over this; the dashboard reads this. Add an
# entry here → it becomes a routable path AND a dashboard tile automatically.
# Remove one → it vanishes from both. No hand-maintained list drifts out of sync
# (that drift caused the $12.34 phantom + stale-MiniMax bugs).
#
# Each entry: id, label, family, tier(local|cloud), hardware/provider, the
# env var holding its model name + url + key. Cloud paths without a key present
# are simply skipped at route time (never crash for a missing key).
#
# Tomorrow (Captain): add Gemini (GEMINI_API_KEY, ~/10gem.txt — video) and
# Grok/xAI (~/10grok.txt), plus the PAID MiniMax — each is ONE new dict here.
# ─────────────────────────────────────────────────────────────────────────
ROSTER = [
    {"id": "local_code", "label": "Qwen2.5-14B", "family": "Alibaba", "tier": "local",
     "where": "RTX 3090 (.248)",
     "url_env": "TK_LOCAL_CODE_URL", "model_env": "TK_LOCAL_CODE_MODEL",
     "key_env": "TK_LOCAL_CODE_KEY",
     "url_default": "http://192.168.86.248:11434/v1", "model_default": "qwen2.5:14b"},
    {"id": "local_chat", "label": "Gemma 4 12B", "family": "Google", "tier": "local",
     "where": "A4000 (.41)",
     "url_env": "TK_LOCAL_CHAT_URL", "model_env": "TK_LOCAL_CHAT_MODEL",
     "key_env": "TK_LOCAL_CHAT_KEY",
     "url_default": "http://192.168.86.41:11434/v1", "model_default": "gemma4:12b"},
    {"id": "cloud_deepseek", "label": "DeepSeek", "family": "DeepSeek", "tier": "cloud",
     "where": "DeepSeek API",
     "url_env": "DEEPSEEK_URL", "model_env": "DEEPSEEK_MODEL", "key_env": "DEEPSEEK_API_KEY",
     "url_default": "https://api.deepseek.com/v1", "model_default": "deepseek-chat"},
    {"id": "cloud_glm", "label": "GLM 5.2", "family": "Zhipu", "tier": "cloud",
     "where": "Fireworks",
     "url_env": "GLM_URL", "model_env": "GLM_MODEL", "key_env": "FIREWORKS_API_KEY",
     "url_default": "https://api.fireworks.ai/inference/v1",
     "model_default": "accounts/fireworks/models/glm-5p2"},
    # Kimi K3 (Moonshot AI) — Captain's paid key (kimi.txt), 2026-07-17. Strong
    # reasoning + writing; burns a hidden reasoning channel (needs token headroom,
    # like DeepSeek). The K2.7-code variants are also on this key if wanted later.
    {"id": "cloud_kimi", "label": "Kimi K3", "family": "Moonshot", "tier": "cloud",
     "where": "Moonshot AI",
     "url_env": "KIMI_URL", "model_env": "KIMI_MODEL", "key_env": "KIMI_API_KEY",
     "url_default": "https://api.moonshot.ai/v1", "model_default": "kimi-k3"},
    {"id": "cloud_agnes", "label": "Agnes 2.0 Flash", "family": "Agnes", "tier": "cloud",
     "where": "Agnes AI · FREE tier",
     "url_env": "AGNES_URL", "model_env": "AGNES_MODEL", "key_env": "AGNES_API_KEY",
     "url_default": "https://apihub.agnes-ai.com/v1", "model_default": "agnes-2.0-flash"},
    # --- OpenRouter FREE shelf (one key = many free models; the "free commons").
    # Distinct models as separate paths so the router learns each one's SHAPE.
    # All share OPENROUTER_API_KEY (or.txt). Verified 2026-07-15: shelf is real
    # (Nemotron-Ultra-550B, Gemma-4-free, Nemotron-Omni multimodal). Free = ~200
    # req/day SHARED across all free models on an unfunded account; router treats
    # rate-limit/429 as a failure signal and forages accordingly.
    {"id": "cloud_nemotron", "label": "Nemotron 3 Ultra", "family": "NVIDIA", "tier": "cloud",
     "where": "OpenRouter · FREE",
     "url_env": "OPENROUTER_URL", "model_env": "OPENROUTER_NEMOTRON_MODEL", "key_env": "OPENROUTER_API_KEY",
     "url_default": "https://openrouter.ai/api/v1", "model_default": "nvidia/nemotron-3-ultra-550b-a55b:free"},
    {"id": "cloud_gemma4_or", "label": "Gemma 4 31B", "family": "Google", "tier": "cloud",
     "where": "OpenRouter · FREE",
     "url_env": "OPENROUTER_URL", "model_env": "OPENROUTER_GEMMA_MODEL", "key_env": "OPENROUTER_API_KEY",
     "url_default": "https://openrouter.ai/api/v1", "model_default": "google/gemma-4-31b-it:free"},
    {"id": "cloud_nemo_omni", "label": "Nemotron Omni (vision)", "family": "NVIDIA", "tier": "cloud",
     "where": "OpenRouter · FREE · multimodal",
     "url_env": "OPENROUTER_URL", "model_env": "OPENROUTER_OMNI_MODEL", "key_env": "OPENROUTER_API_KEY",
     "url_default": "https://openrouter.ai/api/v1", "model_default": "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free"},
    # --- PAID VISION paths (wired 2026-07-22 for the self-improvement loop) ---
    # Gemini: video/image analysis. Auth via x-goog-api-key header (handled in caller),
    # not Bearer. Cheaper than Grok for WATCHING an mp4 — prefer for critique.
    {"id": "cloud_gemini", "label": "Gemini 2.5 Flash", "family": "Google", "tier": "cloud",
     "where": "Google API · VISION (video/image)", "vision": True,
     "url_env": "GEMINI_BASE_URL", "model_env": "GEMINI_MODEL", "key_env": "GEMINI_API_KEY",
     "url_default": "https://generativelanguage.googleapis.com/v1beta",
     "model_default": "gemini-2.5-flash"},
    # Grok/xAI: also vision-capable but PRICEY (~$6.50/video clip per budget memo).
    # Use sparingly; the spend-gate prompts before every call.
    {"id": "cloud_grok", "label": "Grok", "family": "xAI", "tier": "cloud",
     "where": "xAI API · VISION · PRICEY", "vision": True,
     "url_env": "GROK_URL", "model_env": "GROK_MODEL", "key_env": "GROK_API_KEY",
     "url_default": "https://api.x.ai/v1", "model_default": "grok-4"},
]

# PATHS/LOCAL_PATHS are DERIVED from the roster so the whole module stays in sync.
PATHS = [e["id"] for e in ROSTER]
LOCAL_PATHS = {e["id"] for e in ROSTER if e["tier"] == "local"}

# PAID paths = cloud paths that actually cost money (subject to the $25 cap).
# Free = local (own GPUs), Agnes free tier, and OpenRouter :free models.
_FREE_CLOUD_IDS = {"cloud_agnes", "cloud_nemotron", "cloud_gemma4_or", "cloud_nemo_omni"}
PAID_PATHS = {e["id"] for e in ROSTER
              if e["tier"] == "cloud" and e["id"] not in _FREE_CLOUD_IDS}


def is_paid_path(path_id):
    """True if routing here costs real money (guardrail applies). Local/free = False."""
    return path_id in PAID_PATHS
# The outcome-attribute bundle the net predicts per path. Order is fixed.
# privacy = 1.0 if the path kept the work local/private, 0.0 if it went to cloud
# (the graphic's "Respects Privacy & Sovereignty" pillar, made measurable).
ATTRS = ["completed", "format_valid", "task_fit", "privacy", "cost", "latency"]
# reward attributes are maximized; penalty attributes are minimized.
REWARD_ATTRS = {"completed", "format_valid", "task_fit", "privacy"}
PENALTY_ATTRS = {"cost", "latency"}
N_OUT = len(PATHS) * len(ATTRS)   # 4 paths x 6 attrs = 24 outputs

# ---------------------------------------------------------------------------
# Fingerprint: cheap word-shape features from the REAL request. No LLM.
# ---------------------------------------------------------------------------
FEATURES = [
    "has_code_fence", "is_question", "length_norm", "numeric_density",
    "is_imperative", "open_ended", "live_info", "multi_hop",
]

_CODE_RE = re.compile(r"```|(?<![A-Za-z])(def|class|import|return|function|const|=>)\b")
_WH_RE = re.compile(r"\b(who|what|when|where|why|how|which)\b", re.I)
_IMP_RE = re.compile(r"\b(write|fix|make|refactor|implement|build|create|add|debug|optimi[sz]e)\b", re.I)
_OPEN_RE = re.compile(r"\b(tell me|what do you think|thoughts|imagine|feel|opinion|reflect|describe)\b", re.I)
_LIVE_RE = re.compile(r"\b(today|news|weather|latest|current|now|price|stock|score|recent)\b", re.I)
_HOP_RE = re.compile(r"\b(because|therefore|given that|so that|step by step|reason|deduce|infer)\b", re.I)
_NUM_RE = re.compile(r"\b\d[\d.,]*\b")
_CODEISH_RE = re.compile(r"```|[{}();=]|(?<![A-Za-z])(def|return|import|class|function)\b")
_DEFLECT_RE = re.compile(r"\b(cannot|can't|i don't have|unable to|no access|as an ai)\b", re.I)

# PRIVACY GATE (2026-07-16, Captain's directive: "local always better for privacy").
# When a request is SENSITIVE, cloud paths are EXCLUDED entirely — not out-weighed,
# EXCLUDED — so the work is guaranteed to stay on-prem. Sovereignty as a hard
# property, not a tradeable 0.5 nudge. Non-sensitive work routes normally.
# Cheap regex, same style as the fingerprint features; no LLM, no raw text leaves.
_SENSITIVE_RE = re.compile(
    r"\b(password|passphrase|secret|api[_ -]?key|token|credential|private key|ssh key|"
    r"confidential|classified|proprietary|nda|social security|ssn|credit card|bank|"
    r"medical|diagnosis|health record|personal data|pii|address|phone number|"
    r"do not share|keep (this|it) (private|local|between us)|off the record|"
    r"my (memory|journal|diary|notes)|fleet (internal|secret|config))\b", re.I)
# Explicit override tokens the Captain (or 隙) can drop in a request to force local.
_PRIVACY_FLAG_RE = re.compile(r"\[(private|local[-_ ]?only|sensitive|no[-_ ]?cloud)\]", re.I)


def is_sensitive(request):
    """True if the request should NEVER leave the box (regex, no LLM). Drives the
    privacy gate in choose(). Kept transparent so every gate decision is auditable."""
    t = request or ""
    return bool(_PRIVACY_FLAG_RE.search(t) or _SENSITIVE_RE.search(t))


def _tail(text, n=800):
    t = text or ""
    return t[-n:]


def fingerprint(request):
    """Request string -> 8-float word-shape vector in [0,1]. No LLM, no raw text out."""
    full = request or ""
    tail = _tail(full)
    toks = tail.split()
    n_tok = max(1, len(toks))
    return [
        1.0 if _CODE_RE.search(tail) else 0.0,
        1.0 if ("?" in tail or _WH_RE.search(tail)) else 0.0,
        min(1.0, math.log1p(len(full)) / math.log1p(4000)),
        min(1.0, len(_NUM_RE.findall(tail)) / n_tok * 4.0),
        1.0 if _IMP_RE.search(tail) else 0.0,
        1.0 if _OPEN_RE.search(tail) else 0.0,
        1.0 if _LIVE_RE.search(tail) else 0.0,
        1.0 if _HOP_RE.search(tail) else 0.0,
    ]


# ---------------------------------------------------------------------------
# Attribute MEASUREMENT — turn a (request, reply, cost, latency) into the raw
# outcome bundle for the path that actually ran. No LLM. All in [0,1].
# ---------------------------------------------------------------------------
def measure_outcome(request, reply, cost_usd, latency_ms, format_ok=None, is_local=True):
    """Return {attr: value in [0,1]} for the path that ran. cost/latency are
    normalized to [0,1] (higher = worse) so the bundle is uniform. is_local drives
    the privacy attribute (local work stays private/sovereign)."""
    r = (reply or "").strip()
    completed = 1.0 if r else 0.0

    # CONSISTENCY RULE (fix 2026-07-15): an EMPTY reply cannot have good quality.
    # Previously task_fit defaulted to 1.0 on empty live-info replies (only checked
    # for a deflection phrase), producing the misleading "completed=0 but fit=1.0"
    # rows that made the KRIs unreadable. If there's no reply, every quality attr is 0.
    if not r:
        privacy = 1.0 if is_local else 0.0
        cost = min(1.0, float(cost_usd) / 0.02)
        latency = min(1.0, float(latency_ms) / 8000.0)
        return {"completed": 0.0, "format_valid": 0.0, "task_fit": 0.0,
                "privacy": privacy, "cost": cost, "latency": latency}

    # format_valid: caller may pass the loop's real paren-balance result; else
    # a light structural check (balanced parens + at least one skill-ish token).
    if format_ok is not None:
        format_valid = 1.0 if format_ok else 0.0
    else:
        balanced = r.count("(") == r.count(")") and r.count('"') % 2 == 0
        format_valid = 1.0 if balanced else 0.0

    # task_fit: does the reply match the request KIND (cheap heuristics).
    fp = fingerprint(request)
    wants_code = fp[FEATURES.index("has_code_fence")] or fp[FEATURES.index("is_imperative")]
    wants_live = fp[FEATURES.index("live_info")]
    if wants_code:
        task_fit = 1.0 if _CODEISH_RE.search(r) else 0.4
    elif wants_live:
        task_fit = 0.2 if _DEFLECT_RE.search(r) else 1.0
    else:
        task_fit = 1.0

    privacy = 1.0 if is_local else 0.0                # stayed on-prem = private
    cost = min(1.0, float(cost_usd) / 0.02)          # $0.02 ~= "expensive" ceiling
    latency = min(1.0, float(latency_ms) / 8000.0)    # 8s ~= "slow" ceiling
    return {"completed": completed, "format_valid": format_valid,
            "task_fit": task_fit, "privacy": privacy, "cost": cost, "latency": latency}


# ---------------------------------------------------------------------------
# Transparent chooser: given predicted bundles per path, pick the best. The
# combination is a simple, INSPECTABLE utility (reward attrs add, penalty attrs
# subtract). These coefficients are the "safety prior" — mild, and the learning
# lives in the PREDICTED BUNDLES, not here. We keep this transparent so "why"
# is always answerable. (The net learns what each path will DO; this says what
# 'good' means, plainly.)
# ---------------------------------------------------------------------------
UTILITY = {  # sign already applied: reward positive, penalty negative
    "completed": 1.0, "format_valid": 0.9, "task_fit": 0.8, "privacy": 0.5,
    "cost": -1.2, "latency": -0.3,
}


def bundle_utility(bundle):
    return sum(UTILITY[a] * bundle.get(a, 0.0) for a in ATTRS)


# Swap cost: a cold 3090 path must pay a container flip before it can answer.
# We express it as an added latency penalty (in the same normalized [0,1] units
# measure_outcome uses: 8s = 1.0), so it flows through the existing utility.
SWAP_LATENCY_NORM = float(os.environ.get("TK_SWAP_LATENCY_NORM", "0.55"))  # ~4.4s of 8s ceiling


def choose(predicted, availability=None, sensitive=False):
    """predicted: {path: {attr: value}}. availability: {path: 'warm'|'cold'|
    'unavailable'} or None (all warm). Return (best_path, utility_by_path).

    - 'unavailable' paths are excluded from the choice entirely.
    - 'cold' paths keep their predicted quality but pay a swap-latency penalty,
      so the router picks a warm path over a better-but-cold one unless the cold
      path is clearly worth the flip. This is the 'right time' of the thesis.
    - PRIVACY GATE: if `sensitive`, every non-LOCAL path is excluded outright —
      the work is guaranteed to stay on-prem. Not a weight; a hard boundary.
    """
    availability = availability or {}
    util = {}
    for p, b in predicted.items():
        state = availability.get(p, "warm")
        if state == "unavailable":
            continue
        if sensitive and p not in LOCAL_PATHS:
            continue                   # privacy gate: sensitive work never leaves the box
        u = bundle_utility(b)
        if state == "cold":
            # penalize as if latency were higher by the swap cost.
            u += UTILITY["latency"] * SWAP_LATENCY_NORM
        util[p] = u
    if not util:                       # everything excluded — safe fallback
        return None, {}
    best = max(util, key=util.get)
    return best, util


# ---------------------------------------------------------------------------
# The PC-net: fingerprint(8) -> hidden -> N_OUT(20 = 4 paths x 5 attrs).
# ---------------------------------------------------------------------------
class Router:
    def __init__(self, seed=0):
        self._structure = None
        self._params = None
        self._optimizer = None
        self._ok = False
        self._seed = seed
        self._key = None
        self._jax = None
        self._primed = False

    def _lazy_init(self):
        if self._structure is not None:
            return self._ok
        try:
            from jax_setup import set_jax_flags_before_importing_jax
            set_jax_flags_before_importing_jax("cpu")
            import jax
            import optax
            from fabricpc.nodes import Linear, IdentityNode
            from fabricpc.core.topology import Edge
            from fabricpc.graph_assembly import TaskMap, graph
            from fabricpc.graph_initialization import initialize_params
            from fabricpc.core.activations import SigmoidActivation
            from fabricpc.core.energy import GaussianEnergy
            from fabricpc.core.inference import InferenceSGD
            from fabricpc.core.initializers import XavierInitializer

            jax.config.update("jax_default_prng_impl", "threefry2x32")
            inp = IdentityNode(shape=(len(FEATURES),), name="fingerprint")
            hidden = Linear(shape=(32,), activation=SigmoidActivation(),
                            name="hidden", weight_init=XavierInitializer())
            out = Linear(shape=(N_OUT,), activation=SigmoidActivation(),
                         energy=GaussianEnergy(), name="bundles",
                         weight_init=XavierInitializer())
            self._structure = graph(
                nodes=[inp, hidden, out],
                edges=[Edge(source=inp, target=hidden.slot("in")),
                       Edge(source=hidden, target=out.slot("in"))],
                task_map=TaskMap(x=inp, y=out),
                inference=InferenceSGD(eta_infer=0.1, infer_steps=20),
            )
            self._jax = jax
            self._key = jax.random.PRNGKey(self._seed)
            gkey, self._key = jax.random.split(self._key)
            self._params = initialize_params(self._structure, gkey)
            self._optimizer = optax.adamw(0.01, weight_decay=0.01)
            self._ok = True
            self._prime_safety_prior()
        except Exception as e:
            print(f"[tk_router] FabricPC unavailable, router disabled: {e}", flush=True)
            self._ok = False
        return self._ok

    def _unpack(self, flat):
        """flat 20-vec -> {path: {attr: value}}."""
        out = {}
        for i, p in enumerate(PATHS):
            seg = flat[i * len(ATTRS):(i + 1) * len(ATTRS)]
            out[p] = {a: float(seg[j]) for j, a in enumerate(ATTRS)}
        return out

    def _pack(self, bundles):
        """{path:{attr:val}} -> flat 20-vec."""
        flat = []
        for p in PATHS:
            b = bundles[p]
            flat.extend(float(b[a]) for a in ATTRS)
        return flat

    def _prime_safety_prior(self):
        """Cold-start 'safe prior, then unlearn it' (Captain's choice) — LOCAL-FIRST.
        The thesis is '$0 living, escalate only when free genuinely can't do it'. So
        the prior must FAVOR local/free: locals start with capability AT LEAST as high
        as clouds (qwen/gemma have PROVEN they work) PLUS their $0-cost + privacy edge.
        Clouds start SLIGHTLY LOWER on capability so the router must LEARN a cloud is
        worth the money for a specific hard task. (Fixed 2026-07-15: the old prior gave
        clouds higher capability → biased toward cloud before any learning, which made
        her slow + burned toward paid. Backwards for a local-first router.)"""
        if self._primed:
            return
        prior = {}
        for e in ROSTER:
            if e["tier"] == "local":
                # locals: high capability (proven), $0, private, fast
                prior[e["id"]] = {"completed": 0.9, "format_valid": 0.88, "task_fit": 0.85,
                                  "privacy": 1.0, "cost": 0.0, "latency": 0.25}
            else:
                # clouds: slightly LOWER capability prior + real cost + no privacy →
                # net utility below local until experience proves a cloud earns it.
                prior[e["id"]] = {"completed": 0.85, "format_valid": 0.82, "task_fit": 0.80,
                                  "privacy": 0.0, "cost": 0.45, "latency": 0.5}
        tgt = self._pack(prior)
        # teach it against a spread of generic fingerprints so it's not overfit to one.
        for seed_fp in ([0.5] * len(FEATURES), [0.0] * len(FEATURES), [1.0] * len(FEATURES)):
            self._train_step(seed_fp, tgt, epochs=40)
        self._primed = True

    def predict(self, request, availability=None, sensitive=None):
        """Return (chosen_path, predicted_bundles, utility_by_path, fingerprint).
        availability: {path: 'warm'|'cold'|'unavailable'} — swap-aware routing.
        sensitive: force the privacy gate (local-only). If None, auto-detected
        from the request via is_sensitive(). Safe default if FabricPC unavailable."""
        fp = fingerprint(request)
        if sensitive is None:
            sensitive = is_sensitive(request)
        if not self._lazy_init():
            return None, {}, {}, fp
        try:
            from fabricpc.graph_initialization.state_initializer import initialize_graph_state
            from fabricpc.core.inference import run_inference
            import numpy as np
            jax = self._jax
            x = jax.numpy.array([fp], dtype=jax.numpy.float32)
            x_node = self._structure.task_map["x"]
            y_node = self._structure.task_map["y"]
            clamps = {x_node: x}
            self._key, k = jax.random.split(self._key)
            state = initialize_graph_state(self._structure, 1, k, clamps=clamps, params=self._params)
            final = run_inference(self._params, state, clamps, self._structure)
            flat = np.asarray(final.nodes[y_node].z_mu[0])
            bundles = self._unpack(flat)
            best, util = choose(bundles, availability, sensitive=sensitive)
            return best, bundles, util, fp
        except Exception as e:
            print(f"[tk_router] predict failed, safe default: {e}", flush=True)
            return None, {}, {}, fp

    def learn_outcome(self, fp, path, measured_bundle, epochs=20):
        """Teach the net: for this fingerprint, the PATH that ran produced this
        measured bundle. Only that path's segment gets the real target; the
        others are left at their current prediction (no false signal)."""
        if not self._lazy_init():
            return
        try:
            import numpy as np
            # current prediction as the base target, then overwrite the ran path.
            best, bundles, util, _ = self.predict_from_fp(fp)
            bundles[path] = {a: float(measured_bundle[a]) for a in ATTRS}
            tgt = self._pack(bundles)
            self._train_step(fp, tgt, epochs=epochs)
        except Exception as e:
            print(f"[tk_router] learn_outcome skipped: {e}", flush=True)

    def predict_from_fp(self, fp):
        """Like predict() but takes a fingerprint directly (used by learn_outcome)."""
        if not self._lazy_init():
            return None, {p: {a: 0.0 for a in ATTRS} for p in PATHS}, {}, fp
        from fabricpc.graph_initialization.state_initializer import initialize_graph_state
        from fabricpc.core.inference import run_inference
        import numpy as np
        jax = self._jax
        x = jax.numpy.array([fp], dtype=jax.numpy.float32)
        clamps = {self._structure.task_map["x"]: x}
        self._key, k = jax.random.split(self._key)
        state = initialize_graph_state(self._structure, 1, k, clamps=clamps, params=self._params)
        final = run_inference(self._params, state, clamps, self._structure)
        flat = np.asarray(final.nodes[self._structure.task_map["y"]].z_mu[0])
        bundles = self._unpack(flat)
        best, util = choose(bundles)
        return best, bundles, util, fp

    def _train_step(self, fp, target_flat, epochs=20):
        from fabricpc.training import train_pcn
        import numpy as np

        class _Loader:
            def __init__(self, x, y):
                self.x = [x]; self.y = [y]
            def __len__(self):
                return 1
            def __iter__(self):
                yield (np.asarray(self.x, dtype="float32"),
                       np.asarray(self.y, dtype="float32"))

        self._key, tk = self._jax.random.split(self._key)
        self._params, _, _ = train_pcn(
            params=self._params, structure=self._structure,
            train_loader=_Loader(fp, target_flat),
            optimizer=self._optimizer, config={"num_epochs": epochs},
            rng_key=tk, verbose=False, use_tqdm=False,
        )


# ---------------------------------------------------------------------------
# Path availability (warm / cold / unavailable) — the swap-aware signal.
#
# A4000 (local_chat / gemma) is the DEDICATED always-warm spine -> always warm.
# 3090 (local_code / laguna) depends on the session's 3090 mode:
#   TK_3090_MODE=router  -> laguna is the resident model -> warm
#   TK_3090_MODE=render  -> 3090 runs ComfyUI (SEEN) -> laguna is COLD (would need
#                           a container swap that kills the render) -> we mark it
#                           'unavailable' so code routes to cloud, protecting the render.
#   TK_3090_MODE=auto/unset -> treat laguna as 'cold' (loadable but pays swap cost).
# Cloud paths are always 'warm' (no local load), gated only by having a key.
# ---------------------------------------------------------------------------
def path_availability():
    """Warm/cold/unavailable per path, derived from the roster + 3090 mode.
    Cloud paths = warm if their key env is set, else unavailable (no crash).
    The .248 (3090) local path follows TK_3090_MODE. Other locals = warm."""
    mode = os.environ.get("TK_3090_MODE", "router").strip().lower()
    avail = {}
    for e in ROSTER:
        pid = e["id"]
        if e["tier"] == "cloud":
            avail[pid] = "warm" if os.environ.get(e.get("key_env", "")) else "unavailable"
        elif ".248" in e.get("where", "") or "3090" in e.get("where", ""):
            # the swappable 3090 local path
            avail[pid] = ("unavailable" if mode == "render"
                          else "warm" if mode == "router" else "cold")
        else:
            avail[pid] = "warm"   # dedicated always-warm local (A4000)
    return avail


def roster_for_dashboard():
    """What the dashboard renders — one entry per configured path, resolved
    against the live env (so it shows the ACTUAL model/where, and whether a
    cloud key is present). The single source of truth, read-only."""
    out = []
    for e in ROSTER:
        model = os.environ.get(e.get("model_env", ""), e.get("model_default", ""))
        key_present = True if e["tier"] == "local" else bool(os.environ.get(e.get("key_env", "")))
        out.append({"id": e["id"], "label": e["label"], "family": e["family"],
                    "tier": e["tier"], "where": e["where"], "model": model,
                    "key_present": key_present})
    return out


# ---------------------------------------------------------------------------
# Spend guardrail — a hard $ ceiling for PAID cloud calls this sprint.
# Captain: "$25 to play, we want it to LEARN." So paid exploration is allowed,
# but bounded: once cumulative PAID spend hits the cap, paid paths are refused
# and the router forages free/local instead (it never goes dark). Free paths
# (agnes, openrouter :free, local) are NEVER blocked — spend on them is $0.
#
# The ledger persists to a file so the cap survives restarts (a restart must not
# silently reset the budget to $0 and let it overspend). Cost is the REAL
# per-call cost the caller records, not a guess.
# ---------------------------------------------------------------------------
SPEND_CAP_USD = float(os.environ.get("TK_SPEND_CAP_USD", "25.0"))
_SPEND_PATH = os.path.join(
    os.environ.get("MEMORY_DIR", "/PeTTa/repos/OmegaClaw-Core/memory"), "tk_spend.json")


def _read_spend():
    try:
        with open(_SPEND_PATH) as f:
            return float(json.load(f).get("paid_spend_usd", 0.0))
    except Exception:
        return 0.0


def _write_spend(total):
    try:
        d = os.path.dirname(_SPEND_PATH) or "."
        os.makedirs(d, exist_ok=True)
        tmp = _SPEND_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"paid_spend_usd": round(total, 6), "cap_usd": SPEND_CAP_USD,
                       "updated": None}, f)  # ts stamped by caller if wanted
        os.replace(tmp, _SPEND_PATH)
    except Exception:
        pass


def spend_status():
    """Current paid spend vs cap. remaining<=0 => paid paths must be refused."""
    spent = _read_spend()
    return {"spent": round(spent, 4), "cap": SPEND_CAP_USD,
            "remaining": round(max(0.0, SPEND_CAP_USD - spent), 4),
            "capped": spent >= SPEND_CAP_USD}


def record_paid_spend(cost_usd):
    """Add a real paid-call cost to the ledger. Returns new total."""
    if not cost_usd:
        return _read_spend()
    total = _read_spend() + float(cost_usd)
    _write_spend(total)
    return total


def paid_allowed():
    """True if there's budget left for a PAID call. Free/local always allowed."""
    return _read_spend() < SPEND_CAP_USD


# ---------------------------------------------------------------------------
# PROMPT-BEFORE-SPENDING approval gate (2026-07-22, Captain's directive for the
# first PDCA cycle: "prompt first before spending money"). A paid call is NOT
# fired until Larry approves it. Because 隙 runs autonomously (can't block on
# input), the gate is ASYNC:
#   * router wants a paid path -> writes a pending request to _APPROVAL_REQ
#   * Sparks (watching that file) relays it to Larry; on 'yes' writes a token
#     to _APPROVAL_OK naming the approved path
#   * approval is ONE-SHOT: consumed when the paid call proceeds
# Until approved, the router forages a free path for that tick (never hangs).
# ---------------------------------------------------------------------------
_MEMDIR = os.environ.get("MEMORY_DIR", "/PeTTa/repos/OmegaClaw-Core/memory")
_APPROVAL_REQ = os.path.join(_MEMDIR, "tk_paid_request.json")
_APPROVAL_OK  = os.path.join(_MEMDIR, "tk_paid_approved.json")

def request_paid_approval(path_id, est_cost_usd, reason=""):
    """Write a pending approval request for a paid call. Idempotent per path."""
    try:
        with open(_APPROVAL_REQ, "w") as f:
            json.dump({"path": path_id, "est_cost_usd": round(float(est_cost_usd or 0), 4),
                       "reason": (reason or "")[:200], "ts": None, "status": "pending"}, f)
    except Exception:
        pass

def paid_approved(path_id):
    """True iff there's a valid one-shot approval token for this path. Consumes it."""
    try:
        with open(_APPROVAL_OK) as f:
            tok = json.load(f)
        if tok.get("path") == path_id and tok.get("approved") is True:
            # consume (one-shot): remove the token so it can't be reused
            try: os.remove(_APPROVAL_OK)
            except Exception: pass
            return True
    except Exception:
        pass
    return False

def clear_paid_request():
    for p in (_APPROVAL_REQ,):
        try: os.remove(p)
        except Exception: pass


def log_row(path, row):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")
    except Exception:
        pass


# module-level singleton the live overlay imports
ROUTER = Router()
