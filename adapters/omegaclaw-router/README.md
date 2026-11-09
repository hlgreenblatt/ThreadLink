# OmegaClaw adapter

ThreadRouter is a toolkit, not a modification of any agent framework. This
directory is everything OmegaClaw-specific: a thin adapter that plugs the
toolkit into an [OmegaClaw](https://github.com/asi-alliance/OmegaClaw-Core)
agent. Nothing in here is imported by the toolkit core — delete this directory
and `tk_router`, `threadhello`, and every test still run.

## What an adapter provides

Any host framework (OmegaClaw, OpenClaw, Hermes, …) integrates by supplying
three things, in its own idiom:

1. **An invoke surface** — how the agent calls routed work from its own
   language. Here that is MeTTa: `skills.metta` binds
   `(watch-film "path.mp4")` → `watchfilm.watch`.
2. **An outcome hookup** — after a routed call completes, feed what happened
   back to the router: `tk_router.measure_outcome(...)` →
   `Router.learn_outcome(...)`. This is what makes the routing *learned*
   rather than configured.
3. **Environment plumbing** — keys and paths via the host's config mechanism
   (OmegaClaw: `.env`, see the repo-root `.env.example`; no keys in the repo,
   ever).

## Files

| File | What it is |
|------|------------|
| `skills.metta` | The MeTTa skill surface — how an OmegaClaw agent invokes routed work in her own language. |
| `watchfilm.py` | The `(watch-film …)` skill: a real paid vision workload routed through the toolkit, honoring the spend cap and the prompt-before-spending approval gate. Deploys by mounting next to `tk_router.py` in the agent's `src/`. |

## Deploying into an OmegaClaw agent

Mount `tk_router.py` (repo root) as the router, `watchfilm.py` as
`src/watchfilm.py`, and `skills.metta` carries the binding. Set `TK_ROUTER=on`
and supply keys via `.env`. The agent then calls, in her own MeTTa:

```
(watch-film "seen-trailer/SEEN-3TITLE-MUSIC-ALPHA.mp4")
```

Adapters for other frameworks are welcome — the contract above is the whole
interface.
