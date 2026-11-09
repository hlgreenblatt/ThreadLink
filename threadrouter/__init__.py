"""ThreadRouter — "where should this work go?"

A learning model router. A request is reduced to a word-shape fingerprint (no
model call, no raw text kept), a FabricPC predictive-coding net predicts an
outcome bundle per path (completed, format, fit, privacy, cost, latency), and a
small transparent chooser picks the path. After the work runs, the real bundle
teaches the net. ThreadHello lets routers share what they learn.

The router itself lives in `tk_router` (its name in the agents that run it).
FabricPC is optional: without it, predict() returns no prediction and the
caller stays on its normal provider, so the router can never break a loop.
To learn, clone FabricPC (https://github.com/trueagi-io/FabricPC), install it
with `pip install -e ./FabricPC`, and put its folder on the Python path.

`tk_router.ROSTER` holds one fleet's model list as the example it was built
from. Point your own paths at your own models through the environment
variables each entry names; see `env.example` beside this file.
"""

from . import tk_router
from .tk_router import ATTRS, PATHS, ROSTER, Router, choose, fingerprint, measure_outcome

__all__ = ["tk_router", "ATTRS", "PATHS", "ROSTER", "Router", "choose", "fingerprint", "measure_outcome"]
