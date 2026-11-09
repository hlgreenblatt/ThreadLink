"""ThreadHello — ThreadRouter agents introducing themselves and trading
learned FabricPC route tables, over a ThreadLink comlink.

ThreadRouter answers "where should this work go?". ThreadHello answers "what
routing knowledge can two routers exchange?". ThreadLink answers "how do two
agents talk at all?" — and lives in its own repo, because it is useful to
agents that have never heard of routing.
"""

from .hello import (
    HelloAgent, HelloMsg, HELLO_VERSION, THREADHELLO,
    classify_model, assurance_rank, ASSURANCE_LADDER,
)
from .routeshare import RouteStore, Observation, cell_key, fp_of_cell, ATTRS

__version__ = "0.2.0"
__all__ = [
    "HelloAgent", "HelloMsg", "HELLO_VERSION", "THREADHELLO",
    "classify_model", "assurance_rank", "ASSURANCE_LADDER",
    "RouteStore", "Observation", "cell_key", "fp_of_cell", "ATTRS",
]
