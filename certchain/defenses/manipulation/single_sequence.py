"""Defence strategy 1: Single-sequence partitioning  -  id "single_sequence".

Rule (Algorithm 1): block i is stored on node p = ((i - 1) mod n) + 1, so consecutive blocks
cycle through the nodes in a fixed order. With the ledger's 0-based idx this is idx mod n.
The assignment itself is partition.SingleSequence; this module runs it against the attack.

Options (all optional):  nodes - number of organisations/nodes, 2..9 (default 3).
The strategy itself is fixed: any other option is ignored.
"""
from .vertical import run_vertical

DEFENSE_ID = "single_sequence"
NAME = "Single-sequence partitioning"


def run_single_sequence(attack: str = "collusion", options: dict | None = None) -> dict:
    opts = {"strategy": "single_sequence"}
    if options and "nodes" in options:
        opts["nodes"] = options["nodes"]
    return run_vertical(attack, opts, defense=DEFENSE_ID, name=NAME)