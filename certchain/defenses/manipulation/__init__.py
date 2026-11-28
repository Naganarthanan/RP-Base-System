"""Manipulation defences (Conventional system side) - Blue team, Component 2.

To add a defence: create a module here, write run_<name>(attack, options=None) -> dict,
and register it in RUNNERS below, keyed by the defence id the frontend sends.
"""
from .single_sequence import run_single_sequence
from .vertical import run_k_sequence, run_single_odd

RUNNERS = {
    "single_sequence": run_single_sequence,
    "single_odd": run_single_odd,
    "k_sequence": run_k_sequence,
}

__all__ = ["RUNNERS"]