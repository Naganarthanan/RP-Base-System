"""Manipulation defences (Conventional system side) - Blue team, Component 2.

To add a defence: create a module here, write run_<name>(attack, options=None) -> dict,
and register it in RUNNERS below, keyed by the defence id the frontend sends.
"""
from .single_sequence import run_single_sequence

RUNNERS = {
    "single_sequence": run_single_sequence,
}

__all__ = ["RUNNERS"]