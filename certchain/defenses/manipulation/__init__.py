"""Manipulation defences (Conventional system side) - Blue team, Component 2.

To add a defence: create a module here, write run_<name>(attack, options=None) -> dict,
and register it in RUNNERS below, keyed by the defence id the frontend sends.
"""
from .vertical import run_vertical

RUNNERS = {
    "vertical": run_vertical,
}

__all__ = ["RUNNERS", "run_vertical"]