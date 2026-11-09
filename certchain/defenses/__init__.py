"""Defence strategies for the security check, split by side (scaffold).

    defenses/
      common.py        shared helpers for both defence folders
      inference/       inference defences     (one owner)
      manipulation/    manipulation defences  (another owner)

Each leaf package exposes a RUNNERS dict (defence id -> function). Add a module in your
folder and register it in that folder's __init__.py; no file outside your folder changes,
so the two defence owners never clash. Nothing is wired into the app yet — the attack
side is live, the defence side is for the teams to fill in.
"""
from . import inference, manipulation

RUNNERS = {**inference.RUNNERS, **manipulation.RUNNERS}

__all__ = ["RUNNERS"]
