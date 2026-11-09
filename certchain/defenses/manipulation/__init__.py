"""Manipulation defences (Conventional system side).

SCAFFOLD ONLY — no defence is implemented yet. To add one:
  1. Create a module in this folder, e.g. keyed.py or forensic.py.
  2. Write a function that applies/evaluates the defence and returns a JSON-able dict.
  3. Register it in RUNNERS below, keyed by the defence id the frontend sends.

Shared helpers: ``from ..common import systems, HashAnchor, BloomAnchor, ...``.
Candidate defence ids (from the UI): vertical, forensic, consensus, keyed.
"""
RUNNERS: dict = {}

__all__ = ["RUNNERS"]
