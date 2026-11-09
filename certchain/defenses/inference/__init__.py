"""Inference defences (Bloom filter system side).

SCAFFOLD ONLY — no defence is implemented yet. To add one:
  1. Create a module in this folder, e.g. salted.py or horizontal.py.
  2. Write a function that applies/evaluates the defence and returns a JSON-able dict.
  3. Register it in RUNNERS below, keyed by the defence id the frontend sends.

Shared helpers: ``from ..common import systems, BloomAnchor, field_item, ...``.
Candidate defence ids (from the UI): keyedbloom, salt, horizontal, padding.
"""
RUNNERS: dict = {}

__all__ = ["RUNNERS"]
