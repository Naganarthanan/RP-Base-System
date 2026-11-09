"""Shared helpers for the defence side (mirror of the attack side's common.py).

Kept separate from the attack side on purpose, so the attack team and the defence team
never edit the same file. Everything a defence strategy commonly needs lives here.
"""
from flask import current_app

from ..anchors import BloomAnchor, HashAnchor, canonical, field_item, sha256
from ..ledger import NODES

__all__ = ["systems", "BloomAnchor", "HashAnchor", "canonical", "field_item", "sha256", "NODES"]


def systems() -> dict:
    """The {name: Flask app} map for each system, set on the site app by create_site()."""
    return current_app.config["SYSTEMS"]
