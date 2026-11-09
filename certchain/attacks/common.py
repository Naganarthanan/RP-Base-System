"""Helpers shared by both attack sides (manipulation and inference).

Side-specific constants live in each side's own folder; only things both sides need
belong here, so the two teams can work without touching the same file.
"""
from flask import current_app

from ..anchors import BloomAnchor, HashAnchor, canonical, field_item, sha256
from ..ledger import NODES

__all__ = ["systems", "BloomAnchor", "HashAnchor", "canonical", "field_item", "sha256", "NODES"]


def systems() -> dict:
    """The {name: Flask app} map for each system, set on the site app by create_site()."""
    return current_app.config["SYSTEMS"]
