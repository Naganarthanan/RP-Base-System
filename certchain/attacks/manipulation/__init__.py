"""Manipulation attacks: forge records and test the anchor (Conventional system side).

Add a new manipulation attack by creating a module here and registering its runner in
RUNNERS below. The key is the check-kind the frontend posts to /api/security/<kind>.
"""
from .collusion_attack import run_manipulation_collusion
from .forgery import (
    run_asset_substitution,
    run_field_rewrite,
    run_manipulation,
    run_node_copy_rewrite,
    run_qr_metadata_swap,
)
from .measures import advantage, asr, defense_effectiveness, measures, timer
from .partition_attacks import (
    sequence_rewrite_collusion,
    odd_node_hijack,
    k_group_tampering,
)

RUNNERS = {
    "manipulation": run_manipulation,
    "manipulation_collusion": run_manipulation_collusion,
    "collusion_manipulation": run_manipulation_collusion,
    "sequence_rewrite_collusion": sequence_rewrite_collusion,
    "odd_node_hijack": odd_node_hijack,
    "k_group_tampering": k_group_tampering,
    "asset": run_asset_substitution,
    "asset_substitution": run_asset_substitution,
    "field": run_field_rewrite,
    "field_rewrite": run_field_rewrite,
    "node": run_node_copy_rewrite,
    "node_copy_rewrite": run_node_copy_rewrite,
    "qr": run_qr_metadata_swap,
    "qr_swap": run_qr_metadata_swap,
}

__all__ = [
    "run_manipulation",
    "run_manipulation_collusion",
    "sequence_rewrite_collusion",
    "odd_node_hijack",
    "k_group_tampering",
    "run_asset_substitution",
    "run_field_rewrite",
    "run_node_copy_rewrite",
    "run_qr_metadata_swap",
    "measures",
    "asr",
    "advantage",
    "defense_effectiveness",
    "timer",
    "RUNNERS",
]
