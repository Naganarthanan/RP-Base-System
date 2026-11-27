"""Security-check attacks, split by side so the two teams don't collide.

* manipulation/ - attacks that forge records and test the anchor (Conventional system).
* inference/    - attacks that try to confirm values from the chain (Bloom filter system).
* common.py     - helpers shared by both sides.

Each side's package exposes a RUNNERS dict (check-kind -> runner). To add an attack,
drop a module in the right folder and register it in that folder's __init__.py; no other
file needs to change. The site endpoint dispatches /api/security/<kind> through RUNNERS.
"""
from . import inference, manipulation

RUNNERS = {**manipulation.RUNNERS, **inference.RUNNERS}

run_manipulation = manipulation.run_manipulation
run_manipulation_collusion = manipulation.run_manipulation_collusion
sequence_rewrite_collusion = manipulation.sequence_rewrite_collusion
odd_node_hijack = manipulation.odd_node_hijack
k_group_tampering = manipulation.k_group_tampering
run_asset_substitution = manipulation.run_asset_substitution
run_field_rewrite = manipulation.run_field_rewrite
run_node_copy_rewrite = manipulation.run_node_copy_rewrite
run_qr_metadata_swap = manipulation.run_qr_metadata_swap
run_inference = inference.run_inference
run_inference_collusion = inference.run_inference_collusion

__all__ = [
    "RUNNERS",
    "run_manipulation",
    "run_manipulation_collusion",
    "sequence_rewrite_collusion",
    "odd_node_hijack",
    "k_group_tampering",
    "run_asset_substitution",
    "run_field_rewrite",
    "run_node_copy_rewrite",
    "run_qr_metadata_swap",
    "run_inference",
    "run_inference_collusion",
]
