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
run_inference = inference.run_inference
run_inference_collusion = inference.run_inference_collusion

__all__ = ["RUNNERS", "run_manipulation", "run_inference", "run_inference_collusion"]
