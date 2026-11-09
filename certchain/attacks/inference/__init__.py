"""Inference attacks: confirm values from the chain (Bloom filter system side).

Add a new inference attack by creating a module here and registering its runner in
RUNNERS below. The key is the check-kind the frontend posts to /api/security/<kind>.
"""
from .baseline import run_inference
from .collusion import run_inference_collusion
from .pattern_mining import run_inference_pattern_mining

RUNNERS = {
    "inference": run_inference,
    "collusion": run_inference_collusion,
    "pattern_mining": run_inference_pattern_mining,
}

__all__ = ["run_inference", "run_inference_collusion", "run_inference_pattern_mining", "RUNNERS"]
