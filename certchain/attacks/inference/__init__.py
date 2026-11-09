"""Inference attacks: confirm values from the chain (Bloom filter system side).

Add a new inference attack by creating a module here and registering its runner in
RUNNERS below. The key is the check-kind the frontend posts to /api/security/<kind>.
"""
from .baseline import run_inference
from .collusion import run_inference_collusion

RUNNERS = {
    "inference": run_inference,
    "collusion": run_inference_collusion,
}

__all__ = ["run_inference", "run_inference_collusion", "RUNNERS"]
