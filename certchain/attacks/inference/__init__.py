"""Inference attacks: confirm values from the chain (Bloom filter system side).

Add a new inference attack by creating a module here and registering its runner in
RUNNERS below. The key is the check-kind the frontend posts to /api/security/<kind>.
"""
from .baseline import run_inference
from .collusion import run_inference_collusion
from .pattern_mining import run_inference_pattern_mining
from .reference_similarity import run_inference_reference_similarity

from . import collusion, pattern_mining, reference_similarity

RUNNERS = {
    "inference": run_inference,
    "collusion": run_inference_collusion,
    "pattern_mining": run_inference_pattern_mining,
    "reference_similarity": run_inference_reference_similarity,
}

# Attacks a defence can run against its own per-node views: id -> run_on_views(views).
# A view is {"node": name, "mask": int}; see views.py for the shared result shape.
VIEW_RUNNERS = {
    "collusion": collusion.run_on_views,
    "pattern_mining": pattern_mining.run_on_views,
    "reference_similarity": reference_similarity.run_on_views,
}

__all__ = ["run_inference", "run_inference_collusion", "run_inference_pattern_mining",
           "run_inference_reference_similarity", "RUNNERS", "VIEW_RUNNERS"]
