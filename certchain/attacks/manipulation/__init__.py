"""Manipulation attacks: forge records and test the anchor (Conventional system side).

Add a new manipulation attack by creating a module here and registering its runner in
RUNNERS below. The key is the check-kind the frontend posts to /api/security/<kind>.
"""
from .collusion_attack import run_manipulation_collusion
from .forgery import run_manipulation

RUNNERS = {
    "manipulation": run_manipulation,
    "manipulation_collusion": run_manipulation_collusion,
    "collusion_manipulation": run_manipulation_collusion,
}

__all__ = ["run_manipulation", "run_manipulation_collusion", "RUNNERS"]
