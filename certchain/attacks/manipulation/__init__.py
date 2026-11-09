"""Manipulation attacks: forge records and test the anchor (Conventional system side).

Add a new manipulation attack by creating a module here and registering its runner in
RUNNERS below. The key is the check-kind the frontend posts to /api/security/<kind>.
"""
from .forgery import run_manipulation

RUNNERS = {
    "manipulation": run_manipulation,
}

__all__ = ["run_manipulation", "RUNNERS"]
