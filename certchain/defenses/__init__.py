"""Defence strategies registered with the shared security-check dispatcher.

The inference and manipulation components keep their implementations separate.
Each leaf package exposes a ``RUNNERS`` mapping from defence id to runner.
"""
from . import inference, manipulation

RUNNERS = {**inference.RUNNERS, **manipulation.RUNNERS}

__all__ = ["RUNNERS"]
