"""Shared shape for running an inference attack against restricted Bloom-filter views.

A defence (for example horizontal partitioning) decides which Bloom positions each node
can see. It hands the attack a list of views, ``[{"node": str, "mask": int}]``, where bit
p of ``mask`` is set when Bloom position p is visible to that node. The attack then runs
its own logic on the visible bits only and returns rows in the shape built here, so the
defence and the UI can show every attack the same way.

Bit p of a filter int is Bloom position p (``int.from_bytes(bits, "little")``).
"""


def filter_int(bloom) -> int:
    """A Bloom filter's bits as an int where bit p is Bloom position p."""
    return int.from_bytes(bloom.bits, "little")


def full_mask(m: int) -> int:
    return (1 << m) - 1


def positions_mask(positions) -> int:
    mask = 0
    for p in positions:
        mask |= 1 << p
    return mask


def check_views(views, m: int) -> list[dict]:
    """Validate the views a defence passes in; every view must see at least one bit."""
    if not isinstance(views, list) or not views:
        raise ValueError("at least one node view is required")
    checked = []
    for view in views:
        node, mask = view.get("node"), view.get("mask")
        if not isinstance(node, str) or not node or not isinstance(mask, int) or mask <= 0:
            raise ValueError("each view needs a node name and a non-empty position mask")
        if mask >> m:
            raise ValueError("a view mask covers positions outside the Bloom filter")
        checked.append({"node": node, "mask": mask})
    return checked


def row(label: str, nodes: list[str], mask: int, m: int, success_rate: float, detail: str, **extra) -> dict:
    """One result row: who attacked, how much they saw, and how well the attack did."""
    visible = mask.bit_count()
    return {
        "label": label,
        "nodes": list(nodes),
        "visible_bits": visible,
        "visibility_percentage": round(visible * 100 / m, 2),
        "success_rate": round(success_rate, 4),
        "detail": detail,
        **extra,
    }
