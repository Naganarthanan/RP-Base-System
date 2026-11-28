"""Adaptive (worst-case) inference attacker.

A real attacker is not limited to one technique. For every coalition size this attacker
pools what the colluding nodes hold and tries all three inference techniques on it:

  Dictionary            needs the key, so only coalitions at or above the key threshold
  Pattern linkage       no key, on the pooled bits
  Reference similarity  no key, on the pooled bits, with known labelled records

and keeps the technique with the highest attacker advantage. Advantage, (ASR - chance) /
(1 - chance), puts the three techniques on one scale even though their random-guess
rates differ. A defence is then judged by the worst coalition below all nodes, as the
collusion attack does: when every organisation colludes, nothing is left hidden.
"""
from itertools import combinations

from ..common import NODES, systems
from . import collusion, pattern_mining, reference_similarity
from .views import check_views, full_mask

TECHNIQUES = {
    "collusion": "Dictionary",
    "pattern_mining": "Pattern linkage",
    "reference_similarity": "Reference similarity",
}


def _coalitions(views) -> dict[int, list[dict]]:
    """Every coalition of the given views, by size, as pooled views."""
    by_size = {}
    for size in range(1, len(views) + 1):
        by_size[size] = []
        for group in combinations(views, size):
            mask = 0
            for view in group:
                mask |= view["mask"]
            by_size[size].append({"node": " + ".join(v["node"] for v in group), "mask": mask})
    return by_size


def _advantage(r) -> float:
    return (r.get("security") or {}).get("advantage", 0.0)


def _pick(candidates):
    """The (technique, row) pair with the highest advantage; ties go to the higher ASR."""
    return max(candidates, key=lambda c: (_advantage(c[1]), c[1]["success_rate"]))


def run_on_views(views, encoding=None) -> dict:
    """Run every technique for every coalition of the given views and keep the best per size."""
    m = systems()["bloom"].config["anchor"].M
    views = check_views(views, m)
    by_size = _coalitions(views)
    pooled = [view for size in sorted(by_size) for view in by_size[size]]
    size_of = {view["node"]: size for size, group in by_size.items() for view in group}

    results = {
        "collusion": collusion.run_on_views(views, encoding=encoding),
        "pattern_mining": pattern_mining.run_on_views(pooled, encoding=encoding),
        "reference_similarity": reference_similarity.run_on_views(pooled, encoding=encoding),
    }

    def summary(candidates):
        best = {}
        for t, r in candidates:
            best[t] = max(best.get(t, 0.0), _advantage(r))
        return ", ".join(f"{TECHNIQUES[t]} {adv:.0%}" for t, adv in best.items())

    base_candidates = [(t, results[t]["baseline"]) for t in TECHNIQUES]
    tech, chosen = _pick(base_candidates)
    baseline = {**chosen, "label": f"No defence (best: {TECHNIQUES[tech]})", "technique": TECHNIQUES[tech],
                "detail": f"Attacker advantage by technique: {summary(base_candidates)}"}

    rows = []
    for size in sorted(by_size):
        candidates = [("collusion", results["collusion"]["rows"][size - 1])]
        for t in ("pattern_mining", "reference_similarity"):
            candidates += [(t, r) for r in results[t]["rows"] if size_of.get(r["label"]) == size]
        tech, chosen = _pick(candidates)
        rows.append({**chosen, "label": f"{size} colluding (best: {TECHNIQUES[tech]})",
                     "technique": TECHNIQUES[tech], "colluding": size,
                     "detail": f"Best coalition {', '.join(chosen['nodes']) or 'all'}. "
                               f"Attacker advantage by technique: {summary(candidates)}"})

    partial = rows[:-1] or rows
    worst = max(partial, key=lambda r: (_advantage(r), r["success_rate"]))
    below_all = len(views) - 1
    return {
        "attack": "adaptive",
        "metric": "Best technique per coalition (worst case)",
        "baseline": baseline,
        "rows": rows,
        "techniques": {TECHNIQUES[t]: results[t]["security"] for t in TECHNIQUES},
        "security": {**worst["security"], "worst_attacker": worst["label"], "technique": worst["technique"]},
        "conclusion": (
            f"With no defence the strongest technique is {baseline['technique']} "
            f"(advantage {_advantage(baseline):.0%}). Under this defence the worst coalition of up to "
            f"{below_all} node{'s' if below_all != 1 else ''} reaches an advantage of {_advantage(worst):.0%} "
            f"using {worst['technique']}. When all {len(views)} nodes collude every defence falls, as expected."
        ),
    }


def run_inference_adaptive() -> dict:
    """The adaptive attacker with no defence: every node holds the complete stored filters."""
    m = systems()["bloom"].config["anchor"].M
    result = run_on_views([{"node": node, "mask": full_mask(m)} for node in NODES])
    return {"check": "inference", "system": "bloom", **result,
            "scenario": "Every organisation holds complete Bloom filters; the attacker tries every technique."}


def run_on_encoding(encoding) -> dict:
    """The adaptive attacker against an encoding-only defence: every node sees the whole filter."""
    m = systems()["bloom"].config["anchor"].M
    return run_on_views([{"node": node, "mask": full_mask(m)} for node in NODES], encoding=encoding)
