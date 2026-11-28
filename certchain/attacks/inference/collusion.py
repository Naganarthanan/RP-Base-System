"""Collusion inference attack on the Bloom filter chain.

The chain's inference protection rests on a secret Bloom key. We model that key as
shared among the organisations that run the nodes, reconstructable only when a majority
collude (a threshold scheme). A single organisation can confirm nothing; once enough
collude they recover the key and can test guesses against every block. The result is the
blast radius: how many blocks become exposed at each collusion size. Touches only the
Bloom filter system's inference attack, nothing else.
"""
from itertools import combinations

from ..common import NODES, field_item, systems
from .data import PROGRAMME_GUESSES
from .measures import asr, attach_view_measures, measures, timer
from .views import check_views, filter_int, full_mask, positions_mask, row

# Fields a colluder's dictionary targets, by the transaction types that carry them.
COLLUSION_TARGETS = {
    "programme": ("student.upsert", "certificate.issue"),
}


def _guess_masks(impl) -> list[int]:
    """The Bloom positions of every dictionary guess, as masks (computed with the key)."""
    probe = impl.new_filter()
    return [positions_mask(probe.positions(field_item(tx_type, field, guess)))
            for field, types in COLLUSION_TARGETS.items()
            for tx_type in types
            for guess in PROGRAMME_GUESSES]


def _exposure(blocks: list[int], guesses: list[int], mask: int) -> tuple[int, int]:
    """(confirmed, candidate) blocks for a coalition that holds the key but sees only `mask`.

    Confirmed: every position of some guess is visible and set, the same test the full
    filter allows. Candidate: every *visible* position of some guess is set, but part of it
    is hidden, so the guess cannot be confirmed (a weaker, false-positive-prone signal).
    """
    confirmed = candidate = 0
    for bits in blocks:
        full = partial = False
        for g in guesses:
            seen = g & mask
            if not seen or bits & seen != seen:
                continue
            if seen == g:
                full = True
                break
            partial = True
        confirmed += full
        candidate += full or partial
    return confirmed, candidate


def run_on_views(views) -> dict:
    """Collusion against defence-supplied node views (see views.py).

    For every coalition size the worst-case coalition is used: the one whose pooled views
    expose the most blocks. Below the key threshold no guess can be tested at all.
    """
    app = systems()["bloom"]
    impl = app.config["anchor"]
    m = impl.M
    views = check_views(views, m)
    blocks = [filter_int(impl.new_filter(a["bits"]))
              for a in app.config["ledger"].anchors().values() if "bits" in a]
    total = len(blocks)
    guesses = _guess_masks(impl)
    threshold = len(views) // 2 + 1

    def measure(label, nodes, mask, has_key):
        with timer() as elapsed:
            confirmed, candidate = _exposure(blocks, guesses, mask) if has_key else (0, 0)
        detail = (f"{confirmed} of {total} blocks confirmed, {candidate} candidates"
                  if has_key else "Bloom key not reconstructed; no guess can be tested")
        return row(label, nodes, mask, m, confirmed / total if total else 0.0, detail,
                   key_reconstructed=has_key, blocks_confirmed=confirmed, blocks_candidate=candidate,
                   attack_ms=round(elapsed(), 1))

    baseline = measure(f"{threshold} colluding, complete filter (no defence)", [], full_mask(m), True)
    rows = []
    for size in range(1, len(views) + 1):
        options = []
        for group in combinations(views, size):
            mask = 0
            for v in group:
                mask |= v["mask"]
            options.append(([v["node"] for v in group], mask))
        has_key = size >= threshold
        results = [measure(f"{size} colluding", nodes, mask, has_key) for nodes, mask in options]
        rows.append(max(results, key=lambda r: (r["success_rate"], r["visible_bits"])))

    at_threshold = rows[threshold - 1]
    for size, r in enumerate(rows, start=1):
        r["colluding"] = size
    result = {
        "attack": "collusion",
        "metric": "Blocks whose programme is confirmed (worst-case coalition)",
        "threshold": threshold,
        "total_blocks": total,
        "baseline": baseline,
        "rows": rows,
        "conclusion": (
            f"With complete filters, {threshold} colluding organisations confirm the programme in "
            f"{baseline['blocks_confirmed']} of {total} blocks. Under this partitioning the worst "
            f"{threshold}-node coalition sees {at_threshold['visibility_percentage']}% of each "
            f"filter and confirms {at_threshold['blocks_confirmed']} of {total}; a guess is only "
            f"confirmed when all {impl.K} of its positions fall inside the pooled partitions."
        ),
    }
    attach_view_measures(result)
    # Every defence falls when all organisations collude, so the headline is the worst
    # coalition smaller than all nodes (as the manipulation side's detection rate does).
    partial = rows[:-1] or rows
    worst = max(partial, key=lambda r: (r["success_rate"], r["visible_bits"]))
    result["security"] = {**worst["security"], "worst_attacker": worst["label"],
                          "collusion_threshold": _collusion_threshold(rows, "blocks_confirmed")}
    return result


def _collusion_threshold(rows, key="blocks_exposed"):
    """Fewest colluding organisations that expose at least one block (None if none do)."""
    return next((r["colluding"] for r in rows if r[key] > 0), None)


def run_inference_collusion() -> dict:
    with timer() as elapsed:
        app = systems()["bloom"]
        impl = app.config["anchor"]
        anchors = app.config["ledger"].anchors()
        total = sum(1 for a in anchors.values() if "bits" in a)

        # With the key, run the dictionary over every block and count those exposed.
        exposed = 0
        for a in anchors.values():
            if "bits" not in a:
                continue
            bloom = impl.new_filter(a["bits"])
            hit = any(field_item(tx_type, field, guess) in bloom
                      for field, types in COLLUSION_TARGETS.items()
                      for tx_type in types
                      for guess in PROGRAMME_GUESSES)
            if hit:
                exposed += 1

    nodes = len(NODES)
    threshold = nodes // 2 + 1
    matrix = [{
        "colluding": c,
        "key_reconstructed": c >= threshold,
        "blocks_exposed": exposed if c >= threshold else 0,
    } for c in range(1, nodes + 1)]
    for m in matrix:
        m["asr"] = round(asr(m["blocks_exposed"], total), 4)

    # Without the key no guess can be tested, so a random guess confirms nothing: chance = 0.
    security = measures(asr(exposed, total), attack_ms=elapsed(),
                        collusion_threshold=_collusion_threshold(matrix),
                        collusion_threshold_fraction=round(threshold / nodes, 4))

    return {
        "check": "inference",
        "attack": "collusion",
        "system": "bloom",
        "nodes": nodes,
        "threshold": threshold,
        "total_blocks": total,
        "blocks_exposed": exposed,
        "matrix": matrix,
        "security": security,
        "scenario": f"The {nodes} organisations that run the Bloom filter chain pool their key shares.",
        "conclusion": (
            f"One organisation on its own cannot test any guess, so no block is exposed. Once "
            f"{threshold} of {nodes} collude they reconstruct the Bloom key and can confirm values "
            f"in {exposed} of {total} blocks. A colluding majority defeats the keyed-Bloom inference "
            f"protection, so the key must be split so that no reachable group of organisations holds it."
        ),
    }
