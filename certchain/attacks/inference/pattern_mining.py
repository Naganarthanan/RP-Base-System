"""Attack pattern mining: link records by Bloom-filter similarity, without the key.

A keyed Bloom filter hides a field's value, but the same value always maps to the same
bits. So two records that share a field (e.g. the same programme) have more bits in
common than chance predicts. Mining the chain for these elevated overlaps groups
records that share a value - a structural inference leak that needs no key at all.

The attacker only reads the stored filters (public on the chain) and counts shared bits;
nothing here uses the secret key or recovers an actual value.
"""
from ..common import systems
from .views import check_views, filter_int, full_mask, row

# Extra shared bits, beyond what chance predicts, that flag two records as linked.
# One shared keyed field contributes about k (=10) set bits, so this margin (~2 fields'
# worth) only links records that share two or more low-entropy values - a confident link
# that random overlap almost never reaches.
LINK_MARGIN = 18


def _popcount(n: int) -> int:
    return bin(n).count("1")


def _chain_filters() -> tuple[int, list[tuple[int, int]]]:
    """(m, [(block index, filter int)]) for every Bloom anchor on the chain."""
    app = systems()["bloom"]
    impl = app.config["anchor"]
    return impl.M, [(idx, filter_int(impl.new_filter(a["bits"])))
                    for idx, a in app.config["ledger"].anchors().items() if "bits" in a]


def mine(filters: list[tuple[int, int]], m: int, mask: int | None = None) -> dict:
    """Link blocks whose shared bits exceed chance, looking only at the `mask` positions."""
    if mask is not None:
        filters = [(idx, value & mask) for idx, value in filters]
        m = mask.bit_count()
    blocks = [(idx, value, _popcount(value)) for idx, value in filters]
    total = len(blocks)

    # Union-find over blocks whose shared-bit count exceeds chance by the margin.
    parent = {idx: idx for idx, _, _ in blocks}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    links = 0
    for i in range(total):
        idx_i, bi, si = blocks[i]
        for j in range(i + 1, total):
            idx_j, bj, sj = blocks[j]
            overlap = _popcount(bi & bj)
            expected = si * sj / m
            if overlap - expected >= LINK_MARGIN:
                union(idx_i, idx_j)
                links += 1

    groups: dict = {}
    for idx, _, _ in blocks:
        groups.setdefault(find(idx), []).append(idx)
    clusters = sorted((sorted(g) for g in groups.values() if len(g) > 1), key=len, reverse=True)
    return {
        "total_blocks": total,
        "linkable_blocks": sum(len(g) for g in clusters),
        "links_found": links,
        "clusters": clusters,
    }


def run_on_views(views) -> dict:
    """Pattern mining against defence-supplied node views (see views.py).

    Each node mines only the positions its view exposes. Fewer visible bits means fewer
    shared bits per common field, so fewer pairs clear the link margin.
    """
    m, filters = _chain_filters()
    views = check_views(views, m)

    def measure(label, nodes, mask):
        found = mine(filters, m, mask)
        total, linkable = found["total_blocks"], found["linkable_blocks"]
        return row(label, nodes, mask, m, linkable / total if total else 0.0,
                   f"{linkable} of {total} blocks linkable in {len(found['clusters'])} group(s), "
                   f"{found['links_found']} links",
                   linkable_blocks=linkable, links_found=found["links_found"],
                   clusters=len(found["clusters"]))

    baseline = measure("Complete Bloom filter (no defence)", [], full_mask(m))
    rows = [measure(v["node"], [v["node"]], v["mask"]) for v in views]
    worst = max(rows, key=lambda r: r["success_rate"])
    return {
        "attack": "pattern_mining",
        "metric": "Blocks linkable by shared bits",
        "baseline": baseline,
        "rows": rows,
        "conclusion": (
            f"With complete filters {baseline['linkable_blocks']} blocks are linkable without the key. "
            f"Under this partitioning the strongest single node ({worst['label']}, "
            f"{worst['visibility_percentage']}% of bits) links {worst['linkable_blocks']}."
        ),
    }


def run_inference_pattern_mining() -> dict:
    m, filters = _chain_filters()
    found = mine(filters, m)
    total, linkable, links = found["total_blocks"], found["linkable_blocks"], found["links_found"]
    clusters = found["clusters"]

    rows = [{
        "group": n + 1,
        "size": len(g),
        "blocks": g[:8],
        "more": max(0, len(g) - 8),
    } for n, g in enumerate(clusters[:6])]

    return {
        "check": "inference",
        "attack": "pattern_mining",
        "system": "bloom",
        "total_blocks": total,
        "linkable_blocks": linkable,
        "links_found": links,
        "clusters": len(clusters),
        "largest_cluster": len(clusters[0]) if clusters else 0,
        "rows": rows,
        "scenario": "An attacker with only the public chain mines the Bloom filters for records that share a value.",
        "conclusion": (
            f"The keyed Bloom filters hide the values, but records that share a field set the same "
            f"bits, so {linkable} of {total} blocks fall into {len(clusters)} linkable group(s) - all "
            f"found without the key. Per-record salting (so the same value maps to different bits in "
            f"different records) removes this similarity leak."
        ),
    }
