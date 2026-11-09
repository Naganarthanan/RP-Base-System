"""Attack pattern mining: link records by Bloom-filter similarity, without the key.

A keyed Bloom filter hides a field's value, but the same value always maps to the same
bits. So two records that share a field (e.g. the same programme) have more bits in
common than chance predicts. Mining the chain for these elevated overlaps groups
records that share a value - a structural inference leak that needs no key at all.

The attacker only reads the stored filters (public on the chain) and counts shared bits;
nothing here uses the secret key or recovers an actual value.
"""
from ..common import systems

# Extra shared bits, beyond what chance predicts, that flag two records as linked.
# One shared keyed field contributes about k (=10) set bits, so this margin (~2 fields'
# worth) only links records that share two or more low-entropy values - a confident link
# that random overlap almost never reaches.
LINK_MARGIN = 18


def _popcount(n: int) -> int:
    return bin(n).count("1")


def run_inference_pattern_mining() -> dict:
    app = systems()["bloom"]
    impl = app.config["anchor"]
    anchors = app.config["ledger"].anchors()
    m = impl.M

    blocks = []
    for idx, a in anchors.items():
        if "bits" not in a:
            continue
        value = int.from_bytes(impl.new_filter(a["bits"]).bits, "big")
        blocks.append((idx, value, _popcount(value)))
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
    linkable = sum(len(g) for g in clusters)

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
