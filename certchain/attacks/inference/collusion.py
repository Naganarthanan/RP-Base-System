"""Collusion inference attack on the Bloom filter chain.

The chain's inference protection rests on a secret Bloom key. We model that key as
shared among the organisations that run the nodes, reconstructable only when a majority
collude (a threshold scheme). A single organisation can confirm nothing; once enough
collude they recover the key and can test guesses against every block. The result is the
blast radius: how many blocks become exposed at each collusion size. Touches only the
Bloom filter system's inference attack, nothing else.
"""
from ..common import NODES, field_item, systems
from .data import PROGRAMME_GUESSES

# Fields a colluder's dictionary targets, by the transaction types that carry them.
COLLUSION_TARGETS = {
    "programme": ("student.upsert", "certificate.issue"),
}


def run_inference_collusion() -> dict:
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

    return {
        "check": "inference",
        "attack": "collusion",
        "system": "bloom",
        "nodes": nodes,
        "threshold": threshold,
        "total_blocks": total,
        "blocks_exposed": exposed,
        "matrix": matrix,
        "scenario": f"The {nodes} organisations that run the Bloom filter chain pool their key shares.",
        "conclusion": (
            f"One organisation on its own cannot test any guess, so no block is exposed. Once "
            f"{threshold} of {nodes} collude they reconstruct the Bloom key and can confirm values "
            f"in {exposed} of {total} blocks. A colluding majority defeats the keyed-Bloom inference "
            f"protection, so the key must be split so that no reachable group of organisations holds it."
        ),
    }
