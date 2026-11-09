"""Manipulation attack: forge a record and test whether its anchor is accepted.

An attacker without the secret key can only compute plain SHA-256 anchors. We build a
forged record, make the best anchor such an attacker could, and check each system's
verify(). The conventional (unkeyed hash) system accepts it; the keyed Bloom system
does not.
"""
from ..common import BloomAnchor, HashAnchor, systems

SAMPLE_TX = {
    "type": "certificate.issue",
    "data": {
        "id": "CERT-DEMO-0001", "student_id": "UNI20260001", "title": "Dean's List Award",
        "programme": "BSc (Hons) Information Technology", "issued_on": "2026-08-20", "code": "DEMO-CODE-2026",
    },
    "actor": "seed", "at": "2026-01-01T00:00:00+00:00",
}


def run_manipulation() -> dict:
    """Forge a record and test whether a keyless attacker can make a matching anchor."""
    forged = {**SAMPLE_TX, "data": {**SAMPLE_TX["data"], "title": "First Class (forged)"}}
    # What an attacker without the secret key can compute: plain SHA-256 anchors only.
    keyless_hash_anchor = HashAnchor().build(forged)
    keyless_bloom_attempt = BloomAnchor(b"\x00" * 32).build(forged)  # wrong key -> wrong bits

    rows = []
    for name, app in systems().items():
        impl = app.config["anchor"]
        label = app.config["SYSTEM"]
        forged_anchor = keyless_hash_anchor if label == "conventional" else keyless_bloom_attempt
        accepted = impl.verify(forged_anchor, forged)
        rows.append({
            "system": label,
            "forgery_accepted": accepted,
            "verdict": "vulnerable" if accepted else "resisted",
            "detail": (
                "Anchors are unkeyed SHA-256, so anyone holding the chain can recompute a "
                "matching hash for a forged record. The forged record passed verification."
                if accepted else
                "Anchors are keyed (HMAC into a Bloom filter). Without the secret key the "
                "attacker cannot build a matching anchor, so the forged record was rejected."
            ),
        })
    rows.sort(key=lambda r: r["system"] != "conventional")
    return {
        "check": "manipulation",
        "scenario": "A compromised organisation rewrites one record and forges its on-chain anchor.",
        "rows": rows,
        "conclusion": (
            "Both systems detect a node that edits its own copy, because the SHA-256 block "
            "links break consensus. They differ on a forged anchor: unkeyed hashes can be "
            "recomputed by anyone, while the keyed Bloom anchors cannot be forged without the key."
        ),
    }
