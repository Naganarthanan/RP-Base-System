"""Security check: side-by-side demonstrations on the two systems' own demo data.

Each check measures a property of the anchor design. Nothing here recovers a real
person's details: the inference check uses a small list of candidate values for a
low-entropy field (programme) to measure whether a guess can be *confirmed*, which is
the property that matters, without reconstructing identifiers such as NIC or date of
birth.

* Manipulation - an attacker who can write to a node rewrites a record and tries to
  produce an anchor that the system's own verify() will accept, using only keyless
  computation (everything a holder of the chain can do without the secret key).
* Inference - an attacker holding a copy of the chain tries to confirm guessed field
  values against the stored anchors, again without the key.
"""
from flask import current_app

from .anchors import BloomAnchor, HashAnchor, canonical, field_item, sha256

SAMPLE_TX = {
    "type": "certificate.issue",
    "data": {
        "id": "CERT-DEMO-0001", "student_id": "UNI20260001", "title": "Dean's List Award",
        "programme": "BSc (Hons) Information Technology", "issued_on": "2026-08-20", "code": "DEMO-CODE-2026",
    },
    "actor": "seed", "at": "2026-01-01T00:00:00+00:00",
}

# One real programme plus decoys. Low-entropy, non-identifying: the point is only whether
# a guess can be confirmed from the chain, not who holds it.
PROGRAMME_GUESSES = [
    "BSc (Hons) Information Technology",
    "BSc (Hons) Software Engineering",
    "BSc (Hons) Data Science",
    "BBA (Hons) Business Management",
    "LLB (Hons) Law",
    "BEng (Hons) Civil Engineering",
]


def _systems() -> dict:
    return current_app.config["SYSTEMS"]


def run_manipulation() -> dict:
    """Forge a record and test whether a keyless attacker can make a matching anchor."""
    forged = {**SAMPLE_TX, "data": {**SAMPLE_TX["data"], "title": "First Class (forged)"}}
    # What an attacker without the secret key can compute: plain SHA-256 anchors only.
    keyless_hash_anchor = HashAnchor().build(forged)
    keyless_bloom_attempt = BloomAnchor(b"\x00" * 32).build(forged)  # wrong key -> wrong bits

    rows = []
    for name, app in _systems().items():
        impl = app.config["anchor"]
        label = app.config["SYSTEM"]
        if label == "conventional":
            # Unkeyed hash: the attacker recomputes the same anchor the system would.
            forged_anchor = keyless_hash_anchor
        else:
            forged_anchor = keyless_bloom_attempt
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


def run_inference() -> dict:
    """Measure whether a chain holder can confirm a guessed programme without the key."""
    rows = []
    for name, app in _systems().items():
        label = app.config["SYSTEM"]
        anchors = app.config["ledger"].anchors()
        confirmed = []
        if label == "conventional":
            # Every programme field hash the chain exposes, unsalted.
            stored = {a["fields"].get("programme") for a in anchors.values() if "fields" in a}
            for guess in PROGRAMME_GUESSES:
                if sha256(canonical(guess)) in stored:
                    confirmed.append(guess)
            detail = (
                "Per-field hashes are unsalted SHA-256. Hashing each guess and matching it "
                "against the chain confirmed which programmes are present - an offline "
                "dictionary attack that needs no key."
            )
        else:
            # Attacker without the key: guess the Bloom positions with a wrong key.
            impl = app.config["anchor"]
            wrong = BloomAnchor(b"\x00" * 32)
            for guess in PROGRAMME_GUESSES:
                item = field_item("student.upsert", "programme", guess)
                positions = wrong.new_filter().positions(item)
                if any(impl.new_filter(a["bits"]).has_bits(positions)
                       for a in anchors.values() if "bits" in a):
                    confirmed.append(guess)
            detail = (
                "Bloom bit positions come from HMAC under the secret key. Without it the guessed "
                "positions are wrong, so no guess could be confirmed against the chain."
            )
        rows.append({
            "system": label,
            "guesses": len(PROGRAMME_GUESSES),
            "confirmed": len(confirmed),
            "verdict": "leaks" if confirmed else "resists",
            "detail": detail,
        })
    rows.sort(key=lambda r: r["system"] != "conventional")
    return {
        "check": "inference",
        "scenario": "Someone holding a copy of the chain tries to confirm guessed field values.",
        "rows": rows,
        "conclusion": (
            "The conventional system's unsalted field hashes let a guess be confirmed offline. "
            "The keyed Bloom filters reveal nothing without the key, so the same guessing attack "
            "confirms nothing."
        ),
    }
