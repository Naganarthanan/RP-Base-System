"""Baseline inference attack: can a chain holder confirm a guessed value without the key?

Runs the same dictionary guess on both systems. The conventional system's unsalted
field hashes can be recomputed and matched (leaks); the keyed Bloom filters cannot be
tested without the key (resists).
"""
from ..common import BloomAnchor, canonical, field_item, sha256, systems
from .data import PROGRAMME_GUESSES


def run_inference() -> dict:
    """Measure whether a chain holder can confirm a guessed programme without the key."""
    rows = []
    for name, app in systems().items():
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
                positions = wrong.new_filter().positions(field_item("student.upsert", "programme", guess))
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
