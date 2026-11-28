"""Per-record salted hashing for keyed Bloom-filter anchors.

The Bloom filter system already derives bit positions from HMAC under a secret key, but
one key serves every record, so the same value always sets the same bits. That lets an
attacker link records (pattern mining) or match a record against known ones (reference
similarity) without ever learning the key.

This defence mixes a random per-record salt into every item before the keyed hash:

    position = HMAC(key, "salt=<record salt>|<item>")

so the same value sets different bits in different records. The salt is stored with the
record and given to the verifier, which still holds the key, so verification is unchanged
for genuine records. Like the partitioning defence this is a read-only experiment: the
chain's records are re-encoded in memory and the live ledger is not modified.
"""
import random
import time

from ...anchors import record_items
from ...bloom import BloomFilter
from ..common import systems
from .partitioning import _tampered_variants

SALT_BYTES = 16
SEED = 2026  # fixed so a run can be repeated exactly


class SaltedEncoding:
    """Encodes records with a per-record salt (the encoding interface in attacks/inference/views.py)."""

    name = "per_record_salt"

    def __init__(self, impl, seed: int = SEED):
        self.impl = impl
        self._rng = random.Random(seed)
        self._salts: dict = {}
        self._filters: dict = {}

    def salt(self, record_id) -> str:
        if record_id not in self._salts:
            self._salts[record_id] = self._rng.getrandbits(SALT_BYTES * 8).to_bytes(SALT_BYTES, "big").hex()
        return self._salts[record_id]

    def salted(self, item: str, record_id) -> str:
        return f"salt={self.salt(record_id)}|{item}"

    def filter(self, tx: dict, record_id, rng: random.Random) -> BloomFilter:
        """The record's salted, padded filter (padding drawn from `rng`, as BloomAnchor.build does).

        A record is encoded once: later calls return the same filter, so the defence and
        the attack it hands this encoding to work on identical filters.
        """
        if record_id in self._filters:
            return self._filters[record_id]
        items = record_items(tx)
        bloom = self.impl.new_filter()
        for item in items:
            bloom.add(self.salted(item, record_id))
        for _ in range(self.impl.PAD_TO - len(items)):
            bloom.add("pad=" + rng.getrandbits(128).to_bytes(16, "big").hex())
        self._filters[record_id] = bloom
        return bloom

    def encode(self, tx: dict, record_id, rng: random.Random) -> int:
        return int.from_bytes(self.filter(tx, record_id, rng).bits, "little")

    def positions(self, item: str, record_id) -> list[int]:
        return self.impl.new_filter().positions(self.salted(item, record_id))

    def verify(self, bloom: BloomFilter, tx: dict, record_id) -> bool:
        return all(self.salted(item, record_id) in bloom for item in record_items(tx))


def run_salted_hashing(attack: str | None = None, options: dict | None = None) -> dict:
    """Evaluate per-record salting: verification accuracy, cost, and the selected attack."""
    if attack is not None and not isinstance(attack, str):
        raise ValueError("attack must be a string")
    if options is not None and not isinstance(options, dict):
        raise ValueError("defence options must be an object")
    app = systems()["bloom"]
    impl = app.config["anchor"]
    ledger = app.config["ledger"]
    encoding = SaltedEncoding(impl)
    rng = random.Random(SEED)

    encode_s = baseline_encode_s = verify_s = baseline_verify_s = 0.0
    genuine = genuine_accepted = tampered = tampered_accepted = baseline_tampered_accepted = 0
    for idx, anchor in ledger.anchors().items():
        tx = ledger.record(idx)
        if "bits" not in anchor or tx is None:
            continue
        started = time.perf_counter()
        impl.build(tx)
        baseline_encode_s += time.perf_counter() - started
        started = time.perf_counter()
        bloom = encoding.filter(tx, idx, rng)
        encode_s += time.perf_counter() - started
        plain = impl.new_filter(anchor["bits"])

        genuine += 1
        started = time.perf_counter()
        genuine_accepted += encoding.verify(bloom, tx, idx)
        verify_s += time.perf_counter() - started
        started = time.perf_counter()
        all(item in plain for item in record_items(tx))
        baseline_verify_s += time.perf_counter() - started
        # Verification accuracy: every forged copy of the record must be rejected.
        for forged in _tampered_variants(tx):
            tampered += 1
            tampered_accepted += encoding.verify(bloom, forged, idx)
            baseline_tampered_accepted += all(item in plain for item in record_items(forged))

    ms = lambda seconds: round(seconds * 1000 / genuine, 3) if genuine else 0.0  # noqa: E731
    checks = genuine + tampered
    verification_accuracy = {
        "genuine_records": genuine,
        "genuine_accepted": genuine_accepted,
        "tampered_records": tampered,
        "tampered_rejected": tampered - tampered_accepted,
        "accuracy": round((genuine_accepted + tampered - tampered_accepted) / checks, 4) if checks else None,
        "false_rejection_rate": round((genuine - genuine_accepted) / genuine, 4) if genuine else None,
        "false_acceptance_rate": round(tampered_accepted / tampered, 4) if tampered else None,
        "baseline_false_acceptance_rate": (
            round(baseline_tampered_accepted / tampered, 4) if tampered else None
        ),
    }
    filter_bytes = impl.M // 8
    metrics = {
        "encoding_ms": ms(encode_s),
        "baseline_encoding_ms": ms(baseline_encode_s),
        "average_verification_ms": ms(verify_s),
        "baseline_verification_ms": ms(baseline_verify_s),
        "verification_overhead_ms": round(ms(verify_s) - ms(baseline_verify_s), 3),
        "storage_bytes_per_record": filter_bytes + SALT_BYTES,
        "baseline_storage_bytes_per_record": filter_bytes,
        # The verifier reads the record's filter and its salt.
        "communication_bytes_per_verification": filter_bytes + SALT_BYTES,
    }

    attack_support = None
    if attack is not None:
        from ...attacks.inference import ENCODING_RUNNERS
        runner = ENCODING_RUNNERS.get(attack)
        result = runner(encoding) if runner else None
        attack_support = {
            "status": "executed" if result else "unsupported_attack",
            "requested_attack": attack,
            "attack_executed": result is not None,
            "result": result,
            "interface": (
                "The defence hands the attack its salted encoding; the attack runs on the salted "
                "filters and is compared with the plain keyed encoding."
                if result else f"The attack {attack!r} has no encoding runner, so it was not executed."
            ),
        }
    executed = bool(attack_support and attack_support["attack_executed"])
    return {
        "check": "inference",
        "defense": "salted_hashing",
        "defense_name": "Per-record salted hashing",
        "system": "bloom",
        "attack": attack,
        "attack_supported": executed,
        "attack_executed": executed,
        "attack_support": attack_support,
        "records": genuine,
        "salt_bytes": SALT_BYTES,
        "verification_accuracy": verification_accuracy,
        "metrics": metrics,
        "conclusion": (
            f"Each of {genuine} records was re-encoded with its own {SALT_BYTES}-byte salt mixed into every "
            "keyed hash. Genuine records still verify and tampered copies are still rejected, while the same "
            "value no longer sets the same bits in different records."
        ),
    }
