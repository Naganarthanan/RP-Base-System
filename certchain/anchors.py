"""What each system writes on-chain for a transaction (its "anchor").

The full transaction is kept off-chain in the registry database. The chain stores
only an anchor that proves the transaction has not changed:

* Conventional system: plain SHA-256. One hash of the whole transaction, plus one
  hash per field. No secret is involved, so anyone holding a copy of the chain can
  recompute these hashes, both to test guesses and to forge new ones.
* Bloom filter system: every field and the whole transaction are added to a
  fixed-size Bloom filter whose bit positions come from a keyed hash (HMAC-SHA256).
  Each filter is padded to the same number of items, so its size and bit count do
  not reveal what kind of record it holds.
"""
import hashlib
import json
import os

from .bloom import BloomFilter

SYSTEMS = ("conventional", "bloom")
SYSTEM_LABELS = {"conventional": "Conventional system", "bloom": "Bloom filter system"}


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def field_item(tx_type: str, field: str, value) -> str:
    return f"{tx_type}.{field}={canonical(value)}"


def record_items(tx: dict) -> list[str]:
    """Bloom filter entries for one transaction: each field, then the whole record."""
    items = [field_item(tx["type"], k, v) for k, v in sorted(tx["data"].items())]
    items.append("tx=" + canonical(tx))
    return items


class HashAnchor:
    """Conventional system: unsalted SHA-256 of the record and of each field."""

    system = "conventional"

    def build(self, tx: dict) -> dict:
        return {
            "tx_hash": sha256(canonical(tx)),
            "fields": {k: sha256(canonical(v)) for k, v in sorted(tx["data"].items())},
        }

    def verify(self, anchor: dict, tx: dict) -> bool:
        return anchor.get("tx_hash") == sha256(canonical(tx))

    def matches_fields(self, anchor: dict, tx_type: str, fields: dict) -> bool:
        stored = anchor.get("fields", {})
        return all(stored.get(k) == sha256(canonical(v)) for k, v in fields.items())

    def summary(self, anchor: dict) -> str:
        return anchor["tx_hash"]


class BloomAnchor:
    """Bloom filter system: keyed hashing into a padded, fixed-size Bloom filter."""

    system = "bloom"
    M, K, PAD_TO = 4096, 10, 16  # bits per block, hash functions, items per filter

    def __init__(self, key: bytes):
        self.key = key

    def new_filter(self, bits: str | None = None) -> BloomFilter:
        if bits is None:
            return BloomFilter(self.M, self.K, self.key)
        return BloomFilter.from_b64(self.M, self.K, self.key, bits)

    def build(self, tx: dict) -> dict:
        items = record_items(tx)
        if len(items) > self.PAD_TO:
            raise ValueError("record has more fields than the Bloom filter is sized for")
        bloom = self.new_filter()
        for item in items:
            bloom.add(item)
        for _ in range(self.PAD_TO - len(items)):  # random padding hides the field count
            bloom.add("pad=" + os.urandom(16).hex())
        return {"m": self.M, "k": self.K, "bits": bloom.to_b64()}

    def _filter(self, anchor: dict) -> BloomFilter | None:
        try:
            bloom = self.new_filter(anchor["bits"])
        except (KeyError, TypeError, ValueError):
            return None
        # A filter with more bits set than PAD_TO items could produce has been stuffed
        # to make forged items look present (a saturation attack), so it is rejected.
        return bloom if bloom.popcount() <= self.K * self.PAD_TO else None

    def verify(self, anchor: dict, tx: dict) -> bool:
        bloom = self._filter(anchor)
        return bloom is not None and all(item in bloom for item in record_items(tx))

    def matches_fields(self, anchor: dict, tx_type: str, fields: dict) -> bool:
        bloom = self._filter(anchor)
        return bloom is not None and all(field_item(tx_type, k, v) in bloom for k, v in fields.items())

    def false_positive_rate(self) -> float:
        return self.new_filter().false_positive_rate(self.PAD_TO)

    def summary(self, anchor: dict) -> str:
        return anchor["bits"]


def make_anchor(system: str, bloom_key: bytes):
    if system == "conventional":
        return HashAnchor()
    if system == "bloom":
        return BloomAnchor(bloom_key)
    raise ValueError(f"unknown system {system!r}")
