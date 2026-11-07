"""Keyed Bloom filter.

Each of the k bit positions for an item comes from its own HMAC-SHA256 under a secret
key: position_i = HMAC(key, item || i) mod m. Using a separate keyed hash per position
keeps the positions independent (unlike double hashing, whose positions form a
correlated arithmetic progression). Without the key nobody can work out which bits an
item sets, so the filter cannot be searched with a dictionary.
"""
import base64
import hashlib
import hmac
import math


class BloomFilter:
    def __init__(self, m: int, k: int, key: bytes, bits: bytes | None = None):
        if m % 8:
            raise ValueError("m must be a multiple of 8")
        self.m, self.k, self.key = m, k, key
        self.bits = bytearray(bits) if bits is not None else bytearray(m // 8)
        if len(self.bits) != m // 8:
            raise ValueError("bit array has the wrong length")

    def positions(self, item: str) -> list[int]:
        raw = item.encode()
        out = []
        for i in range(self.k):
            digest = hmac.new(self.key, raw + b"\x00" + i.to_bytes(2, "big"), hashlib.sha256).digest()
            out.append(int.from_bytes(digest[:8], "big") % self.m)
        return out

    def add(self, item: str) -> None:
        for p in self.positions(item):
            self.bits[p >> 3] |= 1 << (p & 7)

    def has_bits(self, positions: list[int]) -> bool:
        return all(self.bits[p >> 3] & (1 << (p & 7)) for p in positions)

    def __contains__(self, item: str) -> bool:
        return self.has_bits(self.positions(item))

    def popcount(self) -> int:
        return sum(bin(b).count("1") for b in self.bits)

    def to_b64(self) -> str:
        return base64.b64encode(bytes(self.bits)).decode()

    @classmethod
    def from_b64(cls, m: int, k: int, key: bytes, text: str) -> "BloomFilter":
        return cls(m, k, key, base64.b64decode(text.encode()))

    def false_positive_rate(self, n: int) -> float:
        """Expected probability that an item never added still tests as present."""
        return (1 - math.exp(-self.k * n / self.m)) ** self.k
