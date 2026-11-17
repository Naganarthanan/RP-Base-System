"""Inter-block (vertical) partitioning: core engine of the Defence Against Manipulation.

Each block is stored only on the node(s) chosen by a partitioning strategy. Verification
cross-references blocks that live on DIFFERENT nodes: block B(i) carries the hash of B(i-1),
and the two copies are fetched from different organisations.

Index convention: the ledger numbers blocks 0..N-1. The proposal uses p = ((i-1) mod n) + 1
with i = 1..N, which with 0-based idx is simply idx mod n (0-based node index).

Nothing here touches the live database. It works on a copy of the chain.
"""
from __future__ import annotations

import hashlib
import json
import random
import time
from collections import Counter
from itertools import combinations

from ...ledger import GENESIS_PREV, NODES, block_digest

BLOCK_FIELDS = ("idx", "ts", "prev_hash", "anchor", "hash")


def default_node_names(n: int) -> list[str]:
    return [NODES[i] if i < len(NODES) else f"Node-{i + 1}" for i in range(n)]


def _digest(b: dict) -> str:
    return block_digest(b["idx"], b["ts"], b["prev_hash"], b["anchor"])


# ============================================================================
# 1. Partitioning strategies (block -> node assignment)
# ============================================================================
class Strategy:
    key = ""
    label = ""

    def holders(self, idx: int, n: int) -> tuple[int, ...]:
        raise NotImplementedError


class SingleSequence(Strategy):
    """p = ((i - 1) mod n) + 1 : blocks cycle through the nodes in a fixed order."""
    key, label = "single_sequence", "Single-sequence"

    def holders(self, idx, n):
        return (idx % n,)


class SingleOdd(Strategy):
    """Odd-numbered node order first (1, 3, 5 ... then 2, 4 ...), cycled over the blocks."""
    key, label = "single_odd", "Single-odd"

    def holders(self, idx, n):
        order = list(range(0, n, 2)) + list(range(1, n, 2))
        return (order[idx % n],)


class KSequence(Strategy):
    """Each block is replicated on k consecutive nodes."""
    key = "k_sequence"

    def __init__(self, k: int = 2):
        self.k = k
        self.label = f"k-sequence (k={k})"

    def holders(self, idx, n):
        return tuple((idx + j) % n for j in range(min(self.k, n)))


class FullReplication(Strategy):
    """Baseline: every node stores every block (the conventional system)."""
    key, label = "full_replication", "Full replication"

    def holders(self, idx, n):
        return tuple(range(n))


STRATEGIES = ("single_sequence", "single_odd", "k_sequence")


def make_strategy(key: str, k: int = 2) -> Strategy:
    if key == "single_sequence":
        return SingleSequence()
    if key == "single_odd":
        return SingleOdd()
    if key == "k_sequence":
        return KSequence(k)
    if key == "full_replication":
        return FullReplication()
    raise ValueError(f"unknown partitioning strategy {key!r}")


# ============================================================================
# 2. Partitioned chain + hash-chain cross-reference verification
# ============================================================================
class PartitionedChain:
    """Blocks spread over n nodes by a strategy.

    head_pin: optional refinement. Every node also keeps the hash of the newest block,
    closing the gap that the newest block has no successor to cross-reference it.
    """

    def __init__(self, blocks: list[dict], n: int, strategy: Strategy, head_pin: bool = False,
                 node_names: list[str] | None = None):
        if n < 2:
            raise ValueError("vertical partitioning needs at least 2 nodes")
        if not blocks:
            raise ValueError("the chain is empty")
        for position, b in enumerate(blocks):
            if b["idx"] != position:
                raise ValueError("block indexes must run 0..N-1 without gaps")
        self.n, self.strategy, self.head_pin = n, strategy, head_pin
        self.names = node_names or default_node_names(n)
        self.reference = [{f: b[f] for f in BLOCK_FIELDS} for b in blocks]
        self.stores: list[dict[int, dict]] = [{} for _ in range(n)]
        for b in self.reference:
            for node in strategy.holders(b["idx"], n):
                self.stores[node][b["idx"]] = dict(b)
        head = self.reference[-1]["hash"]
        self.pins: list[str | None] = [head if head_pin else None for _ in range(n)]

    @property
    def height(self) -> int:
        return len(self.reference)

    def holders(self, idx: int) -> tuple[int, ...]:
        return self.strategy.holders(idx, self.n)

    def clone(self) -> "PartitionedChain":
        other = object.__new__(PartitionedChain)
        other.n, other.strategy, other.head_pin, other.names = self.n, self.strategy, self.head_pin, self.names
        other.reference = self.reference
        other.stores = [{i: dict(b) for i, b in s.items()} for s in self.stores]
        other.pins = list(self.pins)
        return other

    def storage_profile(self) -> dict:
        counts = [len(s) for s in self.stores]
        avg = sum(counts) / self.n
        return {"blocks_per_node": counts, "average": avg, "percent_of_full": round(100 * avg / self.height, 1)}

    def verify(self) -> dict:
        """Hash-chain cross-reference check (Algorithm 1, second loop).

        For every block i >= 1: take block i-1 from the node(s) holding it, recompute its
        hash, compare with prevHash stored in block i (held by a different node).
        Also checks each copy against its own hash, replica agreement, and the head pin.
        """
        start = time.perf_counter()
        N, names = self.height, self.names
        findings: list[dict] = []

        def add(kind: str, block: int, nodes: list[int], detail: str):
            findings.append({"type": kind, "block": block, "nodes": [names[x] for x in nodes], "detail": detail})

        copies: list[list[tuple[int, dict]]] = []
        reads = 0
        for i in range(N):
            present = []
            for nd in self.holders(i):
                b = self.stores[nd].get(i)
                if b is None:
                    add("missing_block", i, [nd], f"Block {i} is missing from {names[nd]}.")
                else:
                    present.append((nd, b))
            reads += len(present)
            for nd, b in present[1:]:
                if b != present[0][1]:
                    add("replica_mismatch", i, [present[0][0], nd],
                        f"Copies of block {i} on {names[present[0][0]]} and {names[nd]} differ.")
            copies.append(present)

        for i, present in enumerate(copies):
            for nd, b in present:
                if b["idx"] != i or _digest(b) != b["hash"]:
                    add("self_hash_mismatch", i, [nd],
                        f"Block {i} on {names[nd]} does not match its own hash (edited in place).")
        if copies[0] and copies[0][0][1]["prev_hash"] != GENESIS_PREV:
            add("genesis_mismatch", 0, [copies[0][0][0]], "The genesis block does not start from the zero hash.")

        for i in range(1, N):
            for pn, prev in copies[i - 1]:
                recomputed = _digest(prev)
                for cn, cur in copies[i]:
                    if cur["prev_hash"] != recomputed:
                        add("link_mismatch", i, [pn, cn],
                            f"Block {i} on {names[cn]} points to a different hash than the one recomputed "
                            f"from block {i - 1} on {names[pn]}.")

        if self.head_pin and copies[-1]:
            head = _digest(copies[-1][0][1])
            for nd in range(self.n):
                if self.pins[nd] != head:
                    add("head_pin_mismatch", N - 1, [nd],
                        f"The newest block no longer matches the head hash pinned on {names[nd]}.")

        findings.sort(key=lambda f: f["block"])
        return {
            "status": "Manipulation Detected" if findings else "Blockchain Valid",
            "first": findings[0] if findings else None,
            "findings": findings[:12],
            "finding_count": len(findings),
            "checked_blocks": N,
            "block_reads": reads,
            "latency_ms": round((time.perf_counter() - start) * 1000, 3),
        }


# ============================================================================
# 3. Colluding adversary (can WRITE only on the nodes it controls)
# ============================================================================
def apply_collusion(chain: PartitionedChain, colluders: set[int], target: int, forged_anchor: str) -> dict:
    """Replace the anchor of block `target` and re-link every later block.

    Worst case for the defence: colluders can READ the whole chain but WRITE only copies on
    nodes they control. Changing block t changes its hash, so t+1 must carry the new hash,
    and so on up to the newest block. The attack is complete only if the coalition controls
    every copy of every block from t to the head (and, with head_pin, all nodes).
    """
    N = chain.height
    ref = chain.reference
    prev = ref[target - 1]["hash"] if target > 0 else GENESIS_PREV
    forged: dict[int, tuple[str, str, str]] = {}
    for j in range(target, N):
        anchor = forged_anchor if j == target else ref[j]["anchor"]
        digest = block_digest(j, ref[j]["ts"], prev, anchor)
        forged[j] = (prev, anchor, digest)
        prev = digest

    rewritten, blocked, complete = 0, [], True
    for j, (p, a, h) in forged.items():
        for nd in chain.holders(j):
            if nd in colluders:
                blk = chain.stores[nd][j]
                blk["prev_hash"], blk["anchor"], blk["hash"] = p, a, h
                rewritten += 1
        if any(nd not in colluders for nd in chain.holders(j)):
            complete = False
            blocked.append(j)
    if chain.head_pin:
        for nd in colluders:
            chain.pins[nd] = prev
        if len(colluders) < chain.n:
            complete = False
    return {"complete": complete, "blocks_rewritten": rewritten, "blocks_needed": N - target,
            "blocked_blocks": blocked[:8]}


def consensus_accepts(chain: PartitionedChain, target: int, forged_anchor: str) -> bool:
    """Baseline decision rule: majority of valid full copies wins (as in Ledger.status)."""
    N, heads, copies = chain.height, Counter(), {}
    for nd in range(chain.n):
        blocks = [chain.stores[nd][i] for i in range(N)]
        prev, ok = GENESIS_PREV, True
        for pos, b in enumerate(blocks):
            if b["idx"] != pos or b["prev_hash"] != prev or b["hash"] != _digest(b):
                ok = False
                break
            prev = b["hash"]
        if ok:
            heads[blocks[-1]["hash"]] += 1
            copies[blocks[-1]["hash"]] = blocks
    if not heads:
        return False
    head, votes = heads.most_common(1)[0]
    return votes > chain.n // 2 and copies[head][target]["anchor"] == forged_anchor


def forged_text(target: int) -> str:
    """Stand-in forged anchor for evaluation runs (anything different from the original)."""
    return '{"fields":{},"tx_hash":"' + hashlib.sha256(f"forged-{target}".encode()).hexdigest() + '"}'


# ============================================================================
# 4. Exact analysis over every coalition and target block
# ============================================================================
def _masks(strategy: Strategy, n: int, N: int) -> list[int]:
    return [sum(1 << nd for nd in strategy.holders(j, n)) for j in range(N)]


def suffix_masks(strategy: Strategy, n: int, N: int) -> list[int]:
    """suffix[t] = nodes that hold at least one copy of blocks t..N-1 (bitmask)."""
    hm, suffix = _masks(strategy, n, N), [0] * (N + 1)
    for t in range(N - 1, -1, -1):
        suffix[t] = suffix[t + 1] | hm[t]
    return suffix


def attack_succeeds(suffix: list[int], n: int, head_pin: bool, coalition: int, target: int) -> bool:
    if suffix[target] & ~coalition:
        return False
    return not head_pin or coalition == (1 << n) - 1


def analyse(N: int, n: int, strategy: Strategy, head_pin: bool, model_k: int = 2) -> list[dict]:
    """Attack-success rate per coalition size c, over every coalition and every target block."""
    suffix = suffix_masks(strategy, n, N)
    rows = []
    for c in range(1, n + 1):
        coalitions = [sum(1 << i for i in combo) for combo in combinations(range(n), c)]
        wins = worst = with_bypass = 0
        for cm in coalitions:
            exposed = sum(1 for t in range(N) if attack_succeeds(suffix, n, head_pin, cm, t))
            wins += exposed
            worst = max(worst, exposed)
            with_bypass += exposed > 0
        rows.append({
            "colluding": c,
            "asr": wins / (len(coalitions) * N),
            "worst_coalition_blocks": worst,
            "coalitions": len(coalitions),
            "coalitions_with_bypass": with_bypass,
            "model": (c / n) ** model_k,
        })
    return rows


def exposed_blocks(N: int, n: int, strategy: Strategy, head_pin: bool, coalition: set[int]) -> list[int]:
    suffix = suffix_masks(strategy, n, N)
    cm = sum(1 << i for i in coalition)
    return [t for t in range(N) if attack_succeeds(suffix, n, head_pin, cm, t)]


def smallest_coalition_for(N: int, n: int, strategy: Strategy, head_pin: bool, target: int, size: int):
    """A coalition of exactly `size` nodes that can forge `target`, or None."""
    suffix = suffix_masks(strategy, n, N)
    for combo in combinations(range(n), size):
        cm = sum(1 << i for i in combo)
        if attack_succeeds(suffix, n, head_pin, cm, target):
            return set(combo)
    return None


# ============================================================================
# 5. Physical validation (real rewrites + real verification)
# ============================================================================
def validate_physically(template: PartitionedChain, max_cases: int = 300, seed: int = 7) -> dict:
    """Run real attacks on cloned chains and check the analytic model predicts each outcome."""
    n, N = template.n, template.height
    suffix = suffix_masks(template.strategy, n, N)
    cases = [(cm, t) for cm in range(1, 1 << n) for t in range(N)]
    if len(cases) > max_cases:
        cases = random.Random(seed).sample(cases, max_cases)
    bypassed = detected = no_access = agree = 0
    partial = partial_ok = 0  # coalitions smaller than n (total collusion cannot be detected by anyone)
    for cm, t in cases:
        coalition = {i for i in range(n) if cm >> i & 1}
        chain = template.clone()
        res = apply_collusion(chain, coalition, t, forged_text(t))
        verdict = chain.verify()["status"]
        if res["blocks_rewritten"] == 0 and not (chain.head_pin and coalition):
            outcome = "no_access"
        elif verdict == "Blockchain Valid":
            outcome = "bypassed"
        else:
            outcome = "detected"
        bypassed += outcome == "bypassed"
        detected += outcome == "detected"
        no_access += outcome == "no_access"
        agree += (outcome == "bypassed") == attack_succeeds(suffix, n, template.head_pin, cm, t)
        if cm != (1 << n) - 1:
            partial += 1
            partial_ok += outcome != "bypassed"
    total = len(cases)
    return {"cases": total, "bypassed": bypassed, "detected": detected, "no_write_access": no_access,
            "model_agreement": agree == total,
            "partial_cases": partial,
            "detection_rate": round(partial_ok / partial, 4) if partial else 1.0}


def baseline_asr(blocks: list[dict], n: int) -> list[dict]:
    """Conventional (fully replicated, majority consensus) ASR for c = 1..n."""
    chain0 = PartitionedChain(blocks, n, FullReplication())
    target = len(blocks) // 2
    rows = []
    for c in range(1, n + 1):
        chain = chain0.clone()
        forged = forged_text(target)
        apply_collusion(chain, set(range(c)), target, forged)
        rows.append({"colluding": c, "asr": 1.0 if consensus_accepts(chain, target, forged) else 0.0})
    return rows


def measure_latency(chain: PartitionedChain, runs: int = 20) -> float:
    """Average time of one full verification of an untouched chain, in ms."""
    times = [chain.verify()["latency_ms"] for _ in range(runs)]
    return round(sum(times) / len(times), 3)


# ============================================================================
# 6. Synthetic chain (fallback / unit tests)
# ============================================================================
def synthetic_chain(N: int, seed: int = 1) -> list[dict]:
    rng = random.Random(seed)
    blocks, prev = [], GENESIS_PREV
    for i in range(N):
        anchor = json.dumps({"tx_hash": hashlib.sha256(f"tx-{seed}-{i}-{rng.random()}".encode()).hexdigest(),
                             "fields": {}}, sort_keys=True, separators=(",", ":"))
        ts = f"2026-01-01T00:{i // 60 % 60:02d}:{i % 60:02d}+00:00"
        digest = block_digest(i, ts, prev, anchor)
        blocks.append({"idx": i, "ts": ts, "prev_hash": prev, "anchor": anchor, "hash": digest})
        prev = digest
    return blocks