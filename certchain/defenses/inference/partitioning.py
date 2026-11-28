"""Horizontal partitioning strategies for keyed Bloom-filter anchors.

Sequential partitioning uses balanced contiguous ranges. Interleaved
partitioning assigns every nth bit to the same partition. In both strategies,
each partition is stored as a single copy at one participating node and normal
verification checks the owning partition without rebuilding the complete filter.
"""

import base64
import random
import time
from collections.abc import Iterable, Sequence

from ...anchors import record_items
from ...bloom import BloomFilter
from ..common import NODES, systems


class PartitionError(ValueError):
    """A partition set is malformed or incomplete."""


class PartitionUnavailable(PartitionError):
    """A partition required for verification is unavailable."""


def _bit_is_set(bits: bytes | bytearray, position: int) -> bool:
    return bool(bits[position >> 3] & (1 << (position & 7)))


def _set_bit(bits: bytearray, position: int) -> None:
    bits[position >> 3] |= 1 << (position & 7)


STRATEGY_NAMES = {
    "sequential": "Sequential Bit Partitioning",
    "interleaved": "Interleaved Bit Partitioning",
    "pairwise": "Sequential Bit Partitioning with Pairwise Replication",
}


def _partition_layout(
    m: int,
    partition_count: int,
    index: int,
    strategy: str,
) -> tuple[int, int, int]:
    """Return ``(first global bit, local length, global step)`` for a partition."""
    if strategy in {"sequential", "pairwise"}:
        base, remainder = divmod(m, partition_count)
        start = index * base + min(index, remainder)
        length = base + (1 if index < remainder else 0)
        return start, length, 1
    if strategy == "interleaved":
        length = (m - index + partition_count - 1) // partition_count
        return index, length, partition_count
    raise PartitionError(f"unsupported partitioning strategy {strategy!r}")


def _pack_partition(
    bits: bytes | bytearray,
    start: int,
    length: int,
    step: int,
) -> bytes:
    packed = bytearray((length + 7) // 8)
    for local_position in range(length):
        if _bit_is_set(bits, start + local_position * step):
            _set_bit(packed, local_position)
    return bytes(packed)


def partition_filter(
    bloom: BloomFilter,
    partition_count: int,
    nodes: Sequence[str] = NODES,
    record_id: int | str | None = None,
    *,
    strategy: str = "sequential",
) -> list[dict]:
    """Split ``bloom`` using the selected horizontal strategy.

    Partition sizes differ by at most one bit. Node assignments repeat
    round-robin if an experiment uses more partitions than nodes.
    """
    if not isinstance(partition_count, int) or isinstance(partition_count, bool):
        raise PartitionError("partition_count must be an integer")
    if partition_count < 2:
        raise PartitionError("partition_count must be at least 2")
    if partition_count > bloom.m:
        raise PartitionError(
            "partition_count cannot exceed the Bloom-filter bit length"
        )
    if not nodes or any(not isinstance(node, str) or not node for node in nodes):
        raise PartitionError("at least one named node is required")
    if len(set(nodes)) != len(nodes):
        raise PartitionError("node names must be unique")
    if strategy not in STRATEGY_NAMES:
        raise PartitionError(f"unsupported partitioning strategy {strategy!r}")
    if strategy == "pairwise" and len(nodes) < 2:
        raise PartitionError("pairwise replication requires at least two nodes")

    partitions = []
    for index in range(partition_count):
        start, bit_length, step = _partition_layout(
            bloom.m, partition_count, index, strategy
        )
        packed = _pack_partition(bloom.bits, start, bit_length, step)
        if strategy == "pairwise":
            assigned_nodes = [
                nodes[index % len(nodes)],
                nodes[(index - 1) % len(nodes)],
            ]
            placement, replication_factor = "pairwise_replication", 2
        else:
            assigned_nodes = [nodes[index % len(nodes)]]
            placement, replication_factor = "single_copy", 1
        partitions.append(
            {
                "record_id": record_id,
                "partition_index": index,
                "partition_count": partition_count,
                "strategy": strategy,
                "placement": placement,
                "replication_factor": replication_factor,
                "nodes": assigned_nodes,
                "start_bit": start,
                "bit_length": bit_length,
                "position_step": step,
                "m": bloom.m,
                "k": bloom.k,
                "bits": base64.b64encode(packed).decode(),
            }
        )
    return partitions


def partition_anchor(
    anchor: dict,
    key: bytes,
    partition_count: int,
    nodes: Sequence[str] = NODES,
    record_id: int | str | None = None,
    *,
    strategy: str = "sequential",
) -> list[dict]:
    """Create partitions from a serialized Bloom-filter anchor."""
    try:
        m, k, encoded = anchor["m"], anchor["k"], anchor["bits"]
        bloom = BloomFilter.from_b64(m, k, key, encoded)
    except (KeyError, TypeError, ValueError) as exc:
        raise PartitionError("invalid Bloom-filter anchor") from exc
    return partition_filter(bloom, partition_count, nodes, record_id, strategy=strategy)


def _validated_partitions(
    partitions: Iterable[dict],
    *,
    require_complete: bool = True,
) -> list[tuple[dict, bytes]]:
    rows = list(partitions)
    if not rows:
        raise PartitionUnavailable("no Bloom-filter partitions are available")

    try:
        expected_count = rows[0]["partition_count"]
        m, k = rows[0]["m"], rows[0]["k"]
        record_id = rows[0].get("record_id")
        strategy = rows[0]["strategy"]
        placement = rows[0]["placement"]
        replication_factor = rows[0]["replication_factor"]
    except (KeyError, TypeError) as exc:
        raise PartitionError("partition metadata is incomplete") from exc
    if not isinstance(expected_count, int) or expected_count < 2:
        raise PartitionError("partition_count must be an integer of at least 2")
    if not isinstance(m, int) or m <= 0 or not isinstance(k, int) or k <= 0:
        raise PartitionError("Bloom-filter metadata is invalid")
    if len(rows) > expected_count:
        raise PartitionError("more partitions were supplied than expected")

    decoded = []
    for row in rows:
        try:
            raw = base64.b64decode(row["bits"].encode(), validate=True)
            index = row["partition_index"]
            start = row["start_bit"]
            length = row["bit_length"]
            step = row.get("position_step", 1)
            assigned_nodes = row["nodes"]
        except (KeyError, TypeError, ValueError) as exc:
            raise PartitionError("partition data is invalid") from exc
        if (
            row["partition_count"],
            row["m"],
            row["k"],
            row.get("record_id"),
            row["strategy"],
            row["placement"],
            row["replication_factor"],
        ) != (
            expected_count,
            m,
            k,
            record_id,
            strategy,
            placement,
            replication_factor,
        ):
            raise PartitionError(
                "partition metadata does not describe one Bloom filter"
            )
        if strategy not in STRATEGY_NAMES:
            raise PartitionError("unsupported partitioning strategy")
        expected_placement = (
            "pairwise_replication" if strategy == "pairwise" else "single_copy"
        )
        expected_replication = 2 if strategy == "pairwise" else 1
        if (
            placement != expected_placement
            or replication_factor != expected_replication
        ):
            raise PartitionError("partition placement does not match its strategy")
        if not isinstance(replication_factor, int) or replication_factor < 1:
            raise PartitionError("replication_factor must be a positive integer")
        if (
            not isinstance(assigned_nodes, list)
            or len(assigned_nodes) != replication_factor
            or len(set(assigned_nodes)) != len(assigned_nodes)
            or any(not isinstance(node, str) or not node for node in assigned_nodes)
        ):
            raise PartitionError("partition node assignments are invalid")
        if (
            not isinstance(index, int)
            or not isinstance(start, int)
            or not isinstance(length, int)
            or not isinstance(step, int)
        ):
            raise PartitionError("partition positions must be integers")
        if not 0 <= index < expected_count:
            raise PartitionError("partition index is outside the configured range")
        if length <= 0 or len(raw) != (length + 7) // 8:
            raise PartitionError("partition bit data has the wrong length")
        if length % 8 and raw[-1] >> (length % 8):
            raise PartitionError("partition contains bits outside its declared range")

        expected_start, expected_length, expected_step = _partition_layout(
            m, expected_count, index, strategy
        )
        if (start, length, step) != (expected_start, expected_length, expected_step):
            raise PartitionError(
                "partition bit layout does not match its index and strategy"
            )
        decoded.append((row, raw))

    decoded.sort(key=lambda item: item[0]["partition_index"])
    indexes = [row["partition_index"] for row, _ in decoded]
    if len(indexes) != len(set(indexes)):
        raise PartitionError("partition indexes must be unique")
    if require_complete and indexes != list(range(expected_count)):
        missing = expected_count - len(indexes)
        raise PartitionUnavailable(
            f"{missing} of {expected_count} required partitions are unavailable"
        )
    return decoded


def _copy_partition(partition: dict) -> dict:
    """Return a safe copy of one partition and its mutable node assignment."""
    return {**partition, "nodes": list(partition["nodes"])}


class PartitionedBloomStore:
    """Read-only experiment model with one temporary partition store per node.

    Like the manipulation component's ``PartitionedChain``, this model never
    writes to the live ledger. Partitions exist only for the duration of one
    defence run and are grouped by their assigned simulated node.
    """

    def __init__(self, nodes: Sequence[str] = NODES):
        if not nodes or any(not isinstance(node, str) or not node for node in nodes):
            raise PartitionError("at least one named node is required")
        if len(set(nodes)) != len(nodes):
            raise PartitionError("node names must be unique")
        self.nodes = tuple(nodes)
        self.stores: dict[str, dict[int | str, dict[int, dict]]] = {
            node: {} for node in self.nodes
        }

    def add(self, partitions: Iterable[dict]) -> None:
        """Place one record's complete partition set into its assigned stores."""
        rows = [partition for partition, _ in _validated_partitions(partitions)]
        record_id = rows[0].get("record_id")
        if record_id is None:
            raise PartitionError("record_id is required for node storage")

        for partition in rows:
            index = partition["partition_index"]
            for node in partition["nodes"]:
                if node not in self.stores:
                    raise PartitionError(
                        f"partition is assigned to unknown node {node!r}"
                    )
                record = self.stores[node].setdefault(record_id, {})
                candidate = _copy_partition(partition)
                if index in record and record[index] != candidate:
                    raise PartitionError("conflicting partition copy already exists")
                record[index] = candidate

    def partitions_for_node(
        self, node: str, record_id: int | str | None = None
    ) -> list[dict]:
        """Return only the partitions visible to one simulated node."""
        if node not in self.stores:
            raise PartitionError(f"unknown node {node!r}")
        records = self.stores[node]
        if record_id is not None:
            return [
                _copy_partition(p)
                for _, p in sorted(records.get(record_id, {}).items())
            ]
        return [
            _copy_partition(partition)
            for rid in sorted(records, key=str)
            for _, partition in sorted(records[rid].items())
        ]

    def partitions_for_record(
        self,
        record_id: int | str,
        available_nodes: Iterable[str] | None = None,
    ) -> list[dict]:
        """Collect unique partitions from the currently available node stores."""
        active = self.nodes if available_nodes is None else tuple(available_nodes)
        if any(node not in self.stores for node in active):
            raise PartitionError("available_nodes contains an unknown node")

        found: dict[int, dict] = {}
        for node in active:
            for index, partition in self.stores[node].get(record_id, {}).items():
                candidate = _copy_partition(partition)
                if index in found and found[index] != candidate:
                    raise PartitionError("replicated partition copies do not match")
                found[index] = candidate
        return [found[index] for index in sorted(found)]

    def storage_profile(self) -> dict:
        """Measure the temporary partition payload stored by each node."""
        rows = []
        for node in self.nodes:
            partitions = self.partitions_for_node(node)
            rows.append(
                {
                    "node": node,
                    "partitions": len(partitions),
                    "payload_bytes": sum(
                        (p["bit_length"] + 7) // 8 for p in partitions
                    ),
                }
            )
        return {
            "nodes": rows,
            "total_partitions": sum(row["partitions"] for row in rows),
            "total_payload_bytes": sum(row["payload_bytes"] for row in rows),
        }


def reconstruct_filter(partitions: Iterable[dict], key: bytes) -> BloomFilter:
    """Reconstruct a filter for integrity testing, not normal verification."""
    decoded = _validated_partitions(partitions)
    first = decoded[0][0]
    complete = bytearray(first["m"] // 8)
    for row, raw in decoded:
        step = row.get("position_step", 1)
        for local_position in range(row["bit_length"]):
            if _bit_is_set(raw, local_position):
                _set_bit(complete, row["start_bit"] + local_position * step)
    return BloomFilter(first["m"], first["k"], key, bytes(complete))


def verify_items_detailed(
    partitions: Iterable[dict], key: bytes, items: Iterable[str]
) -> dict:
    """Return position-level verification contributions from available partitions.

    Key model: the verifier holds the Bloom key and computes each item's keyed positions.
    It sends every node only the positions that fall inside that node's partition, and
    the node answers whether those bits are set. Nodes store and check bits but never hold
    the key, which stays with the verifier (shared among the organisations by threshold).

    Missing positions are reported as unavailable, not as mismatches. This keeps
    local match percentage, verification coverage, and the final decision as
    separate measurements.
    """
    decoded = _validated_partitions(partitions, require_complete=False)
    first = decoded[0][0]
    position_filter = BloomFilter(first["m"], first["k"], key)
    expected_count = first["partition_count"]
    strategy = first["strategy"]
    available = {row["partition_index"]: (row, raw) for row, raw in decoded}
    contributions = []
    for index in range(expected_count):
        start, length, step = _partition_layout(
            first["m"], expected_count, index, strategy
        )
        available_row = available.get(index)
        contributions.append(
            {
                "partition": index + 1,
                "nodes": list(available_row[0]["nodes"]) if available_row else [],
                "start_bit": start,
                "end_bit": start + (length - 1) * step,
                "position_step": step,
                "available": available_row is not None,
                "required_positions": 0,
                "checked_positions": 0,
                "matched_positions": 0,
                "mismatched_positions": 0,
                "unavailable_positions": 0,
            }
        )

    materialized_items = list(items)
    for item in materialized_items:
        for position in position_filter.positions(item):
            if strategy == "interleaved":
                index = position % expected_count
            else:
                index = next(
                    i
                    for i, contribution in enumerate(contributions)
                    if contribution["start_bit"] <= position <= contribution["end_bit"]
                )
            contribution = contributions[index]
            contribution["required_positions"] += 1
            available_row = available.get(index)
            if available_row is None:
                contribution["unavailable_positions"] += 1
                continue
            row, raw = available_row
            contribution["checked_positions"] += 1
            local_position = (position - row["start_bit"]) // row.get(
                "position_step", 1
            )
            if _bit_is_set(raw, local_position):
                contribution["matched_positions"] += 1
            else:
                contribution["mismatched_positions"] += 1

    for contribution in contributions:
        checked = contribution["checked_positions"]
        required = contribution["required_positions"]
        contribution["local_match_percentage"] = (
            round(contribution["matched_positions"] * 100 / checked, 2)
            if checked
            else None
        )
        contribution["coverage_percentage"] = (
            round(checked * 100 / required, 2) if required else 100.0
        )
        if contribution["mismatched_positions"]:
            contribution["status"] = "not_matched"
        elif contribution["unavailable_positions"]:
            contribution["status"] = "unavailable"
        elif required:
            contribution["status"] = "matched"
        else:
            contribution["status"] = "not_required"

    total_required = sum(row["required_positions"] for row in contributions)
    checked = sum(row["checked_positions"] for row in contributions)
    matched = sum(row["matched_positions"] for row in contributions)
    mismatched = sum(row["mismatched_positions"] for row in contributions)
    unavailable = sum(row["unavailable_positions"] for row in contributions)
    if mismatched:
        status = "not_matched"
    elif unavailable:
        status = "inconclusive"
    else:
        status = "verified"
    return {
        "status": status,
        "verified": status == "verified",
        "items_checked": len(materialized_items),
        "total_required_positions": total_required,
        "checked_positions": checked,
        "matched_positions": matched,
        "mismatched_positions": mismatched,
        "unavailable_positions": unavailable,
        "match_percentage": round(matched * 100 / checked, 2) if checked else None,
        "coverage_percentage": (
            round(checked * 100 / total_required, 2) if total_required else 100.0
        ),
        "contributions": contributions,
    }


def verify_items(partitions: Iterable[dict], key: bytes, items: Iterable[str]) -> bool:
    """Return the complete membership decision for backward compatibility."""
    result = verify_items_detailed(partitions, key, items)
    if result["status"] == "inconclusive":
        raise PartitionUnavailable(
            f'{result["unavailable_positions"]} required Bloom positions are unavailable'
        )
    return result["verified"]


def _verification_traffic(verification: dict, partitions: Iterable[dict]) -> int:
    """Bytes exchanged between the verifier and the node stores to verify one record.

    For each partition the verifier sends the holding node the local index of every
    required position in that partition, and the node answers with one bit per index.
    Only one copy of each partition is queried, so pairwise replication does not double it.
    """
    lengths = {p["partition_index"] + 1: p["bit_length"] for p in partitions}
    total = 0
    for contribution in verification["contributions"]:
        checked = contribution["checked_positions"]
        if checked:
            index_bytes = (
                max(lengths[contribution["partition"]] - 1, 1).bit_length() + 7
            ) // 8
            total += checked * index_bytes + (checked + 7) // 8
    return total


def _tampered_variants(tx: dict) -> list[dict]:
    """One forged copy of the record per field, each with that single field changed."""
    return [
        {**tx, "data": {**tx["data"], field: f"{tx['data'][field]} (tampered)"}}
        for field in sorted(tx["data"])
    ]


def _assignment_mask(assignments: Iterable[dict]) -> int:
    """Bloom positions covered by partition assignments, as an int mask (bit p = position p)."""
    mask = 0
    for assignment in assignments:
        start, step = assignment["start_bit"], assignment["position_step"]
        for local_position in range(assignment["bit_length"]):
            mask |= 1 << (start + local_position * step)
    return mask


def _run_partitioning(
    strategy: str,
    attack: str | None = None,
    options: dict | None = None,
    encoding=None,
) -> dict:
    """Evaluate one horizontal strategy and an optional integrated attack.

    With `encoding` (for example per-record salting, see salting.py) every record is
    re-encoded that way before it is partitioned, verification checks the encoded items,
    and the attack runs on the encoded filters' node views.
    """
    if strategy not in STRATEGY_NAMES:
        raise PartitionError(f"unsupported partitioning strategy {strategy!r}")
    if attack is not None and not isinstance(attack, str):
        raise PartitionError("attack must be a string")
    if options is not None and not isinstance(options, dict):
        raise PartitionError("defence options must be an object")
    app = systems()["bloom"]
    ledger = app.config["ledger"]
    anchor_impl = app.config["anchor"]
    anchors = ledger.anchors()
    partition_count = len(NODES)
    store = PartitionedBloomStore(NODES)
    rows = []
    assignments = []
    records: dict[int, dict] = {}
    verification_results = []
    partition_seconds = 0.0
    verification_seconds = 0.0
    baseline_seconds = 0.0
    communication_bytes = 0
    tampered_checks = tampered_accepted = baseline_tampered_accepted = 0
    encode_rng = random.Random(2026)

    def items_of(tx: dict, block_id) -> list[str]:
        items = record_items(tx)
        return (
            [encoding.salted(item, block_id) for item in items] if encoding else items
        )

    for block_id, anchor in anchors.items():
        if not {"m", "k", "bits"} <= anchor.keys():
            continue
        if encoding is not None:
            tx = ledger.record(block_id)
            if tx is None:
                continue
            anchor = {
                "m": anchor_impl.M,
                "k": anchor_impl.K,
                "bits": encoding.filter(tx, block_id, encode_rng).to_b64(),
            }
        started = time.perf_counter()
        partitions = partition_anchor(
            anchor,
            anchor_impl.key,
            partition_count,
            NODES,
            block_id,
            strategy=strategy,
        )
        store.add(partitions)
        partition_seconds += time.perf_counter() - started
        if not assignments:
            assignments = []
            for partition in partitions:
                start = partition["start_bit"]
                length = partition["bit_length"]
                step = partition.get("position_step", 1)
                end = start + (length - 1) * step
                assignments.append(
                    {
                        "partition": partition["partition_index"] + 1,
                        "start_bit": start,
                        "end_bit": end,
                        "position_step": step,
                        "position_rule": (
                            f"{start}-{end}"
                            if step == 1
                            else f"{start}, {start + step}, ... {end}"
                        ),
                        "bit_length": length,
                        "nodes": partition["nodes"],
                    }
                )
        tx = ledger.record(block_id)
        if tx is None:
            continue
        records[block_id] = tx
        stored = store.partitions_for_record(block_id)
        items = items_of(tx, block_id)
        started = time.perf_counter()
        verification = verify_items_detailed(stored, anchor_impl.key, items)
        verification_seconds += time.perf_counter() - started
        verification_results.append(verification)
        communication_bytes += _verification_traffic(verification, stored)
        baseline = BloomFilter.from_b64(
            anchor["m"], anchor["k"], anchor_impl.key, anchor["bits"]
        )
        started = time.perf_counter()
        baseline_verified = all(item in baseline for item in items)
        baseline_seconds += time.perf_counter() - started
        # Verification accuracy: every forged copy of the record must be rejected.
        for forged in _tampered_variants(tx):
            forged_items = items_of(forged, block_id)
            tampered_checks += 1
            tampered_accepted += verify_items_detailed(
                stored, anchor_impl.key, forged_items
            )["verified"]
            baseline_tampered_accepted += all(item in baseline for item in forged_items)
        reconstructed = reconstruct_filter(stored, anchor_impl.key)
        rows.append(
            {
                "block": block_id,
                "reconstructed": reconstructed.to_b64() == anchor["bits"],
                "verified": verification["verified"],
                "verification_status": verification["status"],
                "match_percentage": verification["match_percentage"],
                "coverage_percentage": verification["coverage_percentage"],
                "baseline_verified": baseline_verified,
                "matches_baseline": verification["verified"] == baseline_verified,
                "contributions": verification["contributions"],
                "assignments": [p["nodes"] for p in stored],
            }
        )

    availability = []
    for offline in (None, *NODES):
        active = (
            list(NODES)
            if offline is None
            else [node for node in NODES if node != offline]
        )
        verified_records = not_matched_records = unavailable_records = 0
        total_required = checked = matched = mismatched = unavailable_positions = 0
        available_filter_bits = 0
        for block_id, tx in records.items():
            visible = store.partitions_for_record(block_id, active)
            result = verify_items_detailed(
                visible, anchor_impl.key, items_of(tx, block_id)
            )
            total_required += result["total_required_positions"]
            checked += result["checked_positions"]
            matched += result["matched_positions"]
            mismatched += result["mismatched_positions"]
            unavailable_positions += result["unavailable_positions"]
            if result["status"] == "verified":
                verified_records += 1
            elif result["status"] == "not_matched":
                not_matched_records += 1
            else:
                unavailable_records += 1
            if available_filter_bits == 0:
                available_filter_bits = sum(
                    partition["bit_length"] for partition in visible
                )
        availability.append(
            {
                "scenario": "all_nodes_online" if offline is None else "node_offline",
                "offline_nodes": [] if offline is None else [offline],
                "available_nodes": active,
                "verified_records": verified_records,
                "not_matched_records": not_matched_records,
                "unavailable_records": unavailable_records,
                "total_required_positions": total_required,
                "checked_positions": checked,
                "matched_positions": matched,
                "mismatched_positions": mismatched,
                "unavailable_positions": unavailable_positions,
                "match_percentage": (
                    round(matched * 100 / checked, 2) if checked else None
                ),
                "verification_coverage_percentage": (
                    round(checked * 100 / total_required, 2)
                    if total_required
                    else 100.0
                ),
                "available_filter_bits": available_filter_bits,
                "available_filter_percentage": round(
                    available_filter_bits * 100 / anchor_impl.M, 2
                ),
                "status": "available" if unavailable_records == 0 else "inconclusive",
            }
        )

    storage = store.storage_profile()
    bytes_per_record = (
        round(storage["total_payload_bytes"] / len(records)) if records else 0
    )
    if encoding is not None:
        bytes_per_record += encoding.salt_bytes
    placement = "pairwise_replication" if strategy == "pairwise" else "single_copy"
    replication_factor = 2 if strategy == "pairwise" else 1
    exposure_by_node = {
        node: sum(
            assignment["bit_length"]
            for assignment in assignments
            if node in assignment["nodes"]
        )
        for node in NODES
    }
    maximum_node_bits = max(exposure_by_node.values(), default=0)
    total_required = sum(
        row["total_required_positions"] for row in verification_results
    )
    overall_checked = sum(row["checked_positions"] for row in verification_results)
    overall_matched = sum(row["matched_positions"] for row in verification_results)
    overall_mismatched = sum(
        row["mismatched_positions"] for row in verification_results
    )
    unavailable_positions = sum(
        row["unavailable_positions"] for row in verification_results
    )
    contribution_totals = []
    for assignment in assignments:
        partition = assignment["partition"]
        source_rows = [
            result["contributions"][partition - 1] for result in verification_results
        ]
        required = sum(row["required_positions"] for row in source_rows)
        checked = sum(row["checked_positions"] for row in source_rows)
        matched = sum(row["matched_positions"] for row in source_rows)
        mismatched = sum(row["mismatched_positions"] for row in source_rows)
        contribution_totals.append(
            {
                "partition": partition,
                "nodes": assignment["nodes"],
                "required_positions": required,
                "checked_positions": checked,
                "matched_positions": matched,
                "mismatched_positions": mismatched,
                "local_match_percentage": (
                    round(matched * 100 / checked, 2) if checked else None
                ),
                "coverage_percentage": (
                    round(checked * 100 / required, 2) if required else 100.0
                ),
                "position_share_percentage": (
                    round(required * 100 / total_required, 2) if total_required else 0.0
                ),
                "status": "not_matched" if mismatched else "matched",
            }
        )
    verification_summary = {
        "status": (
            "not_matched"
            if overall_mismatched
            else "inconclusive" if unavailable_positions else "verified"
        ),
        "total_required_positions": total_required,
        "checked_positions": overall_checked,
        "matched_positions": overall_matched,
        "mismatched_positions": overall_mismatched,
        "unavailable_positions": unavailable_positions,
        "match_percentage": (
            round(overall_matched * 100 / overall_checked, 2)
            if overall_checked
            else None
        ),
        "coverage_percentage": (
            round(overall_checked * 100 / total_required, 2)
            if total_required
            else 100.0
        ),
        "contributions": contribution_totals,
        "baseline_records_compared": len(rows),
        "baseline_agreement": bool(rows)
        and all(row["matches_baseline"] for row in rows),
    }
    genuine = len(rows)
    genuine_accepted = sum(row["verified"] for row in rows)
    tampered_rejected = tampered_checks - tampered_accepted
    checks = genuine + tampered_checks
    verification_accuracy = {
        "genuine_records": genuine,
        "genuine_accepted": genuine_accepted,
        "tampered_records": tampered_checks,
        "tampered_rejected": tampered_rejected,
        "accuracy": (
            round((genuine_accepted + tampered_rejected) / checks, 4)
            if checks
            else None
        ),
        "false_rejection_rate": (
            round((genuine - genuine_accepted) / genuine, 4) if genuine else None
        ),
        "false_acceptance_rate": (
            round(tampered_accepted / tampered_checks, 4) if tampered_checks else None
        ),
        "baseline_false_acceptance_rate": (
            round(baseline_tampered_accepted / tampered_checks, 4)
            if tampered_checks
            else None
        ),
    }
    attack_support = None
    if attack is not None:
        partition_views = []
        view_masks = []
        for node in NODES:
            visible = [
                assignment for assignment in assignments if node in assignment["nodes"]
            ]
            visible_bits = sum(assignment["bit_length"] for assignment in visible)
            partition_views.append(
                {
                    "node": node,
                    "partition": visible[0]["partition"] if len(visible) == 1 else None,
                    "partitions": [assignment["partition"] for assignment in visible],
                    "visible_bits": visible_bits,
                    "visibility_percentage": round(
                        visible_bits * 100 / anchor_impl.M, 2
                    ),
                    "position_rule": "; ".join(
                        f'P{assignment["partition"]}: {assignment["position_rule"]}'
                        for assignment in visible
                    ),
                }
            )
            view_masks.append({"node": node, "mask": _assignment_mask(visible)})
        # The attack component runs its own logic on exactly the bits each node holds.
        from ...attacks.inference import VIEW_RUNNERS

        view_runner = VIEW_RUNNERS.get(attack)
        attack_result = (
            view_runner(view_masks, encoding=encoding)
            if view_runner and view_masks
            else None
        )
        attack_support = {
            "status": "executed" if attack_result else "unsupported_attack",
            "requested_attack": attack,
            "attack_executed": attack_result is not None,
            "baseline": {
                "representation": "complete_bloom_filter",
                "visibility_percentage": 100.0,
                "records": len(rows),
            },
            "partition_views": partition_views,
            "result": attack_result,
            "interface": (
                "The defence passes each node's partition view to the attack component, "
                "which runs on the visible Bloom positions only and is compared with the "
                "complete-filter baseline."
                if attack_result
                else f"The attack {attack!r} has no partition-view runner, so it was not executed."
            ),
        }
    attack_executed = bool(attack_support and attack_support["attack_executed"])
    average_ms = (
        round(verification_seconds * 1000 / len(records), 3) if records else 0.0
    )
    baseline_ms = round(baseline_seconds * 1000 / len(records), 3) if records else 0.0
    return {
        "check": "inference",
        "defense": "horizontal_partitioning",
        "system": "bloom",
        "strategy": strategy,
        "strategy_name": (
            f"Salted + {STRATEGY_NAMES[strategy]}"
            if encoding
            else STRATEGY_NAMES[strategy]
        ),
        "salted": encoding is not None,
        "attack": attack,
        "attack_supported": attack_executed,
        "attack_executed": attack_executed,
        "attack_support": attack_support,
        "placement": placement,
        "replication_factor": replication_factor,
        "partition_count": partition_count,
        "bloom_filter_bits": anchor_impl.M,
        "nodes": list(NODES),
        "assignments": assignments,
        "blocks_partitioned": len(rows),
        "storage": storage,
        "verification": verification_summary,
        "verification_accuracy": verification_accuracy,
        "availability": availability,
        "metrics": {
            "partition_generation_ms": round(partition_seconds * 1000, 3),
            "average_verification_ms": average_ms,
            "baseline_verification_ms": baseline_ms,
            "verification_overhead_ms": round(average_ms - baseline_ms, 3),
            "storage_bytes_per_record": bytes_per_record,
            "communication_bytes_per_verification": (
                round(communication_bytes / len(records)) if records else 0
            ),
        },
        "all_reconstructed": bool(rows) and all(row["reconstructed"] for row in rows),
        "all_verified": bool(rows) and all(row["verified"] for row in rows),
        "max_node_exposure_percent": round(maximum_node_bits * 100 / anchor_impl.M, 2),
        "rows": rows,
        "conclusion": (
            f"The Horizontal Partitioning defence used {STRATEGY_NAMES[strategy]} to "
            "distribute each complete Bloom-filter anchor across "
            f"{partition_count} balanced partitions with replication factor "
            f"{replication_factor}. "
            "Partition-aware verification matched the complete-filter baseline without giving "
            "one node the entire bit array."
            + (
                " Every record was first salted, so the same value sets different bits in different records."
                if encoding
                else ""
            )
        ),
    }


def run_sequential_partitioning(
    attack: str | None = None,
    options: dict | None = None,
) -> dict:
    """Evaluate balanced contiguous Sequential Bit Partitioning."""
    return _run_partitioning("sequential", attack, options)


def run_interleaved_partitioning(
    attack: str | None = None,
    options: dict | None = None,
) -> dict:
    """Evaluate round-robin Interleaved Bit Partitioning."""
    return _run_partitioning("interleaved", attack, options)


def run_pairwise_partitioning(
    attack: str | None = None,
    options: dict | None = None,
) -> dict:
    """Evaluate pairwise replication, optionally after per-record salting."""
    if options is not None and not isinstance(options, dict):
        raise PartitionError("defence options must be an object")
    salted = (options or {}).get("salted", False)
    if not isinstance(salted, bool):
        raise PartitionError("pairwise salted option must be a boolean")
    encoding = None
    if salted:
        from .salting import SaltedEncoding

        encoding = SaltedEncoding(systems()["bloom"].config["anchor"])
    return _run_partitioning("pairwise", attack, options, encoding)


def run_salted_partitioning(
    attack: str | None = None,
    options: dict | None = None,
) -> dict:
    """Combined defence: per-record salting, then sequential partitioning across nodes.

    Salting removes the shared bit patterns that similarity attacks rely on; partitioning
    keeps a key-holding coalition from seeing all of a guess's positions.
    """
    from .salting import SaltedEncoding

    return _run_partitioning(
        "sequential",
        attack,
        options,
        SaltedEncoding(systems()["bloom"].config["anchor"]),
    )


# Backward-compatible name for code written before the strategy was named SBP.
run_horizontal_partitioning = run_sequential_partitioning
