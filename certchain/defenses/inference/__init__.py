"""Inference defences for the Bloom-filter system."""
from .partitioning import (
    PartitionedBloomStore,
    PartitionError,
    PartitionUnavailable,
    partition_anchor,
    partition_filter,
    reconstruct_filter,
    run_horizontal_partitioning,
    run_interleaved_partitioning,
    run_pairwise_partitioning,
    run_salted_partitioning,
    run_sequential_partitioning,
    verify_items,
    verify_items_detailed,
)

from .salting import SaltedEncoding, run_salted_hashing

RUNNERS = {
    "salted": run_salted_hashing,
    "salted_partitioned": run_salted_partitioning,
    "sequential": run_sequential_partitioning,
    "interleaved": run_interleaved_partitioning,
    "pairwise": run_pairwise_partitioning,
    "horizontal": run_sequential_partitioning,
}

__all__ = [
    "PartitionedBloomStore",
    "PartitionError",
    "PartitionUnavailable",
    "partition_anchor",
    "partition_filter",
    "reconstruct_filter",
    "run_horizontal_partitioning",
    "run_interleaved_partitioning",
    "run_pairwise_partitioning",
    "run_sequential_partitioning",
    "run_salted_hashing",
    "run_salted_partitioning",
    "SaltedEncoding",
    "verify_items",
    "verify_items_detailed",
    "RUNNERS",
]
