"""Component C1: Manipulation Attacks against Inter-Block Partitioning Defenses.

This module implements three targeted attack strategies designed to evaluate the
resilience of the Component C2 (Defense) partitioning schemes:
1. "Sequence-Rewrite Collusion" (against Single-sequence partitioning):
   Exploits knowledge of the deterministic cyclic placement ((i - 1) mod n) + 1.
   Colluding nodes target sequential nodes to rewrite content/visual data in a
   coordinated chain rewrite.
2. "Odd-Node Hijack" (against Single-odd partitioning):
   Targets the subset of nodes assigned to odd-numbered blocks. The attacker colludes
   with the odd-block holders to modify only odd blocks while leaving even blocks intact.
3. "K-Group Tampering" (against k-sequence partitioning):
   Identifies the k-replica groups and targets group boundaries (first/last block of
   a k-group) to break hash-chain consistency and test replica consensus.

Each attack outputs explicit "Success" or "Failure" logs to allow evaluation scripts
to calculate Attack Success Rate (ASR) and Defense Effectiveness (DE):
    ASR = Successful Bypasses / Total Attack Trials
    DE  = Detected Attacks / Total Attack Trials = 1.0 - ASR
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import logging
import random
import sys
from pathlib import Path

# Setup dual logging: both Python logger and console output
logger = logging.getLogger("certchain.attacks.manipulation.partition_attacks")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Imports from existing framework
try:
    from ...defenses.manipulation import partition as P
    from ...ledger import GENESIS_PREV, NODES, block_digest
    from ...anchors import canonical, HashAnchor
    from .collusion_attack import SAMPLE_CERTIFICATE, tamper_document
    from .measures import advantage, asr, defense_effectiveness, measures, timer
except (ImportError, ValueError):
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from certchain.defenses.manipulation import partition as P
    from certchain.ledger import GENESIS_PREV, NODES, block_digest
    from certchain.anchors import canonical, HashAnchor
    from certchain.attacks.manipulation.collusion_attack import SAMPLE_CERTIFICATE, tamper_document
    from certchain.attacks.manipulation.measures import advantage, asr, defense_effectiveness, measures, timer


def _build_forged_anchor(base_doc: dict | None = None, category: str = "content") -> tuple[str, dict]:
    """Generates a forged anchor and returns the tampered canonical JSON and diffs."""
    doc = base_doc or copy.deepcopy(SAMPLE_CERTIFICATE)
    tampered, diffs = tamper_document(doc, category=category)
    anchor_dict = HashAnchor().build(tampered)
    return canonical(anchor_dict), diffs


def _format_eval_log(strategy_name: str, defense_name: str, target: int,
                      colluders: list[str] | set[int], result: str,
                      asr: float, de: float, finding: dict | None = None) -> str:
    finding_str = f" | Detected by: {finding['type']}" if finding else " | No detection (Valid)"
    return (
        f"[ATTACK EVALUATION] Strategy: {strategy_name} | "
        f"Defense: {defense_name} | Target Block: {target} | "
        f"Colluders: {colluders} | "
        f"Result: {result} | ASR: {asr:.2f} | DE: {de:.2f}{finding_str}"
    )


# ============================================================================
# Strategy 1: Sequence-Rewrite Collusion (against Single-sequence partitioning)
# ============================================================================
class SequenceRewriteCollusion:
    """Exploits Single-Sequence partitioning ((i - 1) mod n) + 1.
    
    The attacker knows that consecutive blocks cycle strictly through nodes
    (0, 1, 2, ..., n-1, 0, 1, ...). Colluders pool write access to coordinate
    sequential rewrites from a target block forward to satisfy cross-referencing.
    """
    NAME = "Sequence-Rewrite Collusion"
    TARGET_DEFENSE = "Single-sequence"

    @classmethod
    def execute(
        cls,
        chain: P.PartitionedChain | None = None,
        target_block: int = 3,
        colluders: set[int] | None = None,
        category: str = "content",
        n: int = 3,
        num_blocks: int = 12,
        head_pin: bool = False,
    ) -> dict:
        """Executes a sequence-rewrite collusion attack.
        
        Args:
            chain: Optional pre-existing PartitionedChain (uses SingleSequence).
            target_block: The block index to manipulate.
            colluders: Set of node indices (0..n-1) in the colluding coalition.
            category: Tampering category ('content', 'visual', or 'both').
            n: Number of nodes if creating a mock chain.
            num_blocks: Number of blocks in mock chain.
            head_pin: Whether the defense enables head hash pinning.
        """
        with timer() as elapsed:
            if chain is None:
                strategy = P.SingleSequence()
                chain = P.PartitionedChain(P.synthetic_chain(num_blocks), n, strategy, head_pin=head_pin)
            else:
                chain = chain.clone()

            n = chain.n
            N = chain.height
            target_block = max(0, min(target_block, N - 1))

            # Default colluders: coalition that includes the holder of target_block and its sequence
            if colluders is None:
                # Default to a 2-node coalition out of n
                target_holder = chain.holders(target_block)[0]
                colluders = {target_holder, (target_holder + 1) % n}

            forged_anchor, diffs = _build_forged_anchor(category=category)
            
            # Apply the coordinated sequence rewrite through the colluders
            rewrite_res = P.apply_collusion(chain, colluders, target_block, forged_anchor)
            
            # Run defense verification pipeline (Algorithm 1 hash-chain cross-reference)
            verification = chain.verify()
            is_valid = verification["status"] == "Blockchain Valid"
            attack_success = is_valid and rewrite_res["blocks_rewritten"] > 0

            result = "Success" if attack_success else "Failure"
            asr = 1.0 if attack_success else 0.0
            de = 0.0 if attack_success else 1.0

        # Collusion threshold: distinct nodes along the sequence suffix to the chain head
        seq_threshold = min(n, max(1, N - target_block))
        security = measures(
            success_rate=asr,
            chance=0.0,
            baseline_asr=1.0,
            attack_ms=elapsed(),
            collusion_threshold=seq_threshold,
            total_nodes=n,
        )

        colluder_names = [chain.names[i] for i in sorted(colluders)]
        log_msg = _format_eval_log(
            cls.NAME, cls.TARGET_DEFENSE, target_block, colluder_names,
            result, asr, de, verification["first"]
        )
        logger.info(log_msg)

        return {
            "strategy": cls.NAME,
            "defense": cls.TARGET_DEFENSE,
            "result": result,
            "asr": asr,
            "defense_effectiveness": de,
            "security": security,
            "target_block": target_block,
            "colluders": list(sorted(colluders)),
            "colluder_names": colluder_names,
            "blocks_rewritten": rewrite_res["blocks_rewritten"],
            "blocks_needed": rewrite_res["blocks_needed"],
            "blocked_blocks": rewrite_res["blocked_blocks"],
            "verification_status": verification["status"],
            "first_finding": verification["first"],
            "finding_count": verification["finding_count"],
            "tampering_category": category,
            "modifications": diffs,
            "head_pin": chain.head_pin,
            "log": log_msg,
        }


# ============================================================================
# Strategy 2: Odd-Node Hijack (against Single-odd partitioning)
# ============================================================================
class OddNodeHijack:
    """Exploits Single-Odd partitioning.
    
    The Single-Odd defense partitions nodes into odd and even cycles.
    The attacker identifies and compromises the subset of nodes holding odd-numbered
    blocks, altering records in odd blocks while leaving even blocks untouched.
    """
    NAME = "Odd-Node Hijack"
    TARGET_DEFENSE = "Single-odd"

    @classmethod
    def execute(
        cls,
        chain: P.PartitionedChain | None = None,
        target_block: int | None = None,
        odd_colluders: set[int] | None = None,
        category: str = "content",
        n: int = 4,
        num_blocks: int = 12,
        head_pin: bool = False,
    ) -> dict:
        """Executes the Odd-Node Hijack attack.
        
        Args:
            chain: Optional pre-existing PartitionedChain (uses SingleOdd).
            target_block: Optional specific odd block to target (defaults to first odd block).
            odd_colluders: Set of node indices holding the odd blocks.
            category: Tampering category ('content', 'visual', or 'both').
            n: Number of nodes (best demonstrated with n >= 4 for distinct odd/even node sets).
            num_blocks: Number of blocks in mock chain.
            head_pin: Whether the defense enables head hash pinning.
        """
        with timer() as elapsed:
            if chain is None:
                strategy = P.SingleOdd()
                chain = P.PartitionedChain(P.synthetic_chain(num_blocks), n, strategy, head_pin=head_pin)
            else:
                chain = chain.clone()

            n = chain.n
            N = chain.height
            
            # Identify all odd-numbered blocks and their assigned nodes
            odd_blocks = [i for i in range(N) if i % 2 == 1]
            nodes_holding_odd = {chain.holders(i)[0] for i in odd_blocks}
            
            # Default to compromising all nodes that store odd blocks
            colluders = odd_colluders if odd_colluders is not None else nodes_holding_odd
            
            # Default target block is an odd-numbered block held by the odd coalition
            if target_block is None or target_block % 2 == 0:
                target_block = odd_blocks[0] if odd_blocks else 1

            forged_anchor, diffs = _build_forged_anchor(category=category)
            
            # Apply the hijack targeting the odd block
            rewrite_res = P.apply_collusion(chain, colluders, target_block, forged_anchor)
            
            # Verify cross-references between odd nodes and even nodes
            verification = chain.verify()
            is_valid = verification["status"] == "Blockchain Valid"
            attack_success = is_valid and rewrite_res["blocks_rewritten"] > 0

            result = "Success" if attack_success else "Failure"
            asr = 1.0 if attack_success else 0.0
            de = 0.0 if attack_success else 1.0

        odd_threshold = max(1, len(nodes_holding_odd))
        security = measures(
            success_rate=asr,
            chance=0.0,
            baseline_asr=1.0,
            attack_ms=elapsed(),
            collusion_threshold=odd_threshold,
            total_nodes=n,
        )

        colluder_names = [chain.names[i] for i in sorted(colluders)]
        log_msg = _format_eval_log(
            cls.NAME, cls.TARGET_DEFENSE, target_block, colluder_names,
            result, asr, de, verification["first"]
        )
        logger.info(log_msg)

        return {
            "strategy": cls.NAME,
            "defense": cls.TARGET_DEFENSE,
            "result": result,
            "asr": asr,
            "defense_effectiveness": de,
            "security": security,
            "target_block": target_block,
            "odd_blocks_count": len(odd_blocks),
            "colluders": list(sorted(colluders)),
            "colluder_names": colluder_names,
            "blocks_rewritten": rewrite_res["blocks_rewritten"],
            "blocks_needed": rewrite_res["blocks_needed"],
            "verification_status": verification["status"],
            "first_finding": verification["first"],
            "finding_count": verification["finding_count"],
            "tampering_category": category,
            "modifications": diffs,
            "head_pin": chain.head_pin,
            "log": log_msg,
        }


# ============================================================================
# Strategy 3: K-Group Tampering (against k-sequence partitioning)
# ============================================================================
class KGroupTampering:
    """Exploits k-sequence partitioning.
    
    Each block in k-sequence is replicated across k consecutive nodes.
    Attackers identify the k-block groups and target the boundaries of these
    groups (e.g., tampering with the boundary block or across group transitions)
    to test whether the multi-replica consensus and inter-group link hold.
    """
    NAME = "K-Group Tampering"
    TARGET_DEFENSE = "k-sequence"

    @classmethod
    def execute(
        cls,
        chain: P.PartitionedChain | None = None,
        target_block: int = 4,
        colluders: set[int] | None = None,
        k: int = 2,
        category: str = "content",
        n: int = 4,
        num_blocks: int = 12,
        boundary_mode: str = "within_group",
        head_pin: bool = False,
    ) -> dict:
        """Executes the K-Group Tampering attack.
        
        Args:
            chain: Optional pre-existing PartitionedChain (uses KSequence).
            target_block: The block index to tamper with (boundary or internal).
            colluders: Colluding nodes set. If None, derives a boundary coalition.
            k: Replication factor (k consecutive nodes).
            category: Tampering category ('content', 'visual', or 'both').
            n: Number of nodes.
            num_blocks: Number of blocks in mock chain.
            boundary_mode:
                - 'partial_group': Colluders control < k nodes of the group (tests replica mismatch).
                - 'full_group_boundary': Colluders control all k nodes of the boundary block
                  (tests boundary transition consistency).
            head_pin: Whether the defense enables head hash pinning.
        """
        with timer() as elapsed:
            if chain is None:
                strategy = P.KSequence(k=k)
                chain = P.PartitionedChain(P.synthetic_chain(num_blocks), n, strategy, head_pin=head_pin)
            else:
                chain = chain.clone()

            n = chain.n
            N = chain.height
            target_block = max(0, min(target_block, N - 1))
            group_holders = set(chain.holders(target_block))

            # Configure coalition based on boundary testing mode
            if colluders is None:
                if boundary_mode == "partial_group":
                    # Compromise fewer than k nodes in the group (e.g., k - 1 nodes)
                    colluders = set(list(group_holders)[:max(1, k - 1)])
                else:
                    # Compromise all k nodes holding the boundary block
                    colluders = set(group_holders)

            forged_anchor, diffs = _build_forged_anchor(category=category)
            
            # Apply the tampering on the k-group
            rewrite_res = P.apply_collusion(chain, colluders, target_block, forged_anchor)
            
            # Verify cross-reference and replica consensus
            verification = chain.verify()
            is_valid = verification["status"] == "Blockchain Valid"
            attack_success = is_valid and rewrite_res["blocks_rewritten"] > 0

            result = "Success" if attack_success else "Failure"
            asr = 1.0 if attack_success else 0.0
            de = 0.0 if attack_success else 1.0

        # Collusion threshold for k-sequence: must compromise all k replicas to tamper without replica mismatch
        k_threshold = k
        security = measures(
            success_rate=asr,
            chance=0.0,
            baseline_asr=1.0,
            attack_ms=elapsed(),
            collusion_threshold=k_threshold,
            total_nodes=n,
        )

        defense_label = f"k-sequence (k={k})"
        colluder_names = [chain.names[i] for i in sorted(colluders)]
        log_msg = _format_eval_log(
            cls.NAME, defense_label, target_block, colluder_names,
            result, asr, de, verification["first"]
        )
        logger.info(log_msg)

        return {
            "strategy": cls.NAME,
            "defense": defense_label,
            "k": k,
            "boundary_mode": boundary_mode,
            "result": result,
            "asr": asr,
            "defense_effectiveness": de,
            "security": security,
            "target_block": target_block,
            "group_holders": list(sorted(group_holders)),
            "colluders": list(sorted(colluders)),
            "colluder_names": colluder_names,
            "blocks_rewritten": rewrite_res["blocks_rewritten"],
            "verification_status": verification["status"],
            "first_finding": verification["first"],
            "finding_count": verification["finding_count"],
            "tampering_category": category,
            "modifications": diffs,
            "head_pin": chain.head_pin,
            "log": log_msg,
        }


# ============================================================================
# Convenience Functional Wrappers
# ============================================================================
def _get_request_opts() -> dict:
    try:
        from flask import request
        if request:
            return request.get_json(silent=True) or {}
    except Exception:
        pass
    return {}


def sequence_rewrite_collusion(options: dict | None = None, **kwargs) -> dict:
    """Wrapper function for Strategy 1: Sequence-Rewrite Collusion."""
    opts = {**_get_request_opts(), **(options or {}), **kwargs}
    clean_opts = {k: v for k, v in opts.items() if k in ("target_block", "colluders", "category", "n", "num_blocks", "head_pin")}
    return SequenceRewriteCollusion.execute(**clean_opts)


def odd_node_hijack(options: dict | None = None, **kwargs) -> dict:
    """Wrapper function for Strategy 2: Odd-Node Hijack."""
    opts = {**_get_request_opts(), **(options or {}), **kwargs}
    clean_opts = {k: v for k, v in opts.items() if k in ("target_block", "odd_colluders", "category", "n", "num_blocks", "head_pin")}
    return OddNodeHijack.execute(**clean_opts)


def k_group_tampering(options: dict | None = None, **kwargs) -> dict:
    """Wrapper function for Strategy 3: K-Group Tampering."""
    opts = {**_get_request_opts(), **(options or {}), **kwargs}
    clean_opts = {k: v for k, v in opts.items() if k in ("target_block", "colluders", "k", "category", "n", "num_blocks", "boundary_mode", "head_pin")}
    return KGroupTampering.execute(**clean_opts)


# ============================================================================
# Multi-Trial Evaluation Runner (Calculates ASR and Defense Effectiveness)
# ============================================================================
def evaluate_partitioning_attacks(
    trials: int = 15,
    n: int = 4,
    num_blocks: int = 12,
    category: str = "content",
) -> dict:
    """Runs a benchmark comparing all three attack strategies against their defenses.
    
    Computes empirical:
    - Attack Success Rate (ASR) = Successes / Trials
    - Defense Effectiveness (DE) = Failures / Trials = 1.0 - ASR
    """
    results = {}
    strategies = [
        ("Sequence-Rewrite Collusion", "Single-sequence", SequenceRewriteCollusion),
        ("Odd-Node Hijack", "Single-odd", OddNodeHijack),
        ("K-Group Tampering", "k-sequence (k=2)", KGroupTampering),
    ]

    print("\n" + "=" * 85)
    print("RUNNING COMPONENT C1: MANIPULATION ATTACKS AGAINST PARTITIONING DEFENSES")
    print(f"Configuration: Trials={trials} per strategy | Nodes={n} | Chain Height={num_blocks} | Category={category}")
    print("=" * 85)

    for strat_name, def_name, strat_cls in strategies:
        print(f"\n--> Evaluating {strat_name} (against {def_name})...")
        success_count = 0
        failure_count = 0
        findings_summary = {}

        for t in range(trials):
            # Select target block across the chain (avoiding genesis block 0)
            target = (t % (num_blocks - 1)) + 1
            
            # Vary coalition sizes across trials to simulate realistic attacker variations
            if strat_cls == SequenceRewriteCollusion:
                # Alternate between partial sequence and full suffix sequence
                colluders = set(range(n)) if (t % 3 == 0) else {target % n, (target + 1) % n}
                res = strat_cls.execute(target_block=target, colluders=colluders, category=category, n=n, num_blocks=num_blocks)
            elif strat_cls == OddNodeHijack:
                # Target odd blocks; test intermediate vs tail odd block
                target_odd = (num_blocks - 1) if (t % 4 == 0) else ((2 * t + 1) % (num_blocks - 1))
                res = strat_cls.execute(target_block=target_odd, category=category, n=n, num_blocks=num_blocks)
            else:
                # Alternate between partial boundary and full group boundary
                mode = "partial_group" if (t % 2 == 0) else "full_group_boundary"
                res = strat_cls.execute(target_block=target, k=2, boundary_mode=mode, category=category, n=n, num_blocks=num_blocks)

            if res["result"] == "Success":
                success_count += 1
            else:
                failure_count += 1
                finding_type = res["first_finding"]["type"] if res["first_finding"] else "unknown"
                findings_summary[finding_type] = findings_summary.get(finding_type, 0) + 1

        asr = success_count / trials
        de = failure_count / trials
        c_thresh = 2 if "k-sequence" in def_name else (max(1, n // 2) if "odd" in def_name else n)
        sec = measures(
            success_rate=asr,
            chance=0.0,
            baseline_asr=1.0,
            collusion_threshold=c_thresh,
            total_nodes=n,
        )
        results[strat_name] = {
            "defense": def_name,
            "trials": trials,
            "successes": success_count,
            "failures": failure_count,
            "asr": asr,
            "defense_effectiveness": de,
            "security": sec,
            "detections": findings_summary,
        }

        print(f"Summary for {strat_name}:")
        print(f"  Successes (Bypassed): {success_count} | Failures (Detected): {failure_count}")
        print(f"  ASR: {asr:.2%} | Defense Effectiveness (DE): {de:.2%}")
        if findings_summary:
            print(f"  Detection breakdown: {findings_summary}")

    print("\n" + "=" * 85)
    print("FINAL EVALUATION METRICS TABLE")
    print("=" * 85)
    print(f"{'Attack Strategy':<28} | {'Target Defense':<20} | {'Trials':<6} | {'ASR':<8} | {'DE (1-ASR)':<10}")
    print("-" * 85)
    for s_name, data in results.items():
        print(f"{s_name:<28} | {data['defense']:<20} | {data['trials']:<6} | {data['asr']:<7.1%} | {data['defense_effectiveness']:<9.1%}")
    print("=" * 85 + "\n")

    return results


# ============================================================================
# CLI Execution Entry Point
# ============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Component C1: Manipulation Attacks on Partitioning Defenses")
    parser.add_argument("--strategy", choices=["sequence", "odd", "kgroup", "all"], default="all",
                        help="Attack strategy to execute")
    parser.add_argument("--category", choices=["content", "visual", "both"], default="content",
                        help="Tampering category (content, visual, or both)")
    parser.add_argument("--trials", type=int, default=10,
                        help="Number of trials for statistical evaluation")
    parser.add_argument("--nodes", type=int, default=4,
                        help="Number of blockchain nodes")
    parser.add_argument("--blocks", type=int, default=12,
                        help="Number of blocks in the chain")
    parser.add_argument("--head-pin", action="store_true",
                        help="Enable head hash pinning defense refinement")
    args = parser.parse_args()

    if args.strategy == "sequence":
        res = SequenceRewriteCollusion.execute(category=args.category, n=args.nodes, num_blocks=args.blocks, head_pin=args.head_pin)
        print(json.dumps(res, indent=2))
    elif args.strategy == "odd":
        res = OddNodeHijack.execute(category=args.category, n=args.nodes, num_blocks=args.blocks, head_pin=args.head_pin)
        print(json.dumps(res, indent=2))
    elif args.strategy == "kgroup":
        res = KGroupTampering.execute(category=args.category, n=args.nodes, num_blocks=args.blocks, head_pin=args.head_pin)
        print(json.dumps(res, indent=2))
    else:
        evaluate_partitioning_attacks(trials=args.trials, n=args.nodes, num_blocks=args.blocks, category=args.category)
