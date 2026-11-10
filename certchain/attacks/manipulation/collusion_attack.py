"""Component C1: Manipulation Attack - Collusion among organisations.

In a standard manipulation attack, a single rogue organisation or attacker attempts
to tamper with an academic document (e.g., certificate or transcript). Under the
blockchain verification pipeline, a single-node attack fails because:
1. The remaining honest nodes outvote the rogue node in consensus (threshold > 1).
2. For keyed Bloom anchors, a single node does not possess the full cryptographic key.

In this 'Collusion among organisations' strategy:
- Multi-Node Sharing: Two or more organisations pool their access and cryptographic
  key shares (modeled via (t, n) Shamir Secret Sharing).
- Bypass Mechanism: When the number of colluding organisations reaches or exceeds
  the consensus threshold (t = floor(n/2) + 1), the colluders:
    a) Reconstruct the master key to compute a cryptographically valid anchor.
    b) Synchronously rewrite their local block anchors and chain hashes.
    c) Form the consensus majority, forcing the verification pipeline to accept
       the tampered document as authentic.
- Tampering Categories: Supports both 'Content' (degree classification, marks, grades)
  and 'Visual' (seal hashes, signature digests, QR metadata) tampering.
- Output: Logs explicit 'Success' or 'Failure' results and calculates the Attack
  Success Rate (ASR) for evaluation modules.
"""
import argparse
import copy
import hashlib
import json
import logging
import os
import secrets
import tempfile
from pathlib import Path

# Setup dual logging: both Python logger and console-friendly output
logger = logging.getLogger("certchain.attacks.manipulation.collusion")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

try:
    from ..common import NODES, BloomAnchor, HashAnchor, canonical, field_item, sha256, systems
except (ImportError, ValueError):
    # Standalone execution support
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from certchain.attacks.common import NODES, BloomAnchor, HashAnchor, canonical, field_item, sha256, systems

# Sample base document for manipulation experiments
SAMPLE_CERTIFICATE = {
    "type": "certificate.issue",
    "data": {
        "id": "CERT-2026-0001",
        "student_id": "UNI20260001",
        "title": "Bachelor of Science (Pass)",
        "programme": "BSc (Hons) Information Technology",
        "issued_on": "2026-08-20",
        "code": "DEMO-NILA-2026",
        "visual_seal_hash": "sha256:d41d8cd98f00b204e9800998ecf8427e",
        "signature_digest": "sha256:academic_registrar_signature_official",
    },
    "actor": "seed",
    "at": "2026-01-01T00:00:00+00:00",
}


# ============================================================================
# 1. Multi-Node Cryptographic Key Sharing (Threshold Secret Sharing)
# ============================================================================
class ThresholdKeySharing:
    """Simulates a (t, n) Shamir Secret Sharing scheme for master cryptographic keys.
    
    A 256-bit prime field ensures information-theoretic security:
    - Any subset of t or more shares can reconstruct the exact master key.
    - Fewer than t shares reveal zero information about the secret key.
    """
    PRIME = 2**256 + 297

    @classmethod
    def split(cls, secret_bytes: bytes, n: int, t: int) -> dict[str, tuple[int, int]]:
        """Split a 32-byte secret key into n shares labeled by node name."""
        if not (1 <= t <= n):
            raise ValueError(f"Invalid threshold t={t} for n={n} nodes.")
        s = int.from_bytes(secret_bytes, "big")
        coeffs = [s] + [secrets.randbelow(cls.PRIME) for _ in range(t - 1)]
        shares = {}
        for idx, node in enumerate(NODES[:n], start=1):
            y = sum(c * pow(idx, exp, cls.PRIME) for exp, c in enumerate(coeffs)) % cls.PRIME
            shares[node] = (idx, y)
        return shares

    @classmethod
    def reconstruct(cls, shares: list[tuple[int, int]], t: int) -> bytes | None:
        """Reconstruct the 32-byte secret key using Lagrange interpolation at x=0."""
        if len(shares) < t:
            return None
        selected = shares[:t]
        secret = 0
        P = cls.PRIME
        for j, (xj, yj) in enumerate(selected):
            num, den = 1, 1
            for m, (xm, _) in enumerate(selected):
                if m != j:
                    num = (num * (-xm)) % P
                    den = (den * (xj - xm)) % P
            lj = (num * pow(den, -1, P)) % P
            secret = (secret + yj * lj) % P
        return secret.to_bytes(32, "big")


# ============================================================================
# 2. Document Tampering Engine (Content & Visual Categories)
# ============================================================================
def tamper_document(original_doc: dict, category: str = "content") -> tuple[dict, dict]:
    """Applies unauthorized alterations to an academic document.
    
    Categories:
    - 'content': Alter academic degree classification, title, or marks.
    - 'visual': Alter security seal, emblem hash, signature digest, or QR token.
    - 'both': Alter both content and visual attributes simultaneously.
    
    Returns:
        (tampered_document, modifications_dict)
    """
    tampered = copy.deepcopy(original_doc)
    modifications = {}

    if category in ("content", "both"):
        # Elevate degree title from Pass to First Class Honours with Distinction
        old_title = tampered["data"].get("title", "")
        new_title = "Bachelor of Science (First Class Honours with Distinction)"
        tampered["data"]["title"] = new_title
        modifications["title"] = {"original": old_title, "tampered": new_title}

    if category in ("visual", "both"):
        # Alter visual watermark / seal and forged signature digest
        old_seal = tampered["data"].get("visual_seal_hash", "none")
        new_seal = "sha256:" + hashlib.sha256(b"forged_gold_embossed_seal_2026").hexdigest()
        tampered["data"]["visual_seal_hash"] = new_seal
        modifications["visual_seal_hash"] = {"original": old_seal, "tampered": new_seal}

        old_sig = tampered["data"].get("signature_digest", "none")
        new_sig = "sha256:" + hashlib.sha256(b"forged_registrar_signature").hexdigest()
        tampered["data"]["signature_digest"] = new_sig
        modifications["signature_digest"] = {"original": old_sig, "tampered": new_sig}

    return tampered, modifications


# ============================================================================
# 3. Core Collusion Attack Simulation
# ============================================================================
def simulate_single_collusion(
    num_colluding: int,
    tampering_category: str = "content",
    system_type: str = "bloom",
    total_nodes: int = len(NODES),
    threshold: int | None = None,
    master_key: bytes | None = None,
    base_doc: dict | None = None,
) -> dict:
    """Simulates a single attack run with a specific collusion coalition size.
    
    Workflow:
    1. Multi-Node Sharing: Sample coalition of `num_colluding` organisations.
    2. Key Recovery: Attempt to reconstruct master cryptographic key.
    3. Consensus Hijacking: Evaluate whether colluding nodes control consensus majority.
    4. Bypass Verification: Test whether the tampered document is verified as valid.
    5. Output Log: Emit 'Success' or 'Failure' log for ASR calculation.
    """
    threshold = threshold or (total_nodes // 2 + 1)
    base_doc = base_doc or SAMPLE_CERTIFICATE
    master_key = master_key or secrets.token_bytes(32)

    colluding_nodes = list(NODES[:num_colluding])
    honest_nodes = [n for n in NODES[:total_nodes] if n not in colluding_nodes]

    # Step 1: Multi-node key sharing
    shares = ThresholdKeySharing.split(master_key, total_nodes, threshold)
    pooled_shares = [shares[n] for n in colluding_nodes]
    reconstructed_key = ThresholdKeySharing.reconstruct(pooled_shares, threshold)

    key_reconstructed = reconstructed_key is not None
    effective_key = reconstructed_key if key_reconstructed else (b"\x00" * 32)

    # Step 2: Tamper with the document
    tampered_doc, diffs = tamper_document(base_doc, category=tampering_category)

    # Step 3: Compute anchor using the colluders' available key
    if system_type == "conventional":
        colluder_anchor = HashAnchor().build(tampered_doc)
        valid_verifier = HashAnchor()
    else:
        colluder_anchor = BloomAnchor(effective_key).build(tampered_doc)
        valid_verifier = BloomAnchor(master_key)

    # Step 4: Consensus check - do colluders control majority of nodes?
    consensus_hijacked = len(colluding_nodes) >= threshold

    # Step 5: Verification Pipeline evaluation
    # If consensus is not hijacked, the honest majority chain retains the original anchor,
    # so the verification pipeline rejects the tampered document.
    # If consensus is hijacked, the verification pipeline reads the colluders' anchor.
    # For Bloom, that anchor must also have been generated with the correct reconstructed key.
    if consensus_hijacked:
        verification_passed = valid_verifier.verify(colluder_anchor, tampered_doc)
    else:
        verification_passed = False

    attack_status = "Success" if verification_passed else "Failure"
    asr_score = 1.0 if verification_passed else 0.0

    # Human-readable evaluation log for external modules
    log_msg = (
        f"[ATTACK EVALUATION] Strategy: Collusion among organisations | "
        f"Category: {tampering_category.capitalize()} | "
        f"System: {system_type} | "
        f"Collusion Size: {num_colluding}/{total_nodes} (Threshold: {threshold}) | "
        f"Key Reconstructed: {key_reconstructed} | "
        f"Consensus Hijacked: {consensus_hijacked} | "
        f"Verification Pipeline: {'PASSED' if verification_passed else 'REJECTED'} | "
        f"Result: {attack_status} | "
        f"ASR: {asr_score:.2f}"
    )
    logger.info(log_msg)

    return {
        "status": attack_status,
        "asr": asr_score,
        "verification_passed": verification_passed,
        "colluding_nodes": colluding_nodes,
        "honest_nodes": honest_nodes,
        "collusion_size": num_colluding,
        "total_nodes": total_nodes,
        "threshold": threshold,
        "key_reconstructed": key_reconstructed,
        "consensus_hijacked": consensus_hijacked,
        "tampering_category": tampering_category,
        "modifications": diffs,
        "system": system_type,
        "log": log_msg,
    }


# ============================================================================
# 4. Framework Runner: Compatible with certchain/attacks RUNNERS Schema
# ============================================================================
def run_manipulation_collusion() -> dict:
    """Security-check runner for Manipulation Collusion Attack.
    
    Conforms to the exact schema expected by CertChain security checks
    (analogous to run_inference_collusion). Evaluates the blast radius and
    Attack Success Rate (ASR) across increasing collusion sizes.
    """
    total_nodes = len(NODES)
    threshold = total_nodes // 2 + 1

    matrix = []
    for c in range(1, total_nodes + 1):
        res = simulate_single_collusion(
            num_colluding=c,
            tampering_category="content",
            system_type="bloom",
            total_nodes=total_nodes,
            threshold=threshold,
        )
        matrix.append({
            "colluding": c,
            "key_reconstructed": res["key_reconstructed"],
            "consensus_hijacked": res["consensus_hijacked"],
            "verification_passed": res["verification_passed"],
            "status": res["status"],
            "asr": res["asr"],
        })

    # Evaluate across both systems with threshold collusion (2 nodes)
    rows = []
    for sys_name in ("conventional", "bloom"):
        res = simulate_single_collusion(
            num_colluding=threshold,
            tampering_category="content",
            system_type=sys_name,
            total_nodes=total_nodes,
            threshold=threshold,
        )
        rows.append({
            "system": sys_name,
            "colluding_nodes": threshold,
            "status": res["status"],
            "forgery_accepted": res["verification_passed"],
            "verdict": "vulnerable" if res["verification_passed"] else "resisted",
            "detail": (
                f"With {threshold} of {total_nodes} organisations colluding, the consensus "
                f"threshold is reached. {'The secret Bloom key is reconstructed, allowing a ' if sys_name == 'bloom' else 'An unkeyed '}"
                f"matching anchor to be committed to the majority chain, successfully bypassing the verification pipeline."
            ),
        })

    return {
        "check": "manipulation",
        "attack": "collusion",
        "category": "content",
        "nodes": total_nodes,
        "threshold": threshold,
        "matrix": matrix,
        "rows": rows,
        "scenario": (
            f"Multiple organisations running node infrastructure pool their cryptographic keys "
            f"and ledger write access to tamper with academic records."
        ),
        "conclusion": (
            f"A single compromised organisation cannot make a forged document pass verification "
            f"(ASR = 0.0), as honest nodes outvote it and keyed Bloom filters reject keyless anchors. "
            f"However, once {threshold} of {total_nodes} organisations collude, they reconstruct "
            f"the master key, capture consensus majority, and achieve an Attack Success Rate (ASR) of 1.0 (100%). "
            f"To defend against organisation collusion, multi-party consensus thresholds and decentralized "
            f"cross-institution attestation must be enforced."
        ),
    }


# ============================================================================
# 5. Statistical Evaluation Module (Calculates ASR over Trials)
# ============================================================================
def evaluate_asr(
    trials: int = 100,
    colluding_nodes: int = 2,
    tampering_category: str = "content",
    system_type: str = "bloom",
) -> dict:
    """Calculates empirical Attack Success Rate (ASR) over multiple randomized trials.
    
    ASR = (Number of Successful Verification Bypasses) / (Total Attack Trials)
    """
    total_nodes = len(NODES)
    threshold = total_nodes // 2 + 1
    success_count = 0
    failure_count = 0

    print(f"\n" + "=" * 80)
    print(f"RUNNING MANIPULATION ATTACK EVALUATION: COLLUSION AMONG ORGANISATIONS")
    print(f"Parameters: Trials={trials} | Colluding Nodes={colluding_nodes}/{total_nodes} | "
          f"Threshold={threshold} | Category={tampering_category} | System={system_type}")
    print("=" * 80)

    for i in range(1, trials + 1):
        # Generate fresh master keys and unique certificate IDs per trial
        trial_key = secrets.token_bytes(32)
        trial_cert = copy.deepcopy(SAMPLE_CERTIFICATE)
        trial_cert["data"]["id"] = f"CERT-EVAL-{i:05d}"
        trial_cert["data"]["code"] = secrets.token_hex(8).upper()

        result = simulate_single_collusion(
            num_colluding=colluding_nodes,
            tampering_category=tampering_category,
            system_type=system_type,
            total_nodes=total_nodes,
            threshold=threshold,
            master_key=trial_key,
            base_doc=trial_cert,
        )

        if result["status"] == "Success":
            success_count += 1
        else:
            failure_count += 1

    asr = success_count / trials
    summary_log = (
        f"[EVALUATION REPORT] Strategy: Collusion among organisations | "
        f"Category: {tampering_category.capitalize()} | "
        f"System: {system_type} | "
        f"Collusion Size: {colluding_nodes}/{total_nodes} | "
        f"Threshold: {threshold} | "
        f"Trials: {trials} | "
        f"Successes: {success_count} | "
        f"Failures: {failure_count} | "
        f"ASR: {asr:.2%}"
    )
    print("-" * 80)
    print(summary_log)
    print("=" * 80 + "\n")

    return {
        "strategy": "collusion_among_organisations",
        "tampering_category": tampering_category,
        "system": system_type,
        "trials": trials,
        "colluding_nodes": colluding_nodes,
        "total_nodes": total_nodes,
        "threshold": threshold,
        "successes": success_count,
        "failures": failure_count,
        "asr": asr,
        "summary": summary_log,
    }


# ============================================================================
# 6. Physical Ledger Validation Test
# ============================================================================
def test_against_live_sqlite_ledger():
    """Validates the collusion bypass mechanism against a real SQLite Ledger instance.
    
    Demonstrates:
    1. Single node tamper -> Ledger verification REJECTED (Consensus outvoted).
    2. Two nodes collude -> Ledger verification ACCEPTED (Consensus hijacked).
    """
    from certchain.ledger import Ledger
    
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "test_ledger.db"
        master_key = secrets.token_bytes(32)
        anchor_impl = BloomAnchor(master_key)
        ledger = Ledger(db_path, anchor_impl)
        
        try:
            # 1. Commit genuine certificate
            cert = copy.deepcopy(SAMPLE_CERTIFICATE)
            idx, _ = ledger.append(cert["type"], cert["data"], cert["actor"])
            assert ledger.verify_record(idx) is True, "Original record must verify as True"
            
            # 2. Tamper document
            tampered, _ = tamper_document(cert, category="content")
            tampered_anchor = anchor_impl.build(tampered)
            
            # Single node tamper: Registry-Node only
            ledger.rewrite_node(NODES[0], idx, tampered_anchor)
            ledger.overwrite_record(idx, tampered)
            single_verify = ledger.verify_record(idx)
            assert single_verify is False, "Single node tamper MUST fail verification"
            
            # Collusion: Second node (Academic-Board-Node) joins coalition (2 >= threshold)
            ledger.rewrite_node(NODES[1], idx, tampered_anchor)
            colluded_verify = ledger.verify_record(idx)
            assert colluded_verify is True, "Colluding majority MUST bypass verification"
            
            print("[PHYSICAL LEDGER TEST] Verified successfully against live SQLite Ledger!")
            print(f"  - Single node tampered verify: {single_verify} (Attack Failed)")
            print(f"  - 2 colluding nodes tampered verify: {colluded_verify} (Attack Succeeded)")
        finally:
            ledger.close()


# ============================================================================
# CLI Execution Entry Point
# ============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Component C1: Manipulation Attack - Collusion Strategy")
    parser.add_argument("--category", choices=["content", "visual", "both"], default="content",
                        help="Tampering category to evaluate")
    parser.add_argument("--colluding", type=int, default=2,
                        help="Number of colluding organisations (1 to 3)")
    parser.add_argument("--system", choices=["bloom", "conventional"], default="bloom",
                        help="Target blockchain system")
    parser.add_argument("--trials", type=int, default=50,
                        help="Number of evaluation trials for ASR calculation")
    parser.add_argument("--run-check", action="store_true",
                        help="Execute full security check matrix")
    parser.add_argument("--test-ledger", action="store_true",
                        help="Run test against physical SQLite ledger")
    args = parser.parse_args()

    if args.test_ledger:
        test_against_live_sqlite_ledger()
    elif args.run_check:
        results = run_manipulation_collusion()
        print(json.dumps(results, indent=2))
    else:
        evaluate_asr(
            trials=args.trials,
            colluding_nodes=args.colluding,
            tampering_category=args.category,
            system_type=args.system,
        )
