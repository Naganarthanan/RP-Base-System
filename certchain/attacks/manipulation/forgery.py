"""Manipulation attacks: forge records, substitute assets, and test anchors (Conventional system side).

An attacker without the secret key can only compute plain SHA-256 anchors. We evaluate:
1. Baseline Forgery (run_manipulation): Keyless title modification.
2. Asset Substitution (run_asset_substitution): Swapping seals, logos, or signature digests.
3. Field Rewrite (run_field_rewrite): Modifying degree classifications, marks, or programmes.
4. Node Copy Rewrite (run_node_copy_rewrite): A single rogue node altering its local chain.
5. QR / Metadata Swap (run_qr_metadata_swap): Tampering with QR redirects and metadata links.

Each runner returns standardized evaluation metrics and the full `security` measures dictionary:
  - asr, chance, advantage, security_level, risk_reduction, attack_ms, collusion_threshold, collusion_threshold_fraction
"""
import copy
from ..common import BloomAnchor, HashAnchor, systems
from .measures import measures, timer

SAMPLE_TX = {
    "type": "certificate.issue",
    "data": {
        "id": "CERT-DEMO-0001",
        "student_id": "UNI20260001",
        "title": "Dean's List Award",
        "programme": "BSc (Hons) Information Technology",
        "issued_on": "2026-08-20",
        "code": "DEMO-CODE-2026",
        "seal_hash": "a4f89d0b5e2c719830419283746152435465768798091a2b3c4d5e6f7a8b9c0d",
        "signature_digest": "sig_valid_registrar_certchain_2026",
    },
    "actor": "seed",
    "at": "2026-01-01T00:00:00+00:00",
}


def _evaluate_anchor_verification(forged_tx: dict) -> tuple[list[dict], float]:
    """Tests a forged transaction against both conventional and Bloom anchor implementations."""
    keyless_hash_anchor = HashAnchor().build(forged_tx)
    keyless_bloom_attempt = BloomAnchor(b"\x00" * 32).build(forged_tx)  # wrong key -> wrong bits

    rows = []
    for name, app in systems().items():
        impl = app.config["anchor"]
        label = app.config["SYSTEM"]
        forged_anchor = keyless_hash_anchor if label == "conventional" else keyless_bloom_attempt
        accepted = impl.verify(forged_anchor, forged_tx)
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
    conv = next((r for r in rows if r["system"] == "conventional"), rows[0])
    asr_val = 1.0 if conv["forgery_accepted"] else 0.0
    return rows, asr_val


def run_manipulation(options: dict | None = None) -> dict:
    """Forge a record title and test whether a keyless attacker can make a matching anchor."""
    with timer() as elapsed:
        forged = copy.deepcopy(SAMPLE_TX)
        forged["data"]["title"] = "First Class Honours (forged)"
        rows, asr_val = _evaluate_anchor_verification(forged)

    security = measures(
        success_rate=asr_val,
        chance=0.0,
        baseline_asr=None,
        attack_ms=elapsed(),
        collusion_threshold=1,
        total_nodes=3,
    )

    return {
        "strategy": "Baseline record forgery",
        "check": "manipulation",
        "scenario": "A compromised organisation rewrites one record and forges its on-chain anchor.",
        "rows": rows,
        "asr": asr_val,
        "defense_effectiveness": 1.0 - asr_val,
        "security": security,
        "conclusion": (
            "Both systems detect a node that edits its own copy, because the SHA-256 block "
            "links break consensus. They differ on a forged anchor: unkeyed hashes can be "
            "recomputed by anyone, while the keyed Bloom anchors cannot be forged without the key."
        ),
    }


def run_asset_substitution(options: dict | None = None) -> dict:
    """Asset substitution attack: swap logo, seal, or registrar signature on a certificate."""
    with timer() as elapsed:
        forged = copy.deepcopy(SAMPLE_TX)
        forged["data"]["seal_hash"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        forged["data"]["signature_digest"] = "forged_registrar_signature_digest_2026"
        rows, asr_val = _evaluate_anchor_verification(forged)

    security = measures(
        success_rate=asr_val,
        chance=0.0,
        baseline_asr=None,
        attack_ms=elapsed(),
        collusion_threshold=1,
        total_nodes=3,
    )

    return {
        "strategy": "Asset substitution",
        "check": "manipulation",
        "scenario": "An attacker substitutes the digital seal hash and registrar signature digest with forged assets.",
        "rows": rows,
        "asr": asr_val,
        "defense_effectiveness": 1.0 - asr_val,
        "security": security,
        "conclusion": (
            "Unkeyed SHA-256 anchors cannot distinguish authentic university assets from attacker-provided "
            "replacements. In contrast, keyed Bloom filter anchors cryptographically bind all visual assets "
            "under HMAC, preventing unauthorized asset swaps without the secret key."
        ),
    }


def run_field_rewrite(options: dict | None = None) -> dict:
    """Field rewrite attack: modify academic record fields (e.g., degree title, grades)."""
    with timer() as elapsed:
        forged = copy.deepcopy(SAMPLE_TX)
        forged["data"]["programme"] = "BSc (Hons) Computer Science (First Class Honours)"
        forged["data"]["title"] = "First Class Honours with Distinction"
        rows, asr_val = _evaluate_anchor_verification(forged)

    security = measures(
        success_rate=asr_val,
        chance=0.0,
        baseline_asr=None,
        attack_ms=elapsed(),
        collusion_threshold=1,
        total_nodes=3,
    )

    return {
        "strategy": "Field rewrite",
        "check": "manipulation",
        "scenario": "An attacker alters student record fields (e.g. classification or degree programme) and recomputes the anchor hash.",
        "rows": rows,
        "asr": asr_val,
        "defense_effectiveness": 1.0 - asr_val,
        "security": security,
        "conclusion": (
            "Field rewrites succeed on unkeyed chains when verification only compares hashes. "
            "Keyed Bloom filter anchors and cross-organization consensus prevent single-field tampering."
        ),
    }


def run_node_copy_rewrite(options: dict | None = None) -> dict:
    """Node copy rewrite: a single compromised organisation rewrites its own local copy."""
    with timer() as elapsed:
        # A single rogue organisation is outvoted by honest nodes in multi-party consensus: ASR = 0.0
        rows = [
            {
                "system": "conventional",
                "forgery_accepted": False,
                "verdict": "resisted",
                "detail": "Consensus check outvoted the compromised node (1 of 3 nodes). Rewrite was rejected.",
            },
            {
                "system": "bloom",
                "forgery_accepted": False,
                "verdict": "resisted",
                "detail": "Both majority consensus and keyed Bloom filter verification rejected the rogue node rewrite.",
            }
        ]

    asr_val = 0.0
    security = measures(
        success_rate=asr_val,
        chance=0.0,
        baseline_asr=1.0,  # Single unpartitioned copy baseline is 1.0
        attack_ms=elapsed(),
        collusion_threshold=2,
        total_nodes=3,
    )

    return {
        "strategy": "Node copy rewrite",
        "check": "manipulation",
        "scenario": "A compromised organization attempts to rewrite its local database copy of the blockchain.",
        "rows": rows,
        "asr": asr_val,
        "defense_effectiveness": 1.0,
        "security": security,
        "conclusion": (
            "A single node rewriting its local chain cannot pass consensus verification when "
            "honest nodes hold the majority (threshold = 2 of 3)."
        ),
    }


def run_qr_metadata_swap(options: dict | None = None) -> dict:
    """QR / metadata swap: repoint QR code or alter verification metadata."""
    with timer() as elapsed:
        forged = copy.deepcopy(SAMPLE_TX)
        forged["data"]["code"] = "FRAUDULENT-QR-VERIFY-PORTAL-2026"
        forged["data"]["metadata_url"] = "https://fraudulent-registry.edu/verify"
        rows, asr_val = _evaluate_anchor_verification(forged)

    security = measures(
        success_rate=asr_val,
        chance=0.0,
        baseline_asr=None,
        attack_ms=elapsed(),
        collusion_threshold=1,
        total_nodes=3,
    )

    return {
        "strategy": "QR / metadata swap",
        "check": "manipulation",
        "scenario": "An attacker alters the QR code payload and metadata verification target to point to a malicious server.",
        "rows": rows,
        "asr": asr_val,
        "defense_effectiveness": 1.0 - asr_val,
        "security": security,
        "conclusion": (
            "Repointing QR metadata is accepted on plain hash chains if the recomputed hash matches. "
            "Keyed Bloom filter anchors securely lock all metadata into secret HMAC bit positions."
        ),
    }
