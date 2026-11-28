"""Ablation: every inference attack against every defence setting, in one table.

Settings compared, each against the same attack:

  No defence            the complete stored filters
  Partitioning          sequential horizontal partitioning across the nodes
  Salted hashing        per-record salt, complete filters
  Salted + partitioned  both together

Each cell is the defence's headline (worst-case) measure block for that attack, so the
table shows which layer stops which attack, and whether the combination stops them all.
"""
from .partitioning import run_salted_partitioning, run_sequential_partitioning
from .salting import run_salted_hashing

ATTACKS = {
    "collusion": "Colluding-node dictionary attack",
    "pattern_mining": "Pattern / frequency linkage attack",
    "reference_similarity": "Reference-assisted fragment inference",
    "adaptive": "Adaptive attacker (worst case)",
}
DEFENCES = {
    "sequential": ("Partitioning", run_sequential_partitioning),
    "salted": ("Salted hashing", run_salted_hashing),
    "salted_partitioned": ("Salted + partitioned", run_salted_partitioning),
}
MEASURE_KEYS = ("asr", "chance", "advantage", "security_level", "risk_reduction", "attack_ms")


def _cell(security: dict) -> dict:
    return {k: security.get(k) for k in MEASURE_KEYS}


def run_ablation() -> dict:
    columns = [{"id": "none", "name": "No defence"}] + [
        {"id": key, "name": name} for key, (name, _) in DEFENCES.items()]
    rows = []
    for attack, attack_name in ATTACKS.items():
        cells, baseline = {}, None
        for key, (_, runner) in DEFENCES.items():
            result = runner(attack)["attack_support"]["result"]
            baseline = baseline or result["baseline"]["security"]
            cells[key] = {**_cell(result["security"]), "worst_attacker": result["security"].get("worst_attacker")}
        cells["none"] = _cell(baseline)
        rows.append({"attack": attack, "name": attack_name, "cells": cells})
    return {
        "check": "inference",
        "kind": "ablation",
        "system": "bloom",
        "columns": columns,
        "rows": rows,
        "note": (
            "Each cell is the worst case for that defence: the strongest node or coalition short of "
            "all nodes. Security level is 1 - attacker advantage; 100% means nothing is learned "
            "beyond a random guess."
        ),
    }
