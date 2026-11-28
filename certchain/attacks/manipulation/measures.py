"""Security measures for Component C1: Manipulation Attacks (Conventional/Bloom side).

Standardized security metrics for evaluating document tampering, collusion, and
partitioning bypass attacks:
  ASR                          attack success rate = successful_bypasses / total_attempts (0..1)
  Chance                       random-guess floor without exploiting logic (0..1)
  Advantage                    attacker advantage = (ASR - chance) / (1 - chance) (0..1)
  Security level               1 - advantage (1.0 = completely protected, 0.0 = full bypass)
  Defense Effectiveness (DE)   risk reduction = (baseline_ASR - defended_ASR) / baseline_ASR
  Attack time                  wall-clock milliseconds of attack + verification bypass
  Collusion threshold          fewest colluding nodes needed to bypass verification
  Threshold share              collusion_threshold / total_nodes
"""
from __future__ import annotations

import time
from contextlib import contextmanager


def asr(successes: int, attempts: int) -> float:
    """Computes Attack Success Rate: successful bypasses / total attempts."""
    return successes / attempts if attempts else 0.0


def advantage(success_rate: float, chance: float = 0.0) -> float:
    """Computes Attacker Advantage: (ASR - chance) / (1 - chance)."""
    if not 0 <= chance < 1:
        raise ValueError("chance must be in [0, 1)")
    return max(0.0, (success_rate - chance) / (1 - chance))


def defense_effectiveness(baseline_asr: float | None, defended_asr: float) -> float | None:
    """Calculates Defense Effectiveness (DE) / Risk reduction:
    
    DE = (baseline_ASR - defended_ASR) / baseline_ASR
    Returns None if no baseline is provided to compare against.
    """
    if baseline_asr is None or baseline_asr <= 0:
        return None
    return max(0.0, (baseline_asr - defended_asr) / baseline_asr)


risk_reduction = defense_effectiveness


def measures(
    success_rate: float,
    chance: float = 0.0,
    baseline_asr: float | None = None,
    attack_ms: float | None = None,
    collusion_threshold: int | None = None,
    total_nodes: int | None = None,
    **extra,
) -> dict:
    """Builds the standardized security metrics dictionary for manipulation attacks.
    
    Returns all 8 required metrics:
    1. asr (Attack Success Rate)
    2. chance (Random-guess success baseline)
    3. advantage (Attacker advantage)
    4. security_level (Security level: 1 - advantage)
    5. risk_reduction (Defense Effectiveness / Risk reduction vs baseline)
    6. attack_ms (Attack time in milliseconds)
    7. collusion_threshold (Fewest colluding nodes needed to bypass)
    8. collusion_threshold_fraction (Collusion threshold as share of total nodes)
    """
    adv = advantage(success_rate, chance)
    de = defense_effectiveness(baseline_asr, success_rate)

    block = {
        "asr": round(success_rate, 4),
        "chance": round(chance, 4),
        "advantage": round(adv, 4),
        "security_level": round(1.0 - adv, 4),
        "risk_reduction": None if de is None else round(de, 4),
    }

    if attack_ms is not None:
        block["attack_ms"] = round(attack_ms, 1)

    if collusion_threshold is not None:
        block["collusion_threshold"] = int(collusion_threshold)
        if total_nodes and total_nodes > 0:
            block["collusion_threshold_fraction"] = round(collusion_threshold / total_nodes, 4)
    elif "collusion_threshold_fraction" in extra:
        block["collusion_threshold_fraction"] = extra.pop("collusion_threshold_fraction")

    block.update(extra)
    return block


@contextmanager
def timer():
    """Context manager for timing attack operations:
    
    with timer() as elapsed:
        # execute attack
    print(elapsed())  # wall-clock milliseconds
    """
    started = time.perf_counter()
    elapsed = [None]
    yield lambda: elapsed[0] if elapsed[0] is not None else (time.perf_counter() - started) * 1000
    elapsed[0] = (time.perf_counter() - started) * 1000
