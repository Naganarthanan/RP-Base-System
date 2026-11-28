"""Security measures shared by the inference attacks (Bloom filter system side).

Every inference attack reports the same core measures, so attacks and defences can be
compared on one scale:

  ASR               attack success rate = successes / attempts                 (0..1)
  Advantage         how far the attacker beats a random guess:
                    (ASR - chance) / (1 - chance), floored at 0                 (0..1)
  Security level    1 - advantage; 1 means the attacker learns nothing          (0..1)
  Risk reduction    (baseline ASR - ASR) / baseline ASR, against the no-defence
                    run; None when the baseline itself never succeeds
  Attack time       wall-clock milliseconds the attack took

Attack-specific measures (collusion threshold, link precision, k-anonymity, F1, ...) are
added by each attack next to these.
"""
import time
from contextlib import contextmanager


def asr(successes: int, attempts: int) -> float:
    return successes / attempts if attempts else 0.0


def advantage(success_rate: float, chance: float = 0.0) -> float:
    if not 0 <= chance < 1:
        raise ValueError("chance must be in [0, 1)")
    return max(0.0, (success_rate - chance) / (1 - chance))


def risk_reduction(baseline_asr: float | None, success_rate: float) -> float | None:
    if not baseline_asr:
        return None
    return (baseline_asr - success_rate) / baseline_asr


def measures(success_rate: float, chance: float = 0.0, baseline_asr: float | None = None,
             attack_ms: float | None = None, **extra) -> dict:
    """The core measure block for one attack outcome, plus any attack-specific extras."""
    adv = advantage(success_rate, chance)
    reduction = risk_reduction(baseline_asr, success_rate)
    block = {
        "asr": round(success_rate, 4),
        "chance": round(chance, 4),
        "advantage": round(adv, 4),
        "security_level": round(1 - adv, 4),
        "risk_reduction": None if reduction is None else round(reduction, 4),
    }
    if attack_ms is not None:
        block["attack_ms"] = round(attack_ms, 1)
    block.update(extra)
    return block


@contextmanager
def timer():
    """`with timer() as t: ...` then `t()` gives the elapsed milliseconds."""
    started = time.perf_counter()
    elapsed = [None]
    yield lambda: elapsed[0] if elapsed[0] is not None else (time.perf_counter() - started) * 1000
    elapsed[0] = (time.perf_counter() - started) * 1000


def attach_view_measures(result: dict, chance: float = 0.0) -> dict:
    """Add a measure block to every row of a run_on_views result, against its baseline.

    The headline `security` block is the worst row (highest ASR): a defence is only as
    strong as the node or coalition that gets furthest. A row's `attack_ms`, when the
    attack timed it, becomes that row's attack time.
    """
    base = result["baseline"]["success_rate"]
    result["baseline"]["security"] = measures(base, chance, attack_ms=result["baseline"].get("attack_ms"))
    for row in result["rows"]:
        row["security"] = measures(row["success_rate"], chance, base, row.get("attack_ms"))
    worst = max(result["rows"], key=lambda r: r["success_rate"])
    result["security"] = {**worst["security"], "worst_attacker": worst["label"]}
    return result
