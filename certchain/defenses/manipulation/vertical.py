"""Defence: Vertical (inter-block) partitioning  -  id "vertical".

Blue team (Component 2), evaluated against the Red team's "collusion" manipulation attack
on the Conventional system's chain. The live database is never modified.

Two variants are always reported side by side:
  "as proposed"  cross-reference with the neighbouring block only (Algorithm 1).
  "+ head pin"   refinement: every node also pins the newest block's hash.
"""
from __future__ import annotations

from ...attacks.manipulation.collusion_attack import SAMPLE_CERTIFICATE, simulate_single_collusion, tamper_document
from ..common import HashAnchor, NODES, canonical, systems
from . import partition as P

NAME = "Vertical partitioning (inter-block)"
MODEL_K = 2
DEFAULTS = {"strategy": "single_sequence", "nodes": len(NODES), "k": 2}


def _options(raw: dict | None) -> dict:
    opts = {**DEFAULTS, **(raw or {})}
    try:
        opts["nodes"], opts["k"] = int(opts["nodes"]), int(opts["k"])
    except (TypeError, ValueError):
        raise ValueError("nodes and k must be whole numbers") from None
    if opts["strategy"] not in P.STRATEGIES:
        raise ValueError(f"strategy must be one of {', '.join(P.STRATEGIES)}")
    if not 2 <= opts["nodes"] <= 9:
        raise ValueError("nodes must be between 2 and 9")
    if not 2 <= opts["k"] <= opts["nodes"]:
        raise ValueError("k must be between 2 and the number of nodes")
    return opts


def _load_chain():
    """Majority chain of the live Conventional system (read only), else a synthetic chain."""
    try:
        ledger = systems()["conventional"].config["ledger"]
        rows = ledger.rows(ledger.majority_node())
        if len(rows) >= 4:
            return rows, "conventional system ledger", ledger
    except Exception:
        pass
    return P.synthetic_chain(60), "synthetic chain (live ledger unavailable)", None


def _forged_anchor(ledger, target: int):
    """Forge the record at `target` with the attack team's own tamper_document()."""
    tx = ledger.record(target) if ledger is not None else None
    if not tx or tx.get("type") == "genesis":
        tx = SAMPLE_CERTIFICATE
    tampered, _ = tamper_document(tx, category="content")
    return canonical(HashAnchor().build(tampered)), tx.get("type", "record")


def _label(ledger, idx: int) -> str:
    tx = ledger.record(idx) if ledger is not None else None
    return tx["type"] if tx else "block"


def _scenario(label, plain, pinned, ledger, target, coalition, n, blocks) -> dict:
    forged, kind = _forged_anchor(ledger, target)
    names = plain.names
    out = {"label": label, "target_block": target, "record_type": kind,
           "colluders": [names[i] for i in sorted(coalition)], "variants": {}}

    full = P.PartitionedChain(blocks, n, P.FullReplication(), node_names=names)
    P.apply_collusion(full, coalition, target, forged)
    out["full_replication"] = {"forged_accepted": P.consensus_accepts(full, target, forged)}

    for key, tmpl in (("as_proposed", plain), ("head_pin", pinned)):
        chain = tmpl.clone()
        res = P.apply_collusion(chain, coalition, target, forged)
        v = chain.verify()
        out["variants"][key] = {
            "status": v["status"],
            "forged_accepted": v["status"] == "Blockchain Valid" and res["blocks_rewritten"] > 0,
            "first_finding": v["first"],
            "blocks_rewritten": res["blocks_rewritten"],
            "blocks_needed": res["blocks_needed"],
            "blocked_blocks": res["blocked_blocks"],
            "latency_ms": v["latency_ms"],
        }
    return out


def run_vertical(attack: str = "collusion", options: dict | None = None,
                 defense: str = "vertical", name: str = NAME) -> dict:
    if attack != "collusion":
        raise ValueError(f"vertical partitioning has not been evaluated against the {attack!r} attack yet")
    opts = _options(options)
    n, strategy = opts["nodes"], P.make_strategy(opts["strategy"], opts["k"])
    blocks, source, ledger = _load_chain()
    N, names = len(blocks), P.default_node_names(n)
    threshold = n // 2 + 1

    plain = P.PartitionedChain(blocks, n, strategy, head_pin=False, node_names=names)
    pinned = P.PartitionedChain(blocks, n, strategy, head_pin=True, node_names=names)

    # --- baseline vs defended, every coalition size ---
    base = P.baseline_asr(blocks, n)
    proposed = P.analyse(N, n, strategy, head_pin=False, model_k=MODEL_K)
    refined = P.analyse(N, n, strategy, head_pin=True, model_k=MODEL_K)
    matrix = [{
        "colluding": c,
        "baseline_asr": base[c - 1]["asr"],
        "asr": proposed[c - 1]["asr"],
        "asr_head_pin": refined[c - 1]["asr"],
        "worst_coalition_blocks": proposed[c - 1]["worst_coalition_blocks"],
        "coalitions_with_bypass": proposed[c - 1]["coalitions_with_bypass"],
        "coalitions": proposed[c - 1]["coalitions"],
        "model": proposed[c - 1]["model"],
    } for c in range(1, n + 1)]
    at = matrix[threshold - 1]

    # --- worked scenarios with the attack team's coalition (first `threshold` organisations) ---
    coalition = set(range(threshold))
    certs = [i for i in range(N) if _label(ledger, i) == "certificate.issue"]
    scenarios = []
    mid_pool = [i for i in range(1, N - n - 1) if _label(ledger, i) != "genesis"]
    if mid_pool:
        scenarios.append(_scenario("A record in the middle of the chain", plain, pinned, ledger,
                                   mid_pool[len(mid_pool) // 2], coalition, n, blocks))
    newest = certs[-1] if certs else N - 1
    tail_coalition = P.smallest_coalition_for(N, n, strategy, False, newest, threshold) or coalition
    scenarios.append(_scenario("The newest certificate (near the end of the chain)" if certs
                               else "The newest block", plain, pinned, ledger, newest, tail_coalition, n, blocks))

    # --- red-team reference: what their module reports on the same coalition ---
    red = None
    if n == len(NODES):
        r = simulate_single_collusion(num_colluding=threshold, system_type="conventional", total_nodes=n)
        red = {"status": r["status"], "asr": r["asr"], "consensus_hijacked": r["consensus_hijacked"]}

    # --- strategy comparison at the chosen node count ---
    strategies = []
    for key in P.STRATEGIES:
        s = P.make_strategy(key, opts["k"])
        pc = P.PartitionedChain(blocks, n, s, node_names=names)
        row_a = P.analyse(N, n, s, False)[threshold - 1]
        row_b = P.analyse(N, n, s, True)[threshold - 1]
        strategies.append({
            "strategy": key, "label": s.label,
            "storage_percent": pc.storage_profile()["percent_of_full"],
            "asr": row_a["asr"], "asr_head_pin": row_b["asr"],
            "worst_coalition_blocks": row_a["worst_coalition_blocks"],
            "false_positive": pc.verify()["status"] != "Blockchain Valid",
            "selected": key == opts["strategy"],
        })

    # --- node-count sweep (more nodes -> lower collusion success) ---
    sweep = []
    for m in (3, 4, 5, 7, 9):
        s = P.make_strategy(opts["strategy"], min(opts["k"], m))
        rows = P.analyse(N, m, s, False)
        sweep.append({"nodes": m, "asr_c2": rows[1]["asr"], "model_c2": (2 / m) ** MODEL_K,
                      "asr_majority": rows[m // 2]["asr"]})

    # --- the four evaluation metrics ---
    validation = P.validate_physically(plain)
    profile = plain.storage_profile()
    metrics = {
        "detection_rate": validation["detection_rate"],
        "false_positive_rate": 0.0 if plain.verify()["status"] == "Blockchain Valid" else 1.0,
        "storage_percent_of_full": profile["percent_of_full"],
        "blocks_per_node": profile["blocks_per_node"],
        "latency_ms": P.measure_latency(plain),
        "latency_target_ms": 500,
        "model_agreement": validation["model_agreement"],
        "physical_cases": validation["cases"],
    }

    exposed = P.exposed_blocks(N, n, strategy, False, coalition)
    findings = []
    if exposed:
        findings.append(
            f"As proposed, the newest {len(exposed)} block(s) can still be forged by the first {threshold} "
            f"organisations (blocks {', '.join(map(str, exposed))}): the newest block has no successor on another "
            f"node to cross-reference it. Genuine certificates sit at the end of the live chain, so they are "
            f"inside this window. The head-pin refinement closes it.")
    if matrix[0]["asr"] > matrix[0]["baseline_asr"]:
        findings.append(
            "Regression to fix: as proposed, even ONE organisation that holds the newest block can forge it, "
            "which the fully replicated majority vote would have outvoted. Head pinning removes this.")
    findings.append(
        "Pinning the newest hash on every node means a rewrite needs ALL organisations, not just the holders "
        "of the rewritten blocks." if at["asr_head_pin"] < at["asr"] else
        "Head pinning adds no further protection at this node count.")
    if opts["strategy"] == "single_odd":
        findings.append("Single-odd only permutes which node comes next; against a non-adaptive coalition it "
                        "offers the same collusion resistance as single-sequence.")
    findings.append("The model R(r) = (c/n)^k assumes independent block placement. A rewrite cascades through "
                    "every later block, so the exact success rate is far lower than the model except at the tail.")

    return {
        "check": "manipulation", "layout": "partitioning", "defense": defense, "defense_name": name,
        "attack": "collusion",
        "config": {"strategy": opts["strategy"], "strategy_label": strategy.label, "nodes": n, "k": opts["k"],
                   "chain_blocks": N, "chain_source": source, "threshold": threshold, "model_k": MODEL_K,
                   "node_names": names},
        "headline": {"colluding": threshold, "baseline_asr": at["baseline_asr"], "asr": at["asr"],
                     "asr_head_pin": at["asr_head_pin"]},
        "red_team_reference": red,
        "scenarios": scenarios, "matrix": matrix, "strategies": strategies, "node_sweep": sweep,
        "metrics": metrics, "findings": findings,
        "conclusion": (
            f"With the chain split over {n} nodes ({strategy.label}), {threshold} colluding organisations succeed "
            f"on {at['asr'] * 100:.1f}% of target blocks instead of 100% on the fully replicated chain; they can no "
            f"longer rewrite a record without also controlling the nodes that hold every later block. "
            f"With head pinning the figure is {at['asr_head_pin'] * 100:.1f}% (only an all-node coalition succeeds)."),
    }