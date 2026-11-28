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
SUPPORTED_ATTACKS = {
    "collusion": "Collusion among organisations",
    "sequence_rewrite_collusion": "Sequence-Rewrite Collusion",
    "odd_node_hijack": "Odd-Node Hijack",
    "k_group_tampering": "K-Group Tampering",
}


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
    if attack not in SUPPORTED_ATTACKS:
        raise ValueError(f"vertical partitioning has not been evaluated against the {attack!r} attack yet")
    attack_name = SUPPORTED_ATTACKS[attack]
    opts = _options(options)
    n, strategy = opts["nodes"], P.make_strategy(opts["strategy"], opts["k"])
    model_k = opts["k"] if opts["strategy"] == "k_sequence" else MODEL_K
    blocks, source, ledger = _load_chain()
    N, names = len(blocks), P.default_node_names(n)
    threshold = n // 2 + 1

    plain = P.PartitionedChain(blocks, n, strategy, head_pin=False, node_names=names)
    pinned = P.PartitionedChain(blocks, n, strategy, head_pin=True, node_names=names)

    # --- baseline vs defended, every coalition size ---
    base = P.baseline_asr(blocks, n)
    proposed = P.analyse(N, n, strategy, head_pin=False, model_k=model_k)
    refined = P.analyse(N, n, strategy, head_pin=True, model_k=model_k)
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

    # --- worked scenarios tailored to the selected attack and defense ---
    coalition = set(range(threshold))
    certs = [i for i in range(N) if _label(ledger, i) == "certificate.issue"]
    scenarios = []
    mid_pool = [i for i in range(1, N - n - 1) if _label(ledger, i) != "genesis"]
    newest = certs[-1] if certs else N - 1
    tail_coalition = P.smallest_coalition_for(N, n, strategy, False, newest, threshold) or coalition

    if attack == "odd_node_hijack":
        odd_mid = [i for i in mid_pool if i % 2 == 1]
        mid_target = odd_mid[len(odd_mid) // 2] if odd_mid else (mid_pool[len(mid_pool) // 2] if mid_pool else 1)
        odd_holders = sorted({plain.holders(i)[0] for i in range(1, N, 2)})
        odd_coalition = set(odd_holders[:threshold]) if len(odd_holders) >= n else (set(odd_holders) or coalition)
        odd_tail = newest if newest % 2 == 1 else (newest - 1 if newest > 1 else newest)
        odd_tail_coalition = P.smallest_coalition_for(N, n, strategy, False, odd_tail, threshold) or odd_coalition
        scenarios.append(_scenario("An intermediate odd-numbered block (Odd-Node Hijack)", plain, pinned, ledger,
                                   mid_target, odd_coalition, n, blocks))
        scenarios.append(_scenario("A tail odd-numbered block (near the end of the chain)", plain, pinned, ledger,
                                   odd_tail, odd_tail_coalition, n, blocks))
    elif attack == "k_group_tampering":
        if mid_pool:
            mid_target = mid_pool[len(mid_pool) // 2]
            group_holders = list(plain.holders(mid_target))
            partial_group = set(group_holders[:max(1, len(group_holders) - 1)])
            scenarios.append(_scenario("Partial k-group compromise (within group)", plain, pinned, ledger,
                                       mid_target, partial_group, n, blocks))
        tail_group = set(plain.holders(newest))
        if len(tail_group) >= n and len(tail_coalition) < n:
            tail_group = tail_coalition
        scenarios.append(_scenario("Full k-group boundary (newest block near tail)", plain, pinned, ledger,
                                   newest, tail_group, n, blocks))
    elif attack == "sequence_rewrite_collusion":
        if mid_pool:
            mid_target = mid_pool[len(mid_pool) // 2]
            h0 = plain.holders(mid_target)[0]
            seq_coalition = {h0, (h0 + 1) % n} if n > 2 else {h0}
            scenarios.append(_scenario("Sequential suffix rewrite (middle block)", plain, pinned, ledger,
                                       mid_target, seq_coalition, n, blocks))
        scenarios.append(_scenario("Tail sequence block (near the end of the chain)", plain, pinned, ledger,
                                   newest, tail_coalition, n, blocks))
    else:
        if mid_pool:
            scenarios.append(_scenario("A record in the middle of the chain", plain, pinned, ledger,
                                       mid_pool[len(mid_pool) // 2], coalition, n, blocks))
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
        sweep.append({"nodes": m, "asr_c2": rows[1]["asr"], "model_c2": (2 / m) ** model_k,
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
    if opts["strategy"] == "k_sequence":
        findings.append(f"k-sequence (k={opts['k']}) replicates each block across {opts['k']} consecutive nodes, "
                        f"raising storage to {profile['percent_of_full']}% while catching partial-group edits via replica mismatch.")
    findings.append(f"The model R(r) = (c/n)^{model_k} assumes independent block placement. A rewrite cascades through "
                    "every later block, so the exact success rate is far lower than the model except at the tail.")

    from certchain.attacks.manipulation.measures import measures
    security = measures(
        success_rate=at["asr"],
        chance=0.0,
        baseline_asr=at["baseline_asr"],
        attack_ms=metrics["latency_ms"],
        collusion_threshold=threshold,
        total_nodes=n,
    )

    # Inference-aligned node views and attack_support breakdown for unified reporting
    node_views = [{
        "node": names[nd],
        "blocks_stored": len(plain.stores[nd]),
        "total_blocks": N,
        "storage_percentage": round(100.0 * len(plain.stores[nd]) / N, 1),
        "rule": f"idx mod {n} ({strategy.label})",
    } for nd in range(n)]

    baseline_row = {
        "label": "Full replication (no defence)",
        "nodes": names,
        "visibility_percentage": 100.0,
        "success_rate": at["baseline_asr"],
        "security": measures(
            success_rate=at["baseline_asr"],
            chance=0.0,
            baseline_asr=None,
            collusion_threshold=threshold,
            total_nodes=n,
        ),
        "detail": (
            f"Every node holds 100% of blocks; {threshold} of {n} colluding nodes reach "
            f"majority consensus and rewrite any target block."
        ),
    }
    attack_rows = []
    for row in matrix:
        c_size = row["colluding"]
        held_union = len({idx for nd in range(c_size) for idx in plain.stores[nd]})
        vis_pct = round(100.0 * held_union / N, 1)
        row_base = row["baseline_asr"] if row["baseline_asr"] > 0 else 1.0
        attack_rows.append({
            "label": f"{c_size} colluding",
            "nodes": names[:c_size],
            "visibility_percentage": vis_pct,
            "success_rate": row["asr"],
            "security": measures(
                success_rate=row["asr"],
                chance=0.0,
                baseline_asr=row_base,
                collusion_threshold=threshold,
                total_nodes=n,
            ),
            "detail": (
                f"{row['worst_coalition_blocks']} of {N} tail blocks forgeable in worst case; "
                f"head-pin ASR {round(row['asr_head_pin'] * 100, 1)}%."
            ),
        })

    conclusion_text = (
        f"Against {attack_name}, with the chain split over {n} nodes ({strategy.label}), {threshold} colluding organisations succeed "
        f"on {at['asr'] * 100:.1f}% of target blocks instead of 100% on the fully replicated chain; they can no "
        f"longer rewrite a record without also controlling the nodes that hold every later block. "
        f"With head pinning the figure is {at['asr_head_pin'] * 100:.1f}% (only an all-node coalition succeeds)."
    )

    attack_support = {
        "status": "executed",
        "requested_attack": attack,
        "attack_executed": True,
        "node_views": node_views,
        "result": {
            "attack": attack,
            "metric": f"Attack success rate under {strategy.label} ({attack_name})",
            "chance": 0.0,
            "baseline": baseline_row,
            "rows": attack_rows,
            "security": security,
            "conclusion": conclusion_text,
        },
    }

    return {
        "check": "manipulation", "layout": "partitioning", "defense": defense, "defense_name": name,
        "attack": attack, "attack_name": attack_name,
        "attack_supported": True, "attack_executed": True,
        "attack_support": attack_support, "node_views": node_views,
        "security": security,
        "config": {"strategy": opts["strategy"], "strategy_label": strategy.label, "nodes": n, "k": opts["k"],
                   "chain_blocks": N, "chain_source": source, "threshold": threshold, "model_k": model_k,
                   "node_names": names},
        "headline": {"colluding": threshold, "baseline_asr": at["baseline_asr"], "asr": at["asr"],
                     "asr_head_pin": at["asr_head_pin"]},
        "red_team_reference": red,
        "scenarios": scenarios, "matrix": matrix, "strategies": strategies, "node_sweep": sweep,
        "metrics": metrics, "findings": findings,
        "conclusion": conclusion_text,
    }


def run_single_odd(attack: str = "collusion", options: dict | None = None) -> dict:
    opts = {**(options or {}), "strategy": "single_odd"}
    return run_vertical(attack, opts, defense="single_odd", name="Single-odd partitioning")


def run_k_sequence(attack: str = "collusion", options: dict | None = None) -> dict:
    opts = {**(options or {}), "strategy": "k_sequence"}
    return run_vertical(attack, opts, defense="k_sequence", name="k-sequence partitioning")