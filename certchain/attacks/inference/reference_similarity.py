"""Reference-assisted partial Bloom-filter inference (known-record attack).

Can an attacker infer a hidden academic attribute (the programme) from a Bloom filter,
or from only a fragment of one, by comparing it with records whose programme is known?

Pipeline (one function per stage, so each can be tested on its own):

  1. Synthetic dataset   - fictional student records, balanced over IT / SE / CS.
  2. Encoding            - each record goes through the Bloom filter system's own encoder
                           (same key, m, k and padding), as the verification system would.
  3. Reference / target  - a stratified split. The attacker gets the reference filters
                           WITH their labels and the target filters WITHOUT labels.
  4. Observation         - the filter is split into n equal horizontal fragments and the
                           attacker sees only fragment B1 (n = 1..5 -> 100%, 50%, 33%, 25%, 20%).
  5. Similarity          - Hamming similarity between the target fragment and the same
                           fragment of every reference record.
  6. Aggregation         - Score(C) = mean similarity to the references of class C.
  7. Decision            - predicted class = argmax_C Score(C).
  8. Evaluation          - only now is the target's ground truth revealed, to compute
                           accuracy, precision, recall, F1 and the confusion matrix.

The attacker never uses the Bloom key: it only compares bits it can observe. The same
algorithm runs at every visibility level, so visibility is the only variable that changes.
Horizontal partitioning itself belongs to the defence side; here the fragment is only
simulated so the attack can be measured at each visibility level.
"""
import random

from ...anchors import record_items
from ..common import field_item, systems

CLASSES = {
    "IT": "BSc (Hons) Information Technology",
    "SE": "BSc (Hons) Software Engineering",
    "CS": "BSc (Hons) Computer Science",
}
PARTITIONS = (1, 2, 3, 4, 5)   # E1 full, E2 1/2, E3 1/3, E4 1/4, E5 1/5
RECORDS_PER_CLASS = 100        # N = 300
REFERENCE_SHARE = 0.5          # half of each class is known to the attacker
FRAGMENT_POSITION = 0          # the attacker organisation holds B1
SEED = 2026                    # fixed seed so a run can be repeated exactly
SAMPLE_RESULTS = 8             # per-target result rows returned for each configuration

_FIRST = ["Nila", "Kavin", "Aisha", "Dilan", "Priya", "Ravi", "Tharun", "Meena", "Arun", "Sana"]
_LAST = ["Kumar", "Perera", "Silva", "Nadarajah", "Farook", "Selvam", "Rajan", "Fernando"]
_TOWNS = ["Jaffna", "Vavuniya", "Kilinochchi", "Mannar", "Mullaitivu", "Trincomalee"]
_INTAKES = ["2025 January", "2025 July", "2026 January"]


# 1. Synthetic dataset --------------------------------------------------------------

def synthetic_records(rng: random.Random, per_class: int = RECORDS_PER_CLASS) -> list[dict]:
    """Fictional student records with the same fields as a real student.upsert.

    Every field except the programme is drawn the same way for every class, so the
    programme is the only thing that can separate the classes.
    """
    records = []
    for label, programme in CLASSES.items():
        for _ in range(per_class):
            n = len(records) + 1
            data = {
                "id": f"SYN{n:05d}",
                "name": f"{rng.choice(_FIRST)} {rng.choice(_LAST)}",
                "email": f"syn{n:05d}@synthetic.test",
                "phone": f"+94 7{rng.randint(0, 9)} {rng.randint(100, 999)} {rng.randint(1000, 9999)}",
                "nic": f"{rng.randint(1998, 2004)}{rng.randint(1, 866):03d}{rng.randint(10000, 99999)}",
                "dob": f"{rng.randint(1998, 2004)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
                "address": f"{rng.randint(1, 200)} Main Street, {rng.choice(_TOWNS)}",
                "programme": programme,
                "intake": rng.choice(_INTAKES),
                "status": "active",
            }
            records.append({"id": data["id"], "label": label, "tx": {"type": "student.upsert", "data": data}})
    return records


# 2. Encoding (the verification system's side) ---------------------------------------

def encode(impl, tx: dict, rng: random.Random) -> int:
    """Encode one record exactly as BloomAnchor.build does, with seeded padding.

    Returns the filter as an int where bit p is Bloom position p.
    """
    items = record_items(tx)
    bloom = impl.new_filter()
    for item in items:
        bloom.add(item)
    for _ in range(impl.PAD_TO - len(items)):
        bloom.add("pad=" + rng.getrandbits(128).to_bytes(16, "big").hex())
    return int.from_bytes(bloom.bits, "little")


# 3. Reference / target split --------------------------------------------------------

def split(records: list[dict], rng: random.Random, share: float = REFERENCE_SHARE):
    """Stratified split: the same share of every class becomes reference records."""
    references, targets = [], []
    for label in CLASSES:
        group = [r for r in records if r["label"] == label]
        rng.shuffle(group)
        cut = int(len(group) * share)
        references += group[:cut]
        targets += group[cut:]
    return references, targets


# 4. Observation: horizontal fragment ------------------------------------------------

def fragment_bounds(m: int, partitions: int, position: int = FRAGMENT_POSITION) -> tuple[int, int]:
    """Bit range [start, end) of fragment B(position+1) when m bits are split n ways."""
    if not 1 <= partitions <= m or not 0 <= position < partitions:
        raise ValueError("invalid partition configuration")
    return position * m // partitions, (position + 1) * m // partitions


def observe(bits: int, start: int, end: int) -> int:
    """The only part of a filter the attacker organisation can see."""
    return (bits >> start) & ((1 << (end - start)) - 1)


# 5-7. Inference engine (sees fragments and reference labels only) -------------------

def hamming_similarity(x: int, y: int, length: int) -> float:
    """Percentage of the `length` compared bit positions where x and y agree."""
    return (length - (x ^ y).bit_count()) / length * 100


def class_scores(target: int, references: list[tuple[int, str]], length: int) -> dict:
    """Score(C) = (1/N_C) * sum of Similarity(T, R_i) over the references R_i of class C."""
    sums, counts = {}, {}
    for fragment, label in references:
        sums[label] = sums.get(label, 0.0) + hamming_similarity(target, fragment, length)
        counts[label] = counts.get(label, 0) + 1
    return {label: sums[label] / counts[label] for label in sums}


def predict(scores: dict) -> str:
    """argmax over the class scores; ties go to the first class name alphabetically."""
    return max(sorted(scores), key=lambda label: scores[label])


# 8. Evaluation (the only stage that sees ground truth) ------------------------------

def evaluate(predicted: list[str], actual: list[str], labels: list[str]) -> dict:
    confusion = {a: {p: 0 for p in labels} for a in labels}
    for p, a in zip(predicted, actual):
        confusion[a][p] += 1
    per_class = {}
    for c in labels:
        tp = confusion[c][c]
        fp = sum(confusion[a][c] for a in labels if a != c)
        fn = sum(confusion[c][p] for p in labels if p != c)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[c] = {"precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}
    correct = sum(p == a for p, a in zip(predicted, actual))
    return {
        "accuracy": round(correct / len(actual), 4) if actual else 0.0,
        "correct": correct,
        "total": len(actual),
        "macro_precision": round(sum(v["precision"] for v in per_class.values()) / len(labels), 4),
        "macro_recall": round(sum(v["recall"] for v in per_class.values()) / len(labels), 4),
        "macro_f1": round(sum(v["f1"] for v in per_class.values()) / len(labels), 4),
        "per_class": per_class,
        "confusion": confusion,
    }


# Experiment runner -----------------------------------------------------------------

def run_experiment(impl, seed: int = SEED, per_class: int = RECORDS_PER_CLASS,
                   partitions=PARTITIONS, position: int = FRAGMENT_POSITION) -> dict:
    rng = random.Random(seed)
    records = synthetic_records(rng, per_class)
    for r in records:
        r["bits"] = encode(impl, r["tx"], rng)
    references, targets = split(records, rng)
    labels = list(CLASSES)
    m = impl.M

    # Ground truth is kept apart from what the attacker receives.
    ground_truth = {t["id"]: t["label"] for t in targets}

    experiments = []
    for n in partitions:
        start, end = fragment_bounds(m, n, position)
        length = end - start
        known = [(observe(r["bits"], start, end), r["label"]) for r in references]
        unknown = [(t["id"], observe(t["bits"], start, end)) for t in targets]  # no labels

        results = []
        for target_id, fragment in unknown:
            scores = class_scores(fragment, known, length)
            results.append({"target_id": target_id, "scores": scores, "predicted": predict(scores)})

        # Evaluation: ground truth is looked up only after every prediction is made.
        for r in results:
            r["ground_truth"] = ground_truth[r["target_id"]]
            r["correct"] = r["predicted"] == r["ground_truth"]
        metrics = evaluate([r["predicted"] for r in results], [r["ground_truth"] for r in results], labels)

        # Evaluation-side diagnostic (uses the key, never given to the attacker): how many of
        # each programme's k Bloom bits fall inside the observed fragment. A class with 0 bits
        # in the fragment leaves no signal there, which explains low accuracy at small fragments.
        signal = {label: sum(start <= p < end for p in set(impl.new_filter().positions(
            field_item("student.upsert", "programme", programme)))) for label, programme in CLASSES.items()}

        experiments.append({
            "experiment": f"E{n}",
            "configuration": "Full Bloom filter" if n == 1 else f"1/{n} fragment",
            "partitions": n,
            "fragment": f"B{position + 1}",
            "fragment_bits": [start, end],
            "observed_bits": length,
            "visibility_ratio": round(length / m, 4),
            "programme_bits_in_fragment": signal,
            **metrics,
            "sample_results": [{
                "target_id": r["target_id"],
                "scores": {k: round(v, 3) for k, v in r["scores"].items()},
                "predicted": r["predicted"],
                "ground_truth": r["ground_truth"],
                "correct": r["correct"],
            } for r in results[:SAMPLE_RESULTS]],
        })

    return {
        "config": {
            "bloom_m": m,
            "bloom_k": impl.K,
            "items_per_filter": impl.PAD_TO,
            "target_attribute": "programme",
            "classes": CLASSES,
            "records": len(records),
            "reference_records": len(references),
            "target_records": len(targets),
            "fragment_position": f"B{position + 1}",
            "similarity": "Hamming",
            "aggregation": "mean per class",
            "seed": seed,
        },
        "chance_accuracy": round(1 / len(labels), 4),
        "experiments": experiments,
    }


def run_inference_reference_similarity() -> dict:
    impl = systems()["bloom"].config["anchor"]
    data = run_experiment(impl)
    full, smallest = data["experiments"][0], data["experiments"][-1]
    return {
        "check": "inference",
        "attack": "reference_similarity",
        "system": "bloom",
        **data,
        "scenario": (
            "An attacker organisation knows the programme of some records and sees their Bloom "
            "filters. It compares an unknown record's filter, or only its own fragment of it, "
            "with those references to guess the hidden programme. No key is used."
        ),
        "conclusion": (
            f"With the full filter the attack inferred the programme for {full['accuracy']:.0%} of "
            f"targets (macro F1 {full['macro_f1']:.2f}); seeing only "
            f"{smallest['visibility_ratio']:.0%} of the filter it reached {smallest['accuracy']:.0%} "
            f"(macro F1 {smallest['macro_f1']:.2f}), against {data['chance_accuracy']:.0%} for a "
            f"random guess. Accuracy above chance at any visibility is residual leakage."
        ),
    }
