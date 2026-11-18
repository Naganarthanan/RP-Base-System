import json
import sqlite3
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from certchain import create_app, create_site  # noqa: E402
from certchain.seed import make_nic  # noqa: E402

NILA_NIC = make_nic("2001-03-14", True, "12345")  # UNI20260001


@pytest.fixture(params=["conventional", "bloom"])
def system(request):
    return request.param


@pytest.fixture
def app(tmp_path, system):
    return create_app(data_dir=tmp_path, env="development", system=system)


def login(app, username, password):
    client = app.test_client()
    res = client.post("/api/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.get_json()
    client.csrf = res.get_json()["csrf"]
    return client


def write(client, method, path, **body):
    return getattr(client, method)(path, json=body, headers={"X-CSRF-Token": client.csrf})


@pytest.fixture
def admin(app):
    return login(app, "admin.dev", "Admin@123")


@pytest.fixture
def faculty(app):
    return login(app, "faculty.dev", "Faculty@123")


@pytest.fixture
def student(app):
    return login(app, "student.dev", "Student@123")


# ---- storage model --------------------------------------------------------
def test_chain_stores_only_anchors_not_readable_records(app, tmp_path):
    """Block anchors must not carry readable personal data; records live off-chain."""
    anchors = [r[0] for r in sqlite3.connect(tmp_path / "registry.db").execute("SELECT anchor FROM blocks")]
    blob = "".join(anchors)
    for secret in ("Nila Kanagaratnam", NILA_NIC, "Temple Road", "Dean's List"):
        assert secret not in blob, f"{secret!r} appears in a block anchor"
    tables = {r[0] for r in sqlite3.connect(tmp_path / "registry.db")
              .execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert tables == {"blocks", "records", "users"}


def test_bloom_anchor_hides_fields_but_hash_anchor_exposes_them(app, system):
    """The two systems differ exactly in whether a field hash can be recomputed."""
    from certchain.anchors import canonical, sha256

    tx = {"type": "student.upsert", "data": {"programme": "BSc (Hons) Information Technology"},
          "actor": "t", "at": "2026-01-01T00:00:00+00:00"}
    anchor = app.config["anchor"].build(tx)
    exposed = json.dumps(anchor).find(sha256(canonical("BSc (Hons) Information Technology"))) >= 0
    assert exposed is (system == "conventional")


def test_records_rebuilt_only_when_they_match_their_anchor(app, admin, tmp_path, system):
    assert write(admin, "post", "/api/certificates", student_id="UNI20260002", title="Merit").status_code == 201
    app.config["ledger"].close()
    # Corrupt one off-chain record so it no longer matches its anchor.
    db = sqlite3.connect(tmp_path / "registry.db")
    idx, tx = db.execute("SELECT idx, tx FROM records WHERE tx LIKE '%student.upsert%' ORDER BY idx LIMIT 1").fetchone()
    doc = json.loads(tx)
    doc["data"]["name"] = "Tampered Name"
    db.execute("UPDATE records SET tx=? WHERE idx=?", (json.dumps(doc, sort_keys=True, separators=(",", ":")), idx))
    db.commit()
    db.close()

    reopened = create_app(data_dir=tmp_path, env="development", system=system)
    state = reopened.config["state"]
    assert reopened.config["ledger"].last_audit["failed"] == [idx]
    assert "Tampered Name" not in {s["name"] for s in state.students.values()}
    assert any(c["title"] == "Merit" for c in state.certificates.values())


# ---- authentication and access control ------------------------------------
def test_login_failure_and_throttle(app):
    client = app.test_client()
    for _ in range(5):
        assert client.post("/api/login", json={"username": "admin.dev", "password": "wrong"}).status_code == 401
    assert client.post("/api/login", json={"username": "admin.dev", "password": "Admin@123"}).status_code == 429


def test_dev_login_available_only_in_development(tmp_path, system):
    app = create_app(data_dir=tmp_path, env="development", system=system)
    assert app.test_client().post("/api/dev-login", json={"username": "admin.dev"}).status_code == 200
    prod = create_app(data_dir=tmp_path / "prod", env="production", system=system)
    client = prod.test_client()
    assert client.post("/api/dev-login", json={"username": "admin.dev"}).status_code == 404
    assert client.get("/api/session").get_json()["dev_accounts"] == []
    assert not prod.config["state"].students, "production must not contain demo data"


def test_endpoints_require_auth_and_csrf(app, admin):
    assert app.test_client().get("/api/students").status_code == 401
    assert admin.post("/api/certificates", json={"student_id": "UNI20260001", "title": "X"}).status_code == 403


def test_student_sees_only_own_record(student):
    assert student.get("/api/students/UNI20260001/record").status_code == 200
    assert student.get("/api/students/UNI20260002/record").status_code == 403
    assert student.get("/api/students").status_code == 403
    assert student.get("/api/chain/status").status_code == 403


def test_faculty_is_limited_to_assigned_courses(faculty):
    roster = faculty.get("/api/courses/IT1010/roster").get_json()
    assert "nic" not in roster["rows"][0]["student"]
    assert faculty.get("/api/courses/IT1020/roster").status_code == 403
    assert faculty.get("/api/students/UNI20260001/record").status_code == 403


def test_marks_update_keeps_history_and_validates(app, faculty):
    res = write(faculty, "put", "/api/marks", student_id="UNI20260001", course_code="IT1010", coursework=50, exam=50)
    assert res.get_json()["total"] == 50 and res.get_json()["grade"] == "C"
    assert len(app.config["state"].marks[("UNI20260001", "IT1010")]["history"]) == 2
    assert write(faculty, "put", "/api/marks", student_id="UNI20260001", course_code="IT1010",
                 coursework=101, exam=1).status_code == 400


def test_password_change(app, student):
    assert write(student, "post", "/api/password", current="nope", new="Longenough123").status_code == 400
    assert write(student, "post", "/api/password", current="Student@123", new="Longenough123").status_code == 200
    login(app, "student.dev", "Longenough123")


# ---- certificates and the blockchain --------------------------------------
def test_certificate_verify_and_revoke(app, admin):
    client = app.test_client()
    good = {"id": "CERT-2026-0001", "code": "DEMO-NILA-2026".upper()}
    assert client.post("/api/public/verify", json=good).get_json()["result"] == "valid"
    assert client.post("/api/public/verify", json={**good, "code": "WRONG"}).get_json()["result"] == "not_found"
    assert write(admin, "post", "/api/certificates/CERT-2026-0001/revoke", reason="Issued in error").status_code == 200
    assert client.post("/api/public/verify", json=good).get_json()["result"] == "revoked"


def test_public_verify_detects_a_tampered_record(app, admin):
    client = app.test_client()
    good = {"id": "CERT-2026-0001", "code": "DEMO-NILA-2026"}
    assert client.post("/api/public/verify", json=good).get_json()["result"] == "valid"
    cert = app.config["state"].certificates["CERT-2026-0001"]
    tx = app.config["ledger"].record(cert["block"])
    tx["data"]["title"] = "Forged Award"
    app.config["ledger"].overwrite_record(cert["block"], tx)
    assert client.post("/api/public/verify", json=good).get_json()["result"] == "tampered"


def test_block_view_is_admin_only(admin, faculty):
    res = admin.get("/api/chain/blocks/4")
    assert res.status_code == 200 and res.get_json()["verified"] is True
    assert admin.get("/api/chain/blocks/99999").status_code == 404
    assert faculty.get("/api/chain/blocks/4").status_code == 403


def test_tampering_is_detected_and_repaired(app, admin):
    assert admin.get("/api/chain/status").get_json()["healthy"] is True
    res = write(admin, "post", "/api/dev/tamper", node="Audit-Office-Node", idx=3).get_json()["status"]
    broken = res["nodes"][2]
    assert (res["healthy"], res["has_majority"], broken["valid"], broken["bad_block"]) == (False, True, False, 3)
    repaired = write(admin, "post", "/api/chain/repair").get_json()
    assert repaired["repaired"] == ["Audit-Office-Node"] and repaired["status"]["healthy"] is True


def test_writes_stop_without_a_majority(app, admin):
    ledger = app.config["ledger"]
    with ledger.db:
        ledger.db.execute("DELETE FROM blocks WHERE node='Audit-Office-Node' AND idx=(SELECT MAX(idx) FROM blocks)")
        ledger.db.execute("UPDATE blocks SET hash='forged' WHERE node='Academic-Board-Node' "
                          "AND idx=(SELECT MAX(idx) FROM blocks)")
    assert write(admin, "post", "/api/certificates", student_id="UNI20260002", title="Blocked").status_code == 503


# ---- the combined site and the security check -----------------------------
@pytest.fixture
def site(tmp_path):
    return create_site(data_dir=tmp_path, env="development")


def test_site_mounts_both_systems(site):
    client = site.test_client()
    assert client.get("/").status_code == 200
    assert client.get("/security").status_code == 200
    assert client.get("/conventional/api/session").get_json()["system"] == "conventional"
    assert client.get("/bloom/api/session").get_json()["system"] == "bloom"
    assert client.get("/nope").status_code == 404


def test_manipulation_check_separates_the_two_systems(site):
    rows = {r["system"]: r for r in site.test_client().post("/api/security/manipulation").get_json()["rows"]}
    assert rows["conventional"]["forgery_accepted"] is True
    assert rows["bloom"]["forgery_accepted"] is False


def test_inference_check_separates_the_two_systems(site):
    rows = {r["system"]: r for r in site.test_client().post("/api/security/inference").get_json()["rows"]}
    assert rows["conventional"]["confirmed"] >= 1 and rows["conventional"]["verdict"] == "leaks"
    assert rows["bloom"]["confirmed"] == 0 and rows["bloom"]["verdict"] == "resists"


def test_security_check_is_throttled_in_production(tmp_path):
    # Development runs the checks unthrottled; production keeps a per-minute limit.
    prod = create_site(data_dir=tmp_path, env="production")
    client = prod.test_client()
    codes = [client.post("/api/security/inference").status_code for _ in range(8)]
    assert 429 in codes


def test_security_check_is_unthrottled_in_development(site):
    client = site.test_client()
    codes = [client.post("/api/security/inference").status_code for _ in range(10)]
    assert 429 not in codes


def test_collusion_attack_runs_on_the_bloom_system(site):
    data = site.test_client().post("/api/security/collusion").get_json()
    assert data["system"] == "bloom"
    assert data["threshold"] == 2 and data["nodes"] == 3
    matrix = {m["colluding"]: m["blocks_exposed"] for m in data["matrix"]}
    assert matrix[1] == 0 and matrix[2] == data["blocks_exposed"] and data["blocks_exposed"] > 0


def test_manipulation_collusion_attack(site):
    data = site.test_client().post("/api/security/manipulation_collusion").get_json()
    assert data["check"] == "manipulation" and data["attack"] == "collusion"
    assert data["threshold"] == 2 and data["nodes"] == 3
    matrix = {m["colluding"]: m for m in data["matrix"]}
    assert matrix[1]["status"] == "Failure" and matrix[1]["asr"] == 0.0
    assert matrix[2]["status"] == "Success" and matrix[2]["asr"] == 1.0
    assert matrix[3]["status"] == "Success" and matrix[3]["asr"] == 1.0


def test_pattern_mining_attack_links_records_on_the_bloom_system(site):
    data = site.test_client().post("/api/security/pattern_mining").get_json()
    assert data["system"] == "bloom"
    # Records that share low-entropy fields (e.g. the six students) must link into a group.
    assert data["largest_cluster"] >= 6
    assert 0 < data["linkable_blocks"] <= data["total_blocks"]
    assert data["clusters"] == len(data["rows"]) or len(data["rows"]) == 6


# ---- inference defence ----------------------------------------------------
def test_sequential_partitioning_round_trip():
    from certchain.anchors import BloomAnchor
    from certchain.defenses.inference import partition_anchor, reconstruct_filter

    key = b"partition-test-key"
    impl = BloomAnchor(key)
    tx = {"type": "student.upsert", "data": {"programme": "Software Engineering"},
          "actor": "test", "at": "2026-01-01T00:00:00+00:00"}
    anchor = impl.build(tx)
    partitions = partition_anchor(anchor, key, 3, ("Node-A", "Node-B", "Node-C"), record_id=17)

    assert len(partitions) == 3
    assert [p["nodes"] for p in partitions] == [["Node-A"], ["Node-B"], ["Node-C"]]
    assert all(p["strategy"] == "sequential" for p in partitions)
    assert all(p["placement"] == "single_copy" for p in partitions)
    assert all(p["replication_factor"] == 1 for p in partitions)
    assert all(p["position_step"] == 1 for p in partitions)
    assert sum(p["bit_length"] for p in partitions) == impl.M
    assert max(p["bit_length"] for p in partitions) - min(p["bit_length"] for p in partitions) <= 1
    assert all(p["record_id"] == 17 for p in partitions)
    assert reconstruct_filter(partitions, key).to_b64() == anchor["bits"]


def test_interleaved_partitioning_round_trip_and_verification():
    from certchain.anchors import BloomAnchor, record_items
    from certchain.defenses.inference import (
        partition_anchor, reconstruct_filter, verify_items_detailed,
    )

    key = b"interleaved-partition-test-key"
    impl = BloomAnchor(key)
    tx = {"type": "student.upsert", "data": {"programme": "Software Engineering"},
          "actor": "test", "at": "2026-01-01T00:00:00+00:00"}
    anchor = impl.build(tx)
    partitions = partition_anchor(
        anchor,
        key,
        3,
        ("Node-A", "Node-B", "Node-C"),
        record_id=23,
        strategy="interleaved",
    )

    assert [p["start_bit"] for p in partitions] == [0, 1, 2]
    assert [p["position_step"] for p in partitions] == [3, 3, 3]
    assert [p["bit_length"] for p in partitions] == [1366, 1365, 1365]
    assert all(p["strategy"] == "interleaved" for p in partitions)
    assert reconstruct_filter(partitions, key).to_b64() == anchor["bits"]

    result = verify_items_detailed(partitions, key, record_items(tx))
    assert result["status"] == "verified"
    assert result["match_percentage"] == 100
    assert result["coverage_percentage"] == 100


def test_partitioned_bloom_store_isolates_node_views():
    from certchain.anchors import BloomAnchor, record_items
    from certchain.defenses.inference import (
        PartitionedBloomStore, PartitionUnavailable, partition_anchor, verify_items,
    )

    key = b"partition-test-key"
    impl = BloomAnchor(key)
    tx = {"type": "student.upsert", "data": {"programme": "Software Engineering"},
          "actor": "test", "at": "2026-01-01T00:00:00+00:00"}
    nodes = ("Node-A", "Node-B", "Node-C")
    partitions = partition_anchor(impl.build(tx), key, 3, nodes, record_id=17)
    store = PartitionedBloomStore(nodes)
    store.add(partitions)

    assert [p["partition_index"] for p in store.partitions_for_node("Node-A", 17)] == [0]
    assert [p["partition_index"] for p in store.partitions_for_node("Node-B", 17)] == [1]
    assert [p["partition_index"] for p in store.partitions_for_node("Node-C", 17)] == [2]
    assert verify_items(store.partitions_for_record(17), key, record_items(tx)) is True
    with pytest.raises(PartitionUnavailable):
        verify_items(store.partitions_for_record(17, ("Node-A", "Node-B")), key, record_items(tx))


def test_partition_aware_verification_and_missing_node():
    from certchain.anchors import BloomAnchor, record_items
    from certchain.defenses.inference import (
        PartitionUnavailable, partition_anchor, verify_items, verify_items_detailed,
    )

    key = b"partition-test-key"
    impl = BloomAnchor(key)
    tx = {"type": "student.upsert", "data": {"programme": "Software Engineering"},
          "actor": "test", "at": "2026-01-01T00:00:00+00:00"}
    partitions = partition_anchor(impl.build(tx), key, 3)

    assert verify_items(partitions, key, record_items(tx)) is True
    assert verify_items(partitions, key, ['student.upsert.programme="Medicine"']) is False
    complete = verify_items_detailed(partitions, key, record_items(tx))
    assert complete["status"] == "verified"
    assert complete["match_percentage"] == 100
    assert complete["coverage_percentage"] == 100
    assert sum(row["required_positions"] for row in complete["contributions"]) == complete[
        "total_required_positions"
    ]

    negative = verify_items_detailed(
        partitions, key, ['student.upsert.programme="Medicine"']
    )
    assert negative["status"] == "not_matched"
    assert negative["mismatched_positions"] > 0
    assert negative["coverage_percentage"] == 100

    partial = verify_items_detailed(partitions[:-1], key, record_items(tx))
    assert partial["status"] == "inconclusive"
    assert partial["match_percentage"] == 100
    assert 0 < partial["coverage_percentage"] < 100
    assert partial["unavailable_positions"] > 0
    with pytest.raises(PartitionUnavailable):
        verify_items(partitions[:-1], key, record_items(tx))


def test_sequential_partitioning_defence_endpoint(site):
    data = site.test_client().post("/api/security/sequential").get_json()

    assert data["system"] == "bloom" and data["defense"] == "horizontal_partitioning"
    assert data["strategy"] == "sequential" and data["placement"] == "single_copy"
    assert data["replication_factor"] == 1
    assert data["partition_count"] == 3 and data["blocks_partitioned"] > 0
    assert data["bloom_filter_bits"] == 4096
    assert [row["bit_length"] for row in data["assignments"]] == [1366, 1365, 1365]
    assert [row["nodes"] for row in data["assignments"]] == [
        ["Registry-Node"], ["Academic-Board-Node"], ["Audit-Office-Node"]
    ]
    assert data["all_reconstructed"] is True and data["all_verified"] is True
    assert 0 < data["max_node_exposure_percent"] < 100
    assert data["storage"]["total_partitions"] == data["blocks_partitioned"] * 3
    assert all(row["partitions"] == data["blocks_partitioned"] for row in data["storage"]["nodes"])
    assert data["metrics"]["communication_bytes_per_record"] == 513
    assert data["metrics"]["partition_generation_ms"] >= 0
    assert data["metrics"]["average_verification_ms"] >= 0
    assert data["verification"]["status"] == "verified"
    assert data["verification"]["match_percentage"] == 100
    assert data["verification"]["coverage_percentage"] == 100
    assert data["verification"]["baseline_agreement"] is True
    assert all(row["local_match_percentage"] == 100
               for row in data["verification"]["contributions"])
    assert all(row["coverage_percentage"] == 100
               for row in data["verification"]["contributions"])
    assert 99.9 <= sum(row["position_share_percentage"]
                       for row in data["verification"]["contributions"]) <= 100.1
    assert data["availability"][0]["status"] == "available"
    assert data["availability"][0]["verified_records"] == data["blocks_partitioned"]
    assert data["availability"][0]["match_percentage"] == 100
    assert data["availability"][0]["verification_coverage_percentage"] == 100
    assert data["availability"][0]["available_filter_percentage"] == 100
    assert all(row["status"] == "inconclusive" for row in data["availability"][1:])
    assert all(row["match_percentage"] == 100 for row in data["availability"][1:])
    assert all(0 < row["verification_coverage_percentage"] < 100
               for row in data["availability"][1:])
    assert all(66 < row["available_filter_percentage"] < 67
               for row in data["availability"][1:])
    assert all(row["unavailable_records"] == data["blocks_partitioned"]
               for row in data["availability"][1:])


def test_horizontal_partitioning_endpoint_remains_an_alias(site):
    data = site.test_client().post("/api/security/horizontal").get_json()

    assert data["defense"] == "horizontal_partitioning"


def test_interleaved_partitioning_defence_endpoint(site):
    data = site.test_client().post("/api/security/interleaved").get_json()

    assert data["system"] == "bloom" and data["defense"] == "horizontal_partitioning"
    assert data["strategy"] == "interleaved"
    assert data["strategy_name"] == "Interleaved Bit Partitioning"
    assert data["placement"] == "single_copy" and data["replication_factor"] == 1
    assert data["partition_count"] == 3 and data["blocks_partitioned"] > 0
    assert [row["start_bit"] for row in data["assignments"]] == [0, 1, 2]
    assert [row["position_step"] for row in data["assignments"]] == [3, 3, 3]
    assert [row["bit_length"] for row in data["assignments"]] == [1366, 1365, 1365]
    assert data["assignments"][0]["position_rule"] == "0, 3, ... 4095"
    assert data["all_reconstructed"] is True and data["all_verified"] is True
    assert data["verification"]["status"] == "verified"
    assert data["verification"]["baseline_agreement"] is True
    assert data["verification"]["match_percentage"] == 100
    assert data["verification"]["coverage_percentage"] == 100
    assert data["availability"][0]["status"] == "available"
    assert all(row["status"] == "inconclusive" for row in data["availability"][1:])
    assert all(66 < row["available_filter_percentage"] < 67
               for row in data["availability"][1:])


@pytest.mark.parametrize(("defense", "attack"), [
    ("sequential", "collusion"),
    ("interleaved", "pattern_mining"),
])
def test_horizontal_partitioning_prepares_attack_support_without_execution(
    site, defense, attack,
):
    response = site.test_client().post("/api/security/defend", json={
        "check": "inference",
        "attack": attack,
        "defenses": [defense],
    })
    assert response.status_code == 200
    data = response.get_json()
    assert data["attack"] == attack and data["unavailable"] == []
    assert len(data["results"]) == 1

    result = data["results"][0]
    support = result["attack_support"]
    assert result["strategy"] == defense
    assert result["attack"] == attack and result["attack_supported"] is True
    assert result["attack_executed"] is False
    assert support["status"] == "ready_for_attacker_component"
    assert support["requested_attack"] == attack and support["attack_executed"] is False
    assert support["baseline"]["visibility_percentage"] == 100
    assert support["baseline"]["records"] == result["blocks_partitioned"]
    assert len(support["partition_views"]) == 3
    assert all(33 < row["visibility_percentage"] < 34
               for row in support["partition_views"])


# ---- concurrency and headers ----------------------------------------------
def test_session_survives_concurrent_chain_reads(app):
    failures = []

    def worker(path):
        client = app.test_client()
        client.post("/api/dev-login", json={"username": "admin.dev"})
        for _ in range(30):
            if client.get(path).status_code != 200:
                failures.append((path, client.get(path).status_code))

    threads = [threading.Thread(target=worker, args=(p,)) for p in ("/api/chain/status", "/api/students") * 3]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not failures, f"{len(failures)} failed, first: {failures[:3]}"


def test_security_headers_and_spa(app):
    res = app.test_client().get("/")
    assert res.status_code == 200 and b"CertChain" in res.data
    assert "default-src 'self'" in res.headers["Content-Security-Policy"]


# Reference-assisted fragment inference (known-record attack) ---------------------

from certchain.attacks.inference import reference_similarity as refsim  # noqa: E402


def test_hamming_similarity_matches_the_worked_example():
    # Target 10100 vs reference 10110: 4 of 5 positions agree -> 80%.
    assert refsim.hamming_similarity(0b10100, 0b10110, 5) == 80.0
    assert refsim.hamming_similarity(0b10100, 0b10100, 5) == 100.0


def test_fragments_cover_the_filter_and_observe_only_their_bits():
    for n in refsim.PARTITIONS:
        bounds = [refsim.fragment_bounds(4096, n, i) for i in range(n)]
        assert bounds[0][0] == 0 and bounds[-1][1] == 4096
        assert all(a[1] == b[0] for a, b in zip(bounds, bounds[1:]))
    bits = 0b1011_0100_1011  # 12 bits, Bloom position p is bit p
    assert refsim.observe(bits, *refsim.fragment_bounds(12, 3, 0)) == 0b1011
    assert refsim.observe(bits, *refsim.fragment_bounds(12, 3, 1)) == 0b0100
    with pytest.raises(ValueError):
        refsim.fragment_bounds(4096, 3, 3)


def test_class_scores_average_per_class_and_pick_the_strongest():
    refs = [(0b10100, "IT"), (0b10110, "IT"), (0b01110, "SE"), (0b01010, "SE")]
    scores = refsim.class_scores(0b10100, refs, 5)
    assert scores == {"IT": 90.0, "SE": 30.0}
    assert refsim.predict(scores) == "IT"


def test_evaluation_metrics_and_confusion_matrix():
    m = refsim.evaluate(["IT", "IT", "SE", "CS"], ["IT", "SE", "SE", "CS"], ["IT", "SE", "CS"])
    assert m["accuracy"] == 0.75 and m["confusion"]["SE"]["IT"] == 1
    assert m["per_class"]["IT"]["precision"] == 0.5 and m["per_class"]["SE"]["recall"] == 0.5


def test_inference_engine_never_receives_ground_truth():
    import inspect
    for fn in (refsim.class_scores, refsim.predict, refsim.hamming_similarity):
        assert "ground_truth" not in inspect.signature(fn).parameters


def test_reference_similarity_attack_is_reproducible_and_covers_all_visibilities(site):
    with site.app_context():
        impl = site.config["SYSTEMS"]["bloom"].config["anchor"]
        a = refsim.run_experiment(impl, per_class=30)
        b = refsim.run_experiment(impl, per_class=30)
    assert [e["accuracy"] for e in a["experiments"]] == [e["accuracy"] for e in b["experiments"]]
    ratios = [e["visibility_ratio"] for e in a["experiments"]]
    assert ratios == [1.0, 0.5, 0.3333, 0.25, 0.2]
    assert a["experiments"][0]["accuracy"] > a["chance_accuracy"]


def test_reference_similarity_endpoint(site):
    data = site.test_client().post("/api/security/reference_similarity").get_json()
    assert data["system"] == "bloom" and data["attack"] == "reference_similarity"
    assert [e["experiment"] for e in data["experiments"]] == ["E1", "E2", "E3", "E4", "E5"]
    assert data["config"]["records"] == 300
