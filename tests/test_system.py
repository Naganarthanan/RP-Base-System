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
