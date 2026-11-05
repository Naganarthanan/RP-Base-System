import sqlite3
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from certchain import create_app  # noqa: E402


@pytest.fixture
def app(tmp_path):
    return create_app(data_dir=tmp_path, env="development")


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


def test_private_data_is_only_ciphertext_on_disk(app, tmp_path):
    for path in tmp_path.glob("certchain.db*"):
        raw = path.read_bytes()
        for secret in (b"Nila Kanagaratnam", b"200112345678", b"Temple Road", b"mark.set", b"Dean's List"):
            assert secret not in raw, f"{secret!r} found in {path.name}"
    rows = sqlite3.connect(tmp_path / "certchain.db").execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    assert {r[0] for r in rows} == {"blocks", "users"}


def test_all_academic_data_is_rebuilt_from_chain(app, admin, tmp_path):
    assert write(admin, "post", "/api/certificates", student_id="UNI20260002", title="Merit").status_code == 201
    app.config["ledger"].db.close()
    reopened = create_app(data_dir=tmp_path, env="development")
    state = reopened.config["state"]
    assert state.students["UNI20260001"]["nic"] == "200112345678"
    assert ("UNI20260001", "IT1010") in state.marks
    assert any(c["title"] == "Merit" for c in state.certificates.values())
    assert len(state.students) == 6, "seed must not run twice"


def test_login_failure_and_throttle(app):
    client = app.test_client()
    for _ in range(5):
        assert client.post("/api/login", json={"username": "admin.dev", "password": "wrong"}).status_code == 401
    assert client.post("/api/login", json={"username": "admin.dev", "password": "Admin@123"}).status_code == 429


def test_dev_login_available_only_in_development(app, tmp_path):
    assert app.test_client().post("/api/dev-login", json={"username": "admin.dev"}).status_code == 200
    prod = create_app(data_dir=tmp_path / "prod", env="production")
    client = prod.test_client()
    assert client.post("/api/dev-login", json={"username": "admin.dev"}).status_code == 404
    assert client.get("/api/session").get_json()["dev_accounts"] == []
    assert not prod.config["state"].students, "production must not contain demo data"


def test_dev_login_rejects_remote_clients(app):
    client = app.test_client()
    res = client.post("/api/dev-login", json={"username": "admin.dev"}, environ_base={"REMOTE_ADDR": "10.0.0.8"})
    assert res.status_code == 404


def test_endpoints_require_auth_and_csrf(app, admin):
    assert app.test_client().get("/api/students").status_code == 401
    res = admin.post("/api/certificates", json={"student_id": "UNI20260001", "title": "X"})
    assert res.status_code == 403


def test_student_sees_only_own_record(student):
    assert student.get("/api/students/UNI20260001/record").status_code == 200
    assert student.get("/api/students/UNI20260002/record").status_code == 403
    assert student.get("/api/students").status_code == 403
    assert student.get("/api/chain/status").status_code == 403
    assert student.get("/api/certificates/CERT-2026-0002").status_code == 403


def test_faculty_is_limited_to_assigned_courses(faculty):
    roster = faculty.get("/api/courses/IT1010/roster").get_json()
    assert "nic" not in roster["rows"][0]["student"]
    assert "address" not in roster["rows"][0]["student"]
    assert faculty.get("/api/courses/IT1020/roster").status_code == 403
    assert faculty.get("/api/students/UNI20260001/record").status_code == 403
    denied = write(faculty, "put", "/api/marks", student_id="UNI20260001", course_code="IT1020", coursework=1, exam=1)
    assert denied.status_code == 403


def test_marks_update_keeps_history_and_validates(app, faculty):
    res = write(faculty, "put", "/api/marks", student_id="UNI20260001", course_code="IT1010", coursework=50, exam=50)
    assert res.get_json()["total"] == 50 and res.get_json()["grade"] == "C"
    assert len(app.config["state"].marks[("UNI20260001", "IT1010")]["history"]) == 2
    for bad in ({"coursework": 101, "exam": 1}, {"coursework": "x", "exam": 1}):
        assert write(faculty, "put", "/api/marks", student_id="UNI20260001", course_code="IT1010", **bad).status_code == 400
    assert write(faculty, "put", "/api/marks", student_id="UNI20260004", course_code="IT1050", coursework=1, exam=1).status_code == 404


def test_new_student_gets_login_and_inactive_blocks_it(app, admin):
    res = write(admin, "post", "/api/students", name="New Person", email="new@certchain.test", programme="BSc", intake="2027", nic="99")
    assert res.status_code == 201
    data = res.get_json()
    new = login(app, data["username"], data["temp_password"])
    assert new.get("/api/session").get_json()["user"]["must_change"] == 1
    assert write(admin, "put", f"/api/students/{data['student']['id']}", name="New Person", email="new@certchain.test",
                 programme="BSc", intake="2027", status="inactive").status_code == 200
    assert new.get("/api/profile").status_code == 401


def test_password_change(app, student):
    assert write(student, "post", "/api/password", current="nope", new="Longenough123").status_code == 400
    assert write(student, "post", "/api/password", current="Student@123", new="short1").status_code == 400
    assert write(student, "post", "/api/password", current="Student@123", new="Longenough123").status_code == 200
    login(app, "student.dev", "Longenough123")


def test_reports_follow_teaching_assignments(app, faculty, student):
    fields = {"title": "Progress", "semester": "Y1S1", "body": "Doing well"}
    assert write(faculty, "post", "/api/reports", student_id="UNI20260001", **fields).status_code == 201
    assert write(student, "post", "/api/reports", student_id="UNI20260001", **fields).status_code == 403
    assert student.get("/api/reports").status_code == 403
    other = login(app, "fac0003", "Faculty@123")
    assert write(other, "post", "/api/reports", student_id="UNI20260006", **fields).status_code == 403
    seen = {r["student_id"] for r in other.get("/api/reports").get_json()}
    assert "UNI20260006" not in seen


def test_certificate_verify_and_revoke(app, admin):
    client = app.test_client()
    good = {"id": "CERT-2026-0001", "code": "DEMO-NILA-2026"}
    assert client.post("/api/public/verify", json=good).get_json()["result"] == "valid"
    wrong = client.post("/api/public/verify", json={**good, "code": "WRONG"}).get_json()
    assert wrong == {"result": "not_found"}
    assert write(admin, "post", "/api/certificates/CERT-2026-0001/revoke", reason="Issued in error").status_code == 200
    assert client.post("/api/public/verify", json=good).get_json()["result"] == "revoked"
    assert admin.get("/api/certificates/CERT-2026-0001/qr.svg").status_code == 200


def test_block_decrypt_is_admin_only(admin, faculty, student):
    assert admin.get("/api/chain/blocks/4/decrypted").get_json()["data"]["nic"] == "200112345678"
    assert admin.get("/api/chain/blocks/99999/decrypted").status_code == 404
    assert faculty.get("/api/chain/blocks/4/decrypted").status_code == 403
    assert student.get("/api/chain/blocks/4/decrypted").status_code == 403


def test_tampering_is_detected_and_repaired(app, admin):
    assert admin.get("/api/chain/status").get_json()["healthy"] is True
    res = write(admin, "post", "/api/dev/tamper", node="Audit-Office-Node", idx=3).get_json()["status"]
    broken = res["nodes"][2]
    assert (res["healthy"], res["has_majority"], broken["valid"], broken["bad_block"]) == (False, True, False, 3)
    assert write(admin, "post", "/api/certificates", student_id="UNI20260002", title="During fault").status_code == 201
    repaired = write(admin, "post", "/api/chain/repair").get_json()
    assert repaired["repaired"] == ["Audit-Office-Node"] and repaired["status"]["healthy"] is True


def test_writes_stop_without_a_majority(app, admin):
    ledger = app.config["ledger"]
    with ledger.db:
        ledger.db.execute("DELETE FROM blocks WHERE node='Audit-Office-Node' AND idx=(SELECT MAX(idx) FROM blocks)")
        ledger.db.execute("UPDATE blocks SET hash='forged' WHERE node='Academic-Board-Node' AND idx=(SELECT MAX(idx) FROM blocks)")
    res = write(admin, "post", "/api/certificates", student_id="UNI20260002", title="Blocked")
    assert res.status_code == 503


def test_session_survives_concurrent_chain_reads(app):
    """Session checks and chain scans share one SQLite connection across threads."""
    failures = []

    def worker(path):
        client = app.test_client()
        client.post("/api/dev-login", json={"username": "admin.dev"})
        for _ in range(40):
            status = client.get(path).status_code
            if status != 200:
                failures.append((path, status))

    threads = [threading.Thread(target=worker, args=(p,)) for p in ("/api/chain/status", "/api/students") * 4]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not failures, f"{len(failures)} failed, first: {failures[:3]}"


def test_security_headers_and_spa(app):
    res = app.test_client().get("/")
    assert res.status_code == 200 and b"CertChain" in res.data
    assert "default-src 'self'" in res.headers["Content-Security-Policy"]
