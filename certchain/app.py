"""CertChain web application: authentication, role checks and the JSON API."""
import io
import os
import secrets
from datetime import date
from functools import wraps
from pathlib import Path
from urllib.parse import quote

import qrcode
import qrcode.image.svg
from flask import Flask, jsonify, request, send_file, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

from .app_support import (
    CODE, DEV_ACCOUNTS, ApiError, Throttle, check_date, check_email, check_password, clean,
)
from .crypto import Keys
from .ledger import NODES, Ledger, LedgerError
from .state import COURSEWORK_WEIGHT, EXAM_WEIGHT, GRADE_SCALE, State

BASE = Path(__file__).resolve().parent.parent
DUMMY_HASH = generate_password_hash("timing-equaliser-not-a-real-password")
LOOPBACK = {"127.0.0.1", "::1"}


def create_app(data_dir=None, env=None, seed_demo=True, public_url=None) -> Flask:
    env = env or os.environ.get("APP_ENV", "development")
    dev = env == "development"
    data = Path(data_dir or os.environ.get("CERTCHAIN_DATA", BASE / "data"))
    keys = Keys.load_or_create(data / "keys.json")
    ledger = Ledger(data / "certchain.db", keys)
    state = State()
    for tx in ledger.majority_transactions():
        state.apply(tx)

    app = Flask(__name__, static_folder=str(BASE / "static"), static_url_path="/static")
    app.config.update(
        SECRET_KEY=keys.session_secret,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=not dev,
        SESSION_COOKIE_NAME="certchain_session",
        MAX_CONTENT_LENGTH=1024 * 1024,
        PUBLIC_URL=(public_url or os.environ.get("PUBLIC_URL", "http://127.0.0.1:5000")).rstrip("/"),
    )
    login_throttle, verify_throttle = Throttle(5, 300), Throttle(30, 60)

    # ---- helpers -----------------------------------------------------------
    def commit(kind: str, data_: dict, actor: str | None = None) -> dict:
        actor = actor or (current_user() or {}).get("username", "system")
        tx = ledger.append(kind, data_, actor)
        state.apply(tx)
        return tx

    def add_user(username, password, role, subject_id, must_change=True):
        pw_hash = generate_password_hash(password)
        with ledger.lock, ledger.db:
            ledger.db.execute(
                "INSERT INTO users (username, pw_hash, role, subject_id, must_change) VALUES (?,?,?,?,?)",
                (username, pw_hash, role, subject_id, int(must_change)),
            )

    app.config["commit"], app.config["add_user"] = commit, add_user
    app.config["ledger"], app.config["state"] = ledger, state

    def current_user():
        username = session.get("username")
        if not username:
            return None
        with ledger.lock:  # the SQLite connection is shared between request threads
            row = ledger.db.execute(
                "SELECT username, role, subject_id, must_change FROM users WHERE username=? AND active=1", (username,)
            ).fetchone()
        return dict(row) if row else None

    def body() -> dict:
        data_ = request.get_json(silent=True)
        if not isinstance(data_, dict):
            raise ApiError(400, "expected a JSON object")
        return data_

    def require(*roles):
        def decorate(fn):
            @wraps(fn)
            def inner(*args, **kwargs):
                user = current_user()
                if not user:
                    raise ApiError(401, "please sign in")
                if roles and user["role"] not in roles:
                    raise ApiError(403, "you do not have access to this")
                if request.method != "GET" and request.headers.get("X-CSRF-Token") != session.get("csrf"):
                    raise ApiError(403, "invalid CSRF token, reload the page")
                with ledger.lock:
                    return fn(user, *args, **kwargs)
            return inner
        return decorate

    def start_session(username: str) -> None:
        session.clear()
        session["username"] = username
        session["csrf"] = secrets.token_urlsafe(32)

    def dev_login_allowed() -> bool:
        return dev and request.remote_addr in LOOPBACK

    def public_student(s: dict) -> dict:
        """The subset of a student record a lecturer needs. Excludes NIC, DOB, address and phone."""
        return {k: s[k] for k in ("id", "name", "email", "programme", "intake", "status")}

    def need(mapping: dict, key: str, label: str) -> dict:
        if key not in mapping:
            raise ApiError(404, f"{label} not found")
        return mapping[key]

    def can_view_student(user: dict, student_id: str) -> bool:
        return user["role"] == "admin" or (user["role"] == "student" and user["subject_id"] == student_id)

    def course_access(user: dict, code: str) -> dict:
        course = need(state.courses, code, "course")
        if user["role"] == "faculty" and course.get("faculty_id") != user["subject_id"]:
            raise ApiError(403, "this course is not assigned to you")
        return course

    def student_record(student_id: str) -> dict:
        return {
            "student": state.students[student_id],
            **state.results(student_id),
            "reports": sorted((r for r in state.reports.values() if r["student_id"] == student_id),
                              key=lambda r: r["at"], reverse=True),
            "certificates": [c for c in state.certificates.values() if c["student_id"] == student_id],
        }

    # ---- responses ---------------------------------------------------------
    @app.errorhandler(ApiError)
    def on_api_error(err):
        return jsonify(error=err.message), err.status

    @app.errorhandler(LedgerError)
    def on_ledger_error(err):
        return jsonify(error=str(err)), 503

    @app.errorhandler(404)
    def on_404(_):
        return jsonify(error="not found"), 404

    @app.errorhandler(405)
    def on_405(_):
        return jsonify(error="method not allowed"), 405

    @app.errorhandler(413)
    def on_413(_):
        return jsonify(error="request is too large"), 413

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    # ---- pages -------------------------------------------------------------
    @app.get("/")
    @app.get("/verify")
    def spa():
        return send_from_directory(app.static_folder, "index.html")

    # ---- authentication ----------------------------------------------------
    @app.get("/api/session")
    def get_session():
        user = current_user()
        return jsonify(
            user=user,
            csrf=session.get("csrf") if user else None,
            dev_accounts=DEV_ACCOUNTS if dev_login_allowed() else [],
            env=env,
        )

    @app.post("/api/login")
    def login():
        d = body()
        username = str(d.get("username", "")).strip().lower()
        password = str(d.get("password", ""))
        key = f"{username}|{request.remote_addr}"
        if login_throttle.blocked(key):
            raise ApiError(429, "too many failed attempts, try again in 5 minutes")
        with ledger.lock:
            row = ledger.db.execute("SELECT pw_hash, active FROM users WHERE username=?", (username,)).fetchone()
        valid = check_password_hash(row["pw_hash"] if row else DUMMY_HASH, password)
        if not (row and valid and row["active"]):
            login_throttle.hit(key)
            raise ApiError(401, "incorrect username or password")
        login_throttle.reset(key)
        start_session(username)
        return get_session()

    @app.post("/api/dev-login")
    def dev_login():
        if not dev_login_allowed():
            raise ApiError(404, "not found")
        username = str(body().get("username", ""))
        if username not in {a["username"] for a in DEV_ACCOUNTS}:
            raise ApiError(400, "unknown development account")
        start_session(username)
        return get_session()

    @app.post("/api/logout")
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.post("/api/password")
    @require()
    def change_password(user):
        d = body()
        row = ledger.db.execute("SELECT pw_hash FROM users WHERE username=?", (user["username"],)).fetchone()
        if not check_password_hash(row["pw_hash"], str(d.get("current", ""))):
            raise ApiError(400, "current password is incorrect")
        new = str(d.get("new", ""))
        check_password(new)
        with ledger.db:
            ledger.db.execute("UPDATE users SET pw_hash=?, must_change=0 WHERE username=?",
                              (generate_password_hash(new), user["username"]))
        return jsonify(ok=True)

    # ---- dashboard ---------------------------------------------------------
    @app.get("/api/dashboard")
    @require()
    def dashboard(user):
        if user["role"] == "admin":
            chain = ledger.status()
            return jsonify(
                students=len(state.students), faculty=len(state.faculty), courses=len(state.courses),
                certificates=len(state.certificates), marks=len(state.marks),
                chain={"healthy": chain["healthy"], "height": chain["height"], "nodes": len(NODES)},
            )
        if user["role"] == "faculty":
            mine = [c for c in state.courses.values() if c.get("faculty_id") == user["subject_id"]]
            for_view = []
            for c in mine:
                roster = [s for s, code in state.enrollments if code == c["code"]]
                marked = sum((s, c["code"]) in state.marks for s in roster)
                for_view.append({**c, "enrolled": len(roster), "marked": marked})
            return jsonify(profile=state.faculty[user["subject_id"]],
                           courses=sorted(for_view, key=lambda c: c["code"]))
        return jsonify(student_record(user["subject_id"]))

    # ---- students ----------------------------------------------------------
    STUDENT_FIELDS = dict(required=("name", "email", "programme", "intake"),
                          optional=("phone", "nic", "dob", "address", "status"))

    def student_payload(d: dict) -> dict:
        s = clean(d, **STUDENT_FIELDS)
        check_email(s["email"])
        check_date(s["dob"], "date of birth")
        s["status"] = s["status"] or "active"
        if s["status"] not in ("active", "inactive", "graduated"):
            raise ApiError(400, "status is not valid")
        return s

    @app.get("/api/students")
    @require("admin")
    def list_students(user):
        rows = []
        for s in state.students.values():
            results = state.results(s["id"])
            rows.append({**public_student(s), "gpa": results["gpa"], "courses": len(results["courses"])})
        return jsonify(sorted(rows, key=lambda r: r["id"]))

    @app.post("/api/students")
    @require("admin")
    def create_student(user):
        s = student_payload(body())
        sid = f"UNI{date.today().year}{len(state.students) + 1:04d}"
        while sid in state.students:
            sid = f"UNI{date.today().year}{secrets.randbelow(9000) + 1000}"
        s["id"] = sid
        commit("student.upsert", s)
        temp = secrets.token_urlsafe(9)
        add_user(sid.lower(), temp, "student", sid)
        return jsonify(student=s, username=sid.lower(), temp_password=temp), 201

    @app.put("/api/students/<sid>")
    @require("admin")
    def update_student(user, sid):
        need(state.students, sid, "student")
        s = {**student_payload(body()), "id": sid}
        commit("student.upsert", s)
        with ledger.db:
            ledger.db.execute("UPDATE users SET active=? WHERE role='student' AND subject_id=?",
                              (int(s["status"] != "inactive"), sid))
        return jsonify(s)

    @app.get("/api/students/<sid>/record")
    @require("admin", "student")
    def get_record(user, sid):
        if not can_view_student(user, sid):
            raise ApiError(403, "you can only view your own record")
        need(state.students, sid, "student")
        return jsonify(student_record(sid))

    # ---- faculty -----------------------------------------------------------
    def faculty_payload(d: dict) -> dict:
        f = clean(d, required=("name", "email", "department", "title"), optional=("phone", "status"))
        check_email(f["email"])
        f["status"] = f["status"] or "active"
        if f["status"] not in ("active", "inactive"):
            raise ApiError(400, "status is not valid")
        return f

    @app.get("/api/faculty")
    @require("admin")
    def list_faculty(user):
        rows = [{**f, "courses": sum(c.get("faculty_id") == f["id"] for c in state.courses.values())}
                for f in state.faculty.values()]
        return jsonify(sorted(rows, key=lambda r: r["id"]))

    @app.post("/api/faculty")
    @require("admin")
    def create_faculty(user):
        f = faculty_payload(body())
        fid = f"FAC{len(state.faculty) + 1:04d}"
        while fid in state.faculty:
            fid = f"FAC{secrets.randbelow(9000) + 1000}"
        f["id"] = fid
        commit("faculty.upsert", f)
        temp = secrets.token_urlsafe(9)
        add_user(fid.lower(), temp, "faculty", fid)
        return jsonify(faculty=f, username=fid.lower(), temp_password=temp), 201

    @app.put("/api/faculty/<fid>")
    @require("admin")
    def update_faculty(user, fid):
        need(state.faculty, fid, "faculty member")
        f = {**faculty_payload(body()), "id": fid}
        commit("faculty.upsert", f)
        with ledger.db:
            ledger.db.execute("UPDATE users SET active=? WHERE role='faculty' AND subject_id=?",
                              (int(f["status"] != "inactive"), fid))
        return jsonify(f)

    @app.get("/api/profile")
    @require("faculty", "student")
    def profile(user):
        source = state.faculty if user["role"] == "faculty" else state.students
        return jsonify(source[user["subject_id"]])

    # ---- courses, enrolment and marks ---------------------------------------
    def course_payload(d: dict, code: str | None = None) -> dict:
        c = clean(d, required=("title", "semester"), optional=("faculty_id",))
        try:
            c["credits"] = int(d.get("credits"))
        except (TypeError, ValueError):
            raise ApiError(400, "credits must be a whole number") from None
        if not 1 <= c["credits"] <= 30:
            raise ApiError(400, "credits must be between 1 and 30")
        if c["faculty_id"]:
            need(state.faculty, c["faculty_id"], "faculty member")
        c["code"] = code or str(d.get("code", "")).strip().upper()
        if not CODE.match(c["code"]):
            raise ApiError(400, "course code must be 2-16 capital letters, numbers or dashes")
        return c

    def course_view(c: dict) -> dict:
        lecturer = state.faculty.get(c.get("faculty_id") or "")
        roster = [s for s, code in state.enrollments if code == c["code"]]
        return {**c, "lecturer": lecturer["name"] if lecturer else None, "enrolled": len(roster),
                "marked": sum((s, c["code"]) in state.marks for s in roster)}

    @app.get("/api/courses")
    @require("admin", "faculty")
    def list_courses(user):
        rows = [course_view(c) for c in state.courses.values()
                if user["role"] == "admin" or c.get("faculty_id") == user["subject_id"]]
        return jsonify(sorted(rows, key=lambda r: r["code"]))

    @app.post("/api/courses")
    @require("admin")
    def create_course(user):
        c = course_payload(body())
        if c["code"] in state.courses:
            raise ApiError(409, "a course with this code already exists")
        commit("course.upsert", c)
        return jsonify(c), 201

    @app.put("/api/courses/<code>")
    @require("admin")
    def update_course(user, code):
        need(state.courses, code, "course")
        c = course_payload(body(), code)
        commit("course.upsert", c)
        return jsonify(c)

    @app.get("/api/courses/<code>/roster")
    @require("admin", "faculty")
    def roster(user, code):
        course = course_access(user, code)
        rows = []
        for sid, enrolled_code in state.enrollments:
            if enrolled_code == code:
                rows.append({"student": public_student(state.students[sid]), **state.result_row(sid, code),
                             "history": state.marks.get((sid, code), {}).get("history", [])})
        rows.sort(key=lambda r: r["student"]["id"])
        return jsonify(course=course_view(course), rows=rows,
                       weights={"coursework": COURSEWORK_WEIGHT, "exam": EXAM_WEIGHT},
                       scale=[{"from": f, "grade": g, "points": p} for f, g, p in GRADE_SCALE])

    @app.post("/api/enrollments")
    @require("admin")
    def enrol(user):
        d = clean(body(), required=("student_id", "course_code"))
        need(state.students, d["student_id"], "student")
        need(state.courses, d["course_code"], "course")
        if (d["student_id"], d["course_code"]) in state.enrollments:
            raise ApiError(409, "the student is already enrolled in this course")
        commit("enrollment.add", d)
        return jsonify(d), 201

    @app.delete("/api/enrollments")
    @require("admin")
    def unenrol(user):
        d = clean(body(), required=("student_id", "course_code"))
        key = (d["student_id"], d["course_code"])
        if key not in state.enrollments:
            raise ApiError(404, "enrolment not found")
        if key in state.marks:
            raise ApiError(409, "this enrolment already has marks and cannot be removed")
        commit("enrollment.remove", d)
        return jsonify(ok=True)

    @app.put("/api/marks")
    @require("admin", "faculty")
    def set_mark(user):
        d = body()
        sid, code = str(d.get("student_id", "")), str(d.get("course_code", ""))
        course_access(user, code)
        if (sid, code) not in state.enrollments:
            raise ApiError(404, "the student is not enrolled in this course")
        try:
            coursework, exam = float(d["coursework"]), float(d["exam"])
        except (KeyError, TypeError, ValueError):
            raise ApiError(400, "coursework and exam marks must be numbers") from None
        if not (0 <= coursework <= 100 and 0 <= exam <= 100):
            raise ApiError(400, "marks must be between 0 and 100")
        commit("mark.set", {"student_id": sid, "course_code": code, "coursework": coursework, "exam": exam})
        return jsonify(state.result_row(sid, code))

    # ---- reports -----------------------------------------------------------
    @app.get("/api/reports")
    @require("admin", "faculty")
    def list_reports(user):
        rows = list(state.reports.values())
        if user["role"] == "faculty":
            rows = [r for r in rows if state.teaches(user["subject_id"], r["student_id"])]
        out = [{**r, "student_name": state.students[r["student_id"]]["name"]} for r in rows]
        return jsonify(sorted(out, key=lambda r: r["at"], reverse=True))

    @app.post("/api/reports")
    @require("admin", "faculty")
    def add_report(user):
        d = clean(body(), required=("student_id", "title", "semester", "body"), max_len=5000)
        need(state.students, d["student_id"], "student")
        if user["role"] == "faculty" and not state.teaches(user["subject_id"], d["student_id"]):
            raise ApiError(403, "you can only write reports for students you teach")
        d["id"] = f"REP-{len(state.reports) + 1:04d}"
        tx = commit("report.add", d)
        return jsonify({**d, "by": tx["actor"], "at": tx["at"]}), 201

    # ---- certificates ------------------------------------------------------
    @app.get("/api/certificates")
    @require("admin")
    def list_certificates(user):
        rows = [{**c, "student_name": state.students[c["student_id"]]["name"]} for c in state.certificates.values()]
        return jsonify(sorted(rows, key=lambda r: r["id"], reverse=True))

    @app.post("/api/certificates")
    @require("admin")
    def issue_certificate(user):
        d = clean(body(), required=("student_id", "title"), optional=("issued_on",))
        student = need(state.students, d["student_id"], "student")
        check_date(d["issued_on"], "issue date")
        cert = {
            "id": f"CERT-{date.today().year}-{len(state.certificates) + 1:04d}",
            "student_id": d["student_id"],
            "title": d["title"],
            "programme": student["programme"],
            "issued_on": d["issued_on"] or date.today().isoformat(),
            "code": secrets.token_hex(8).upper(),
        }
        commit("certificate.issue", cert)
        return jsonify(cert), 201

    @app.post("/api/certificates/<cid>/revoke")
    @require("admin")
    def revoke_certificate(user, cid):
        cert = need(state.certificates, cid, "certificate")
        if cert["status"] == "revoked":
            raise ApiError(409, "this certificate is already revoked")
        d = clean(body(), required=("reason",))
        commit("certificate.revoke", {"id": cid, "reason": d["reason"]})
        return jsonify(state.certificates[cid])

    @app.get("/api/certificates/<cid>")
    @require("admin", "student")
    def get_certificate(user, cid):
        cert = need(state.certificates, cid, "certificate")
        if not can_view_student(user, cert["student_id"]):
            raise ApiError(403, "you can only view your own certificates")
        return jsonify({**cert, "student_name": state.students[cert["student_id"]]["name"]})

    @app.get("/api/certificates/<cid>/qr.svg")
    @require("admin", "student")
    def certificate_qr(user, cid):
        cert = need(state.certificates, cid, "certificate")
        if not can_view_student(user, cert["student_id"]):
            raise ApiError(403, "you can only view your own certificates")
        link = f"{app.config['PUBLIC_URL']}/verify#id={quote(cert['id'])}&code={quote(cert['code'])}"
        buffer = io.BytesIO()
        qrcode.make(link, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2).save(buffer)
        buffer.seek(0)
        return send_file(buffer, mimetype="image/svg+xml")

    @app.post("/api/public/verify")
    def public_verify():
        ip = request.remote_addr or "unknown"
        if verify_throttle.blocked(ip):
            raise ApiError(429, "too many checks, try again in a minute")
        verify_throttle.hit(ip)
        d = body()
        cert = state.certificates.get(str(d.get("id", "")).strip())
        code = str(d.get("code", "")).strip().upper()
        if not cert or not secrets.compare_digest(cert["code"].encode(), code.encode()):
            return jsonify(result="not_found")
        return jsonify(
            result=cert["status"],
            certificate={
                "id": cert["id"], "title": cert["title"], "programme": cert["programme"],
                "issued_on": cert["issued_on"], "holder": state.students[cert["student_id"]]["name"],
            },
            chain_healthy=ledger.status()["has_majority"],
        )

    # ---- blockchain --------------------------------------------------------
    @app.get("/api/chain/status")
    @require("admin")
    def chain_status(user):
        return jsonify(ledger.status())

    @app.get("/api/chain/blocks")
    @require("admin")
    def chain_blocks(user):
        limit = min(max(request.args.get("limit", 25, type=int), 1), 100)
        offset = max(request.args.get("offset", 0, type=int), 0)
        node = request.args.get("node", NODES[0])
        if node not in NODES:
            raise ApiError(404, "node not found")
        return jsonify(blocks=ledger.rows(node, limit, offset, newest_first=True), dev=dev)

    @app.get("/api/chain/blocks/<int:idx>/decrypted")
    @require("admin")
    def chain_block_decrypted(user, idx):
        status = ledger.status()
        source = next((n["node"] for n in status["nodes"] if n["in_consensus"]), None)
        if not source:
            raise LedgerError("No majority of nodes agree on a valid chain.")
        block = ledger.rows(source, 1, idx)
        if not block:
            raise ApiError(404, "block not found")
        return jsonify(keys.decrypt(block[0]["nonce"], block[0]["ciphertext"], str(idx)))

    @app.post("/api/chain/repair")
    @require("admin")
    def chain_repair(user):
        return jsonify(repaired=ledger.repair(), status=ledger.status())

    @app.post("/api/dev/tamper")
    @require("admin")
    def dev_tamper(user):
        if not dev_login_allowed():
            raise ApiError(404, "not found")
        d = body()
        node, idx = str(d.get("node", NODES[2])), d.get("idx", 1)
        if node not in NODES or not isinstance(idx, int) or not ledger.tamper(node, idx):
            raise ApiError(404, "block not found")
        return jsonify(status=ledger.status())

    # ---- demo data ---------------------------------------------------------
    is_empty = ledger.db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is None
    if dev and seed_demo and is_empty:
        from .seed import seed
        seed(app)

    return app
