"""Fictional demo data, loaded only in development. It is written through the chain."""
from datetime import date

from .app_support import DEV_ACCOUNTS


def nic_day_code(dob: str, female: bool) -> str:
    """Day-of-year part of a 12-digit Sri Lankan NIC (YYYY DDD NNNNN); women add 500."""
    born = date.fromisoformat(dob)
    return f"{born.timetuple().tm_yday + (500 if female else 0):03d}"


def make_nic(dob: str, female: bool, serial: str) -> str:
    return dob[:4] + nic_day_code(dob, female) + serial


def seed(app, users: bool = True) -> None:
    commit = app.config["commit"]
    add_user = app.config["add_user"] if users else (lambda *a, **k: None)
    for account in DEV_ACCOUNTS:
        if account["role"] == "admin":
            add_user(account["username"], account["password"], "admin", None, must_change=False)

    staff = [
        ("FAC0001", "Dr. Meera Sivalingam", "Computing", "Senior Lecturer", "meera.s@certchain.test", "+94 77 000 1001"),
        ("FAC0002", "Prof. Arjun Rajendran", "Computing", "Professor", "arjun.r@certchain.test", "+94 77 000 1002"),
        ("FAC0003", "Ms. Tharini Yogan", "Mathematics", "Lecturer", "tharini.y@certchain.test", "+94 77 000 1003"),
    ]
    for sid, name, dept, title, email, phone in staff:
        commit("faculty.upsert", {"id": sid, "name": name, "department": dept, "title": title, "email": email,
                                  "phone": phone, "status": "active"}, "seed")
    add_user("faculty.dev", "Faculty@123", "faculty", "FAC0001", must_change=False)
    add_user("fac0002", "Faculty@123", "faculty", "FAC0002", must_change=False)
    add_user("fac0003", "Faculty@123", "faculty", "FAC0003", must_change=False)

    programme = "BSc (Hons) Information Technology"
    people = [
        ("UNI20260001", "Nila Kanagaratnam", True, "12345", "2001-03-14", "12 Temple Road, Jaffna"),
        ("UNI20260002", "Kavin Sutharsan", False, "87654", "2002-07-02", "48 Hospital Road, Vavuniya"),
        ("UNI20260003", "Aisha Farook", True, "45612", "2001-11-23", "7 Lake View, Kilinochchi"),
        ("UNI20260004", "Dilan Perera", False, "78945", "2002-01-30", "21 Station Road, Mannar"),
        ("UNI20260005", "Priya Nadarajah", True, "65498", "2001-09-09", "3 College Lane, Jaffna"),
        ("UNI20260006", "Ravi Selvam", False, "32165", "2002-05-18", "90 Main Street, Mullaitivu"),
    ]
    for n, (sid, name, female, serial, dob, address) in enumerate(people, start=1):
        nic = make_nic(dob, female, serial)
        commit("student.upsert", {"id": sid, "name": name, "email": f"student{n}@certchain.test", "phone": f"+94 76 000 20{n:02d}",
                                  "nic": nic, "dob": dob, "address": address, "programme": programme,
                                  "intake": "2026 January", "status": "active"}, "seed")
        username = "student.dev" if n == 1 else sid.lower()
        add_user(username, "Student@123", "student", sid, must_change=False)

    courses = [
        ("IT1010", "Introduction to Programming", 4, "Y1S1", "FAC0001"),
        ("IT1020", "Database Systems", 4, "Y1S1", "FAC0002"),
        ("MA1030", "Discrete Mathematics", 3, "Y1S1", "FAC0003"),
        ("IT1040", "Software Engineering", 4, "Y1S2", "FAC0002"),
        ("IT1050", "Blockchain Fundamentals", 3, "Y1S2", "FAC0001"),
    ]
    for code, title, credits, semester, faculty_id in courses:
        commit("course.upsert", {"code": code, "title": title, "credits": credits, "semester": semester,
                                 "faculty_id": faculty_id}, "seed")

    marks = {
        "UNI20260001": {"IT1010": (88, 91), "IT1020": (79, 84), "MA1030": (72, 75), "IT1040": (81, 86), "IT1050": None},
        "UNI20260002": {"IT1010": (65, 58), "IT1020": (70, 66), "MA1030": (55, 49), "IT1040": (62, 60)},
        "UNI20260003": {"IT1010": (92, 95), "IT1020": (88, 90), "MA1030": (85, 88), "IT1050": None},
        "UNI20260004": {"IT1010": (48, 42), "IT1020": (53, 39), "MA1030": (44, 36)},
        "UNI20260005": {"IT1010": (75, 71), "IT1020": (68, 73), "MA1030": (77, 80), "IT1040": (70, 74)},
        "UNI20260006": {"IT1010": (58, 62), "IT1020": (61, 55), "IT1050": None},
    }
    for sid, rows in marks.items():
        for code, score in rows.items():
            commit("enrollment.add", {"student_id": sid, "course_code": code}, "seed")
            if score:
                commit("mark.set", {"student_id": sid, "course_code": code, "coursework": score[0], "exam": score[1]},
                       "faculty.dev")

    reports = [
        ("REP-0001", "UNI20260001", "Semester progress", "Y1S1", "Consistently strong programming work and active in labs."),
        ("REP-0002", "UNI20260004", "Academic support plan", "Y1S1", "Exam marks are below coursework. Weekly tutoring is recommended."),
    ]
    for rid, sid, title, semester, body in reports:
        commit("report.add", {"id": rid, "student_id": sid, "title": title, "semester": semester, "body": body},
               "faculty.dev")

    commit("certificate.issue", {"id": "CERT-2026-0001", "student_id": "UNI20260001", "title": "Dean's List Award",
                                 "programme": programme, "issued_on": "2026-08-20", "code": "DEMO-NILA-2026"}, "seed")
    commit("certificate.issue", {"id": "CERT-2026-0002", "student_id": "UNI20260003", "title": "Dean's List Award",
                                 "programme": programme, "issued_on": "2026-08-20", "code": "DEMO-AISHA-2026"}, "seed")
