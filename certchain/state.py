"""In-memory read model rebuilt by replaying the off-chain records that match their
on-chain anchors. A record that fails its check is left out.
"""

# Grade scale used for results and GPA. Replace with the university's official scale.
GRADE_SCALE = [
    (90, "A+", 4.0), (80, "A", 4.0), (75, "A-", 3.7), (70, "B+", 3.3), (65, "B", 3.0), (60, "B-", 2.7),
    (55, "C+", 2.3), (45, "C", 2.0), (40, "C-", 1.7), (35, "D+", 1.3), (30, "D", 1.0), (0, "E", 0.0),
]
COURSEWORK_WEIGHT, EXAM_WEIGHT = 0.4, 0.6


def grade_for(total: float) -> tuple[str, float]:
    for floor, letter, points in GRADE_SCALE:
        if total >= floor:
            return letter, points
    return "E", 0.0


class State:
    def __init__(self):
        self.students: dict[str, dict] = {}
        self.faculty: dict[str, dict] = {}
        self.courses: dict[str, dict] = {}
        self.enrollments: set[tuple[str, str]] = set()
        self.marks: dict[tuple[str, str], dict] = {}
        self.reports: dict[str, dict] = {}
        self.certificates: dict[str, dict] = {}

    def apply(self, tx: dict, idx: int | None = None) -> None:
        kind, d = tx["type"], tx["data"]
        if kind == "student.upsert":
            self.students[d["id"]] = d
        elif kind == "faculty.upsert":
            self.faculty[d["id"]] = d
        elif kind == "course.upsert":
            self.courses[d["code"]] = d
        elif kind == "enrollment.add":
            self.enrollments.add((d["student_id"], d["course_code"]))
        elif kind == "enrollment.remove":
            self.enrollments.discard((d["student_id"], d["course_code"]))
        elif kind == "mark.set":
            key = (d["student_id"], d["course_code"])
            history = self.marks.get(key, {}).get("history", [])
            entry = {"coursework": d["coursework"], "exam": d["exam"], "by": tx["actor"], "at": tx["at"]}
            self.marks[key] = {**entry, "history": [*history, entry]}
        elif kind == "report.add":
            self.reports[d["id"]] = {**d, "by": tx["actor"], "at": tx["at"]}
        elif kind == "certificate.issue":
            self.certificates[d["id"]] = {**d, "status": "valid", "revoked_reason": None, "block": idx}
        elif kind == "certificate.revoke" and d["id"] in self.certificates:
            self.certificates[d["id"]].update(status="revoked", revoked_reason=d["reason"])

    # ---- derived views -----------------------------------------------------
    def result_row(self, student_id: str, code: str) -> dict:
        course = self.courses[code]
        lecturer = self.faculty.get(course.get("faculty_id") or "")
        row = {
            "code": code,
            "title": course["title"],
            "credits": course["credits"],
            "semester": course["semester"],
            "lecturer": lecturer["name"] if lecturer else None,
            "coursework": None, "exam": None, "total": None, "grade": None, "points": None,
        }
        mark = self.marks.get((student_id, code))
        if mark:
            total = round(mark["coursework"] * COURSEWORK_WEIGHT + mark["exam"] * EXAM_WEIGHT, 1)
            letter, points = grade_for(total)
            row.update(coursework=mark["coursework"], exam=mark["exam"], total=total, grade=letter, points=points)
        return row

    def results(self, student_id: str) -> dict:
        rows = sorted(
            (self.result_row(s, c) for s, c in self.enrollments if s == student_id and c in self.courses),
            key=lambda r: (r["semester"], r["code"]),
        )
        graded = [r for r in rows if r["points"] is not None]
        credits = sum(r["credits"] for r in graded)
        gpa = round(sum(r["points"] * r["credits"] for r in graded) / credits, 2) if credits else None
        return {"courses": rows, "gpa": gpa, "credits_earned": sum(r["credits"] for r in graded if r["points"] > 0)}

    def teaches(self, faculty_id: str, student_id: str) -> bool:
        return any(
            s == student_id and self.courses.get(c, {}).get("faculty_id") == faculty_id for s, c in self.enrollments
        )
