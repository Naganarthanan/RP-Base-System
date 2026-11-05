"""Shared constants and small helpers for the web layer."""
import re
import threading
import time
from collections import defaultdict, deque

DEV_ACCOUNTS = [
    {"username": "admin.dev", "password": "Admin@123", "role": "admin", "label": "University admin"},
    {"username": "faculty.dev", "password": "Faculty@123", "role": "faculty", "label": "Faculty member"},
    {"username": "student.dev", "password": "Student@123", "role": "student", "label": "Student"},
]

EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
CODE = re.compile(r"^[A-Z0-9-]{2,16}$")


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def clean(body: dict, required: tuple = (), optional: tuple = (), max_len: int = 500) -> dict:
    """Keep only the named string fields, trimmed and length-checked."""
    out = {}
    for key in (*required, *optional):
        value = body.get(key, "")
        value = "" if value is None else str(value).strip()
        if len(value) > max_len:
            raise ApiError(400, f"{key} is too long (limit {max_len} characters)")
        if key in required and not value:
            raise ApiError(400, f"{key.replace('_', ' ')} is required")
        out[key] = value
    return out


def check_email(value: str) -> None:
    if not EMAIL.match(value):
        raise ApiError(400, "email address is not valid")


def check_date(value: str, label: str = "date") -> None:
    if value and not DATE.match(value):
        raise ApiError(400, f"{label} must be YYYY-MM-DD")


def check_password(value: str) -> None:
    if len(value) < 10 or not re.search(r"[A-Za-z]", value) or not re.search(r"\d", value):
        raise ApiError(400, "password must be at least 10 characters and include letters and numbers")


class Throttle:
    """Sliding-window limiter held in memory, per process."""

    def __init__(self, limit: int, window: int):
        self.limit, self.window = limit, window
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def blocked(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            hits = self.hits[key]
            while hits and now - hits[0] > self.window:
                hits.popleft()
            return len(hits) >= self.limit

    def hit(self, key: str) -> None:
        with self.lock:
            self.hits[key].append(time.monotonic())

    def reset(self, key: str) -> None:
        with self.lock:
            self.hits.pop(key, None)
