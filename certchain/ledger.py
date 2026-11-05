"""Simulated permissioned blockchain persisted in SQLite.

Every node keeps a full copy of the chain. Block payloads are AES-256-GCM encrypted
and each block hash is signed with Ed25519, so nothing readable is stored on-chain
and an edit to any copy is detected. The three nodes live in one database file: this
is a simulation of a network, not a distributed deployment.
"""
import hashlib
import json
import sqlite3
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .crypto import Keys

NODES = ("Registry-Node", "Academic-Board-Node", "Audit-Office-Node")
GENESIS_PREV = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks (
    node TEXT NOT NULL,
    idx INTEGER NOT NULL,
    ts TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    PRIMARY KEY (node, idx)
);
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    pw_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'faculty', 'student')),
    subject_id TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    must_change INTEGER NOT NULL DEFAULT 0
);
"""

COLUMNS = ("idx", "ts", "prev_hash", "nonce", "ciphertext", "hash", "signature")


class LedgerError(RuntimeError):
    pass


def block_digest(idx: int, ts: str, prev_hash: str, nonce: str, ciphertext: str) -> str:
    body = json.dumps([idx, ts, prev_hash, nonce, ciphertext], separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


class Ledger:
    def __init__(self, db_path: Path, keys: Keys):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.keys = keys
        self.lock = threading.RLock()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self.db.commit()
        if not self.db.execute("SELECT 1 FROM blocks LIMIT 1").fetchone():
            self._write_block({"type": "genesis", "data": {}, "actor": "system", "at": _now()}, GENESIS_PREV, 0, NODES)

    # ---- reading -----------------------------------------------------------
    def rows(self, node: str, limit: int | None = None, offset: int = 0, newest_first: bool = False) -> list[dict]:
        order = "DESC" if newest_first else "ASC"
        sql = f"SELECT {','.join(COLUMNS)} FROM blocks WHERE node=? ORDER BY idx {order}"
        args: list = [node]
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            args += [limit, offset]
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args)]

    def _check_chain(self, rows: list[dict]) -> int | None:
        """Return the index of the first invalid block, or None when the chain is sound."""
        prev = GENESIS_PREV
        for position, b in enumerate(rows):
            digest = block_digest(b["idx"], b["ts"], b["prev_hash"], b["nonce"], b["ciphertext"])
            if (
                b["idx"] != position
                or b["prev_hash"] != prev
                or b["hash"] != digest
                or not self.keys.verify(b["signature"], digest)
            ):
                return b["idx"]
            prev = b["hash"]
        return None

    def status(self) -> dict:
        nodes = []
        for name in NODES:
            rows = self.rows(name)
            bad = self._check_chain(rows)
            nodes.append(
                {
                    "node": name,
                    "height": len(rows),
                    "head": rows[-1]["hash"] if rows else None,
                    "valid": bad is None and bool(rows),
                    "bad_block": bad,
                }
            )
        votes = Counter(n["head"] for n in nodes if n["valid"])
        majority_head, count = votes.most_common(1)[0] if votes else (None, 0)
        has_majority = count > len(NODES) // 2
        for n in nodes:
            n["in_consensus"] = has_majority and n["valid"] and n["head"] == majority_head
        return {
            "nodes": nodes,
            "has_majority": has_majority,
            "healthy": has_majority and all(n["in_consensus"] for n in nodes),
            "height": next((n["height"] for n in nodes if n["in_consensus"]), 0),
            "head": majority_head if has_majority else None,
        }

    def majority_transactions(self) -> list[dict]:
        """Decrypted transactions of a chain that a majority of nodes agree on."""
        status = self.status()
        if not status["has_majority"]:
            raise LedgerError("No majority of nodes agree on a valid chain. Restore from a backup.")
        source = next(n["node"] for n in status["nodes"] if n["in_consensus"])
        return [self.keys.decrypt(b["nonce"], b["ciphertext"], str(b["idx"])) for b in self.rows(source)]

    # ---- writing -----------------------------------------------------------
    def append(self, tx_type: str, data: dict, actor: str) -> dict:
        with self.lock:
            heads = {
                r["node"]: (r["hash"], r["idx"])
                for r in self.db.execute(
                    "SELECT b.node, b.hash, b.idx FROM blocks b JOIN "
                    "(SELECT node, MAX(idx) AS top FROM blocks GROUP BY node) t "
                    "ON b.node=t.node AND b.idx=t.top"
                )
            }
            votes = Counter(heads.values())
            if not votes:
                raise LedgerError("Ledger is empty")
            (head, top), count = votes.most_common(1)[0]
            if count <= len(NODES) // 2:
                raise LedgerError("Writes are blocked: the nodes do not have a majority head.")
            targets = [n for n, h in heads.items() if h == (head, top)]
            tx = {"type": tx_type, "data": data, "actor": actor, "at": _now()}
            self._write_block(tx, head, top + 1, targets)
            return tx

    def _write_block(self, tx: dict, prev_hash: str, idx: int, nodes) -> None:
        nonce, ciphertext = self.keys.encrypt(tx, str(idx))
        ts = _now()
        digest = block_digest(idx, ts, prev_hash, nonce, ciphertext)
        signature = self.keys.sign(digest)
        with self.db:
            self.db.executemany(
                "INSERT INTO blocks (node, idx, ts, prev_hash, nonce, ciphertext, hash, signature) "
                "VALUES (?,?,?,?,?,?,?,?)",
                [(n, idx, ts, prev_hash, nonce, ciphertext, digest, signature) for n in nodes],
            )

    def repair(self) -> list[str]:
        """Replace every node outside consensus with a copy of the majority chain."""
        with self.lock:
            status = self.status()
            if not status["has_majority"]:
                raise LedgerError("Cannot repair: no majority of nodes agree on a valid chain.")
            source = next(n["node"] for n in status["nodes"] if n["in_consensus"])
            rows = self.rows(source)
            repaired = [n["node"] for n in status["nodes"] if not n["in_consensus"]]
            with self.db:
                for name in repaired:
                    self.db.execute("DELETE FROM blocks WHERE node=?", (name,))
                    self.db.executemany(
                        "INSERT INTO blocks (node, idx, ts, prev_hash, nonce, ciphertext, hash, signature) "
                        "VALUES (?,?,?,?,?,?,?,?)",
                        [(name, *[b[c] for c in COLUMNS]) for b in rows],
                    )
            return repaired

    def tamper(self, node: str, idx: int) -> bool:
        """Development only: corrupt one stored copy to demonstrate detection."""
        with self.lock, self.db:
            row = self.db.execute("SELECT ciphertext FROM blocks WHERE node=? AND idx=?", (node, idx)).fetchone()
            if not row:
                return False
            text = row["ciphertext"]
            flipped = ("A" if text[0] != "A" else "B") + text[1:]
            self.db.execute("UPDATE blocks SET ciphertext=? WHERE node=? AND idx=?", (flipped, node, idx))
            return True


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
