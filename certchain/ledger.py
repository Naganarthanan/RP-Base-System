"""Simulated permissioned blockchain persisted in SQLite.

Full transactions live off-chain in the `records` table. Each block on the chain holds
only an anchor for one transaction (see anchors.py), linked to the previous block by
SHA-256. Every node keeps a full copy of the chain. The three nodes live in one
database file: this is a simulation of a network, not a distributed deployment.
"""
import hashlib
import json
import sqlite3
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .anchors import canonical

NODES = ("Registry-Node", "Academic-Board-Node", "Audit-Office-Node")
GENESIS_PREV = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks (
    node TEXT NOT NULL,
    idx INTEGER NOT NULL,
    ts TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    anchor TEXT NOT NULL,
    hash TEXT NOT NULL,
    PRIMARY KEY (node, idx)
);
CREATE TABLE IF NOT EXISTS records (
    idx INTEGER PRIMARY KEY,
    tx TEXT NOT NULL
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

COLUMNS = ("idx", "ts", "prev_hash", "anchor", "hash")


class LedgerError(RuntimeError):
    pass


def block_digest(idx: int, ts: str, prev_hash: str, anchor: str) -> str:
    body = json.dumps([idx, ts, prev_hash, anchor], separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


class Ledger:
    def __init__(self, db_path: Path, anchor, wal: bool = True):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.anchor = anchor
        self.lock = threading.RLock()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        if wal:
            self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self.db.commit()
        self.last_audit = {"checked": 0, "failed": []}
        if not self.db.execute("SELECT 1 FROM blocks LIMIT 1").fetchone():
            tx = {"type": "genesis", "data": {}, "actor": "system", "at": _now()}
            with self.db:
                self.db.execute("INSERT INTO records (idx, tx) VALUES (0, ?)", (canonical(tx),))
                self._write_block(tx, GENESIS_PREV, 0, NODES)

    def close(self) -> None:
        with self.lock:
            self.db.close()

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

    @staticmethod
    def _check_chain(rows: list[dict]) -> int | None:
        """Return the index of the first invalid block, or None when the chain is sound."""
        prev = GENESIS_PREV
        for position, b in enumerate(rows):
            digest = block_digest(b["idx"], b["ts"], b["prev_hash"], b["anchor"])
            if b["idx"] != position or b["prev_hash"] != prev or b["hash"] != digest:
                return b["idx"]
            prev = b["hash"]
        return None

    def status(self) -> dict:
        nodes = []
        for name in NODES:
            rows = self.rows(name)
            bad = self._check_chain(rows)
            nodes.append({
                "node": name,
                "height": len(rows),
                "head": rows[-1]["hash"] if rows else None,
                "valid": bad is None and bool(rows),
                "bad_block": bad,
            })
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

    def majority_node(self) -> str:
        status = self.status()
        if not status["has_majority"]:
            raise LedgerError("No majority of nodes agree on a valid chain. Restore from a backup.")
        return next(n["node"] for n in status["nodes"] if n["in_consensus"])

    def anchors(self) -> dict[int, dict]:
        """Anchors of the chain that a majority of nodes agree on, by block index."""
        return {b["idx"]: json.loads(b["anchor"]) for b in self.rows(self.majority_node())}

    def record(self, idx: int) -> dict | None:
        with self.lock:
            row = self.db.execute("SELECT tx FROM records WHERE idx=?", (idx,)).fetchone()
        return json.loads(row["tx"]) if row else None

    def verify_record(self, idx: int) -> bool:
        """Check one off-chain record against its anchor on the majority chain."""
        tx = self.record(idx)
        anchors = self.anchors()
        return tx is not None and idx in anchors and self.anchor.verify(anchors[idx], tx)

    def verified_transactions(self) -> list[tuple[int, dict]]:
        """Off-chain records that match their on-chain anchors. The others are skipped."""
        anchors = self.anchors()
        with self.lock:
            stored = {r["idx"]: json.loads(r["tx"]) for r in self.db.execute("SELECT idx, tx FROM records")}
        good, failed = [], []
        for idx in sorted(set(anchors) | set(stored)):
            tx = stored.get(idx)
            if tx is not None and idx in anchors and self.anchor.verify(anchors[idx], tx):
                good.append((idx, tx))
            else:
                failed.append(idx)
        self.last_audit = {"checked": len(anchors), "failed": failed}
        return good

    # ---- writing -----------------------------------------------------------
    def append(self, tx_type: str, data: dict, actor: str) -> tuple[int, dict]:
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
            idx = top + 1
            with self.db:
                self.db.execute("INSERT OR REPLACE INTO records (idx, tx) VALUES (?, ?)", (idx, canonical(tx)))
                self._write_block(tx, head, idx, targets)
            return idx, tx

    def _write_block(self, tx: dict, prev_hash: str, idx: int, nodes) -> None:
        anchor = canonical(self.anchor.build(tx))
        ts = _now()
        digest = block_digest(idx, ts, prev_hash, anchor)
        self.db.executemany(
            "INSERT INTO blocks (node, idx, ts, prev_hash, anchor, hash) VALUES (?,?,?,?,?,?)",
            [(n, idx, ts, prev_hash, anchor, digest) for n in nodes],
        )

    def rewrite_node(self, node: str, idx: int, anchor: dict) -> None:
        """Replace one block's anchor on one node and re-link every later block.

        Unkeyed SHA-256 links mean anyone with write access to a node can do this.
        It is used by the security check to model a compromised organisation."""
        with self.lock, self.db:
            rows = self.rows(node)
            prev = rows[idx - 1]["hash"] if idx else GENESIS_PREV
            for b in rows[idx:]:
                text = canonical(anchor) if b["idx"] == idx else b["anchor"]
                digest = block_digest(b["idx"], b["ts"], prev, text)
                self.db.execute("UPDATE blocks SET prev_hash=?, anchor=?, hash=? WHERE node=? AND idx=?",
                                (prev, text, digest, node, b["idx"]))
                prev = digest

    def append_to_nodes(self, nodes, tx: dict, anchor: dict) -> int:
        """Append a block carrying a chosen anchor to some nodes only (security check)."""
        with self.lock, self.db:
            head = self.rows(nodes[0], 1, 0, newest_first=True)[0]
            idx, ts, text = head["idx"] + 1, _now(), canonical(anchor)
            digest = block_digest(idx, ts, head["hash"], text)
            self.db.execute("INSERT OR REPLACE INTO records (idx, tx) VALUES (?, ?)", (idx, canonical(tx)))
            self.db.executemany(
                "INSERT INTO blocks (node, idx, ts, prev_hash, anchor, hash) VALUES (?,?,?,?,?,?)",
                [(n, idx, ts, head["hash"], text, digest) for n in nodes],
            )
            return idx

    def overwrite_record(self, idx: int, tx: dict) -> None:
        with self.lock, self.db:
            self.db.execute("UPDATE records SET tx=? WHERE idx=?", (canonical(tx), idx))

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
                        "INSERT INTO blocks (node, idx, ts, prev_hash, anchor, hash) VALUES (?,?,?,?,?,?)",
                        [(name, *[b[c] for c in COLUMNS]) for b in rows],
                    )
            return repaired

    def tamper(self, node: str, idx: int) -> bool:
        """Development only: corrupt one stored copy to demonstrate detection."""
        with self.lock, self.db:
            row = self.db.execute("SELECT anchor FROM blocks WHERE node=? AND idx=?", (node, idx)).fetchone()
            if not row:
                return False
            anchor = json.loads(row["anchor"])
            anchor["tampered"] = True
            self.db.execute("UPDATE blocks SET anchor=? WHERE node=? AND idx=?", (canonical(anchor), node, idx))
            return True


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
