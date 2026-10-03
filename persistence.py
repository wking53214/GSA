"""
persistence.py — durable, append-only audit + trace storage
===========================================================
Closes the "in-memory only, lost on restart" audit gap. Two backends behind one
interface:

  * MemoryAuditStore  — the original behavior (default; nothing persisted).
  * SqliteAuditStore  — file-backed, append-only chain + trace tables that survive
                        a restart. The same schema/queries port to PostgreSQL by
                        swapping the driver (psycopg) and the DSN; the SQL is plain.

Append-only is enforced by the interface: there is no update or delete method.
SQLite calls run under a threading.Lock and connections use check_same_thread=False
so they are safe to invoke from asyncio.to_thread on the gateway's hot path.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple


class AuditStore(ABC):
    @abstractmethod
    def append_block(self, block: Dict[str, Any]) -> None: ...
    @abstractmethod
    def load_chain(self) -> List[Dict[str, Any]]: ...
    @abstractmethod
    def save_trace(self, trace_id: str, tenant_id: Optional[str], created_at: str, bundle: Dict[str, Any]) -> None: ...
    @abstractmethod
    def get_trace(self, trace_id: str) -> Optional[Dict[str, Any]]: ...
    @abstractmethod
    def list_traces(self, tenant_id: str, limit: int, offset: int) -> Tuple[int, List[Dict[str, Any]]]: ...
    def close(self) -> None:  # optional
        pass


class MemoryAuditStore(AuditStore):
    """No durability — kept so 'memory' remains a first-class, explicit choice."""
    def __init__(self) -> None:
        self._chain: List[Dict[str, Any]] = []
        self._traces: Dict[str, Dict[str, Any]] = {}
        self._order: List[str] = []

    def append_block(self, block: Dict[str, Any]) -> None:
        self._chain.append(dict(block))

    def load_chain(self) -> List[Dict[str, Any]]:
        return [dict(b) for b in self._chain]

    def save_trace(self, trace_id, tenant_id, created_at, bundle) -> None:
        self._traces[trace_id] = {"tenant_id": tenant_id, "created_at": created_at, "bundle": bundle}
        self._order.append(trace_id)

    def get_trace(self, trace_id):
        return self._traces.get(trace_id)

    def list_traces(self, tenant_id, limit, offset):
        ids = [t for t in reversed(self._order) if self._traces[t]["tenant_id"] == tenant_id]
        return len(ids), [{"trace_id": t, **self._traces[t]} for t in ids[offset:offset + limit]]


class SqliteAuditStore(AuditStore):
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_chain ("
            "idx INTEGER PRIMARY KEY, timestamp REAL NOT NULL, record TEXT NOT NULL, "
            "previous_hash TEXT NOT NULL, hash TEXT NOT NULL)")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS traces ("
            "trace_id TEXT PRIMARY KEY, tenant_id TEXT, created_at TEXT NOT NULL, "
            "seq INTEGER, bundle_json TEXT NOT NULL)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS ix_traces_tenant ON traces(tenant_id, seq)")
        self._conn.commit()

    def append_block(self, block: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO audit_chain (idx,timestamp,record,previous_hash,hash) VALUES (?,?,?,?,?)",
                (block["index"], block["timestamp"], block["record"], block["previous_hash"], block["hash"]))
            self._conn.commit()

    def load_chain(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT idx,timestamp,record,previous_hash,hash FROM audit_chain ORDER BY idx ASC").fetchall()
        return [{"index": r[0], "timestamp": r[1], "record": r[2], "previous_hash": r[3], "hash": r[4]} for r in rows]

    def save_trace(self, trace_id, tenant_id, created_at, bundle) -> None:
        with self._lock:
            seq = self._conn.execute("SELECT COALESCE(MAX(seq),0)+1 FROM traces").fetchone()[0]
            self._conn.execute(
                "INSERT OR REPLACE INTO traces (trace_id,tenant_id,created_at,seq,bundle_json) VALUES (?,?,?,?,?)",
                (trace_id, tenant_id, created_at, seq, json.dumps(bundle)))
            self._conn.commit()

    def get_trace(self, trace_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT tenant_id,created_at,bundle_json FROM traces WHERE trace_id=?", (trace_id,)).fetchone()
        if not row:
            return None
        return {"tenant_id": row[0], "created_at": row[1], "bundle": json.loads(row[2])}

    def list_traces(self, tenant_id, limit, offset):
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM traces WHERE tenant_id=?", (tenant_id,)).fetchone()[0]
            rows = self._conn.execute(
                "SELECT trace_id,tenant_id,created_at,bundle_json FROM traces WHERE tenant_id=? "
                "ORDER BY seq DESC LIMIT ? OFFSET ?", (tenant_id, limit, offset)).fetchall()
        return total, [{"trace_id": r[0], "tenant_id": r[1], "created_at": r[2], "bundle": json.loads(r[3])} for r in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def make_store(backend: str, db_path: str = "gsa_audit.db") -> AuditStore:
    # An unknown backend used to fall through to MemoryAuditStore, so a typo
    # or an unimplemented choice (e.g. a Postgres DSN) silently lost the audit
    # chain on restart. Only the two implemented backends are accepted.
    if backend == "sqlite":
        return SqliteAuditStore(db_path)
    if backend == "memory":
        return MemoryAuditStore()
    raise ValueError(
        f"unsupported GSA_AUDIT_BACKEND {backend!r}: use 'sqlite' or 'memory'"
    )


if __name__ == "__main__":
    import os, tempfile
    p = os.path.join(tempfile.gettempdir(), "gsa_persist_demo.db")
    if os.path.exists(p):
        os.remove(p)
    s = SqliteAuditStore(p)
    s.append_block({"index": 1, "timestamp": 1.0, "record": "GENESIS", "previous_hash": "0", "hash": "abc"})
    s.append_block({"index": 2, "timestamp": 2.0, "record": "TRACE:xyz", "previous_hash": "abc", "hash": "def"})
    s.save_trace("TR-1", "tenant_A", "2026-06-19T00:00:00Z", {"status": 200})
    s.close()
    # reopen — simulating a process restart
    s2 = SqliteAuditStore(p)
    print("chain survived restart:", len(s2.load_chain()) == 2)
    print("trace survived restart:", s2.get_trace("TR-1") is not None)
    total, rows = s2.list_traces("tenant_A", 10, 0)
    print(f"list after restart: total={total} rows={len(rows)}")
    s2.close()
    os.remove(p)
