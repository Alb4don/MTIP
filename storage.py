from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .logging_setup import get_logger

log = get_logger("storage")

MIGRATIONS: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS sources (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        kind TEXT NOT NULL,
        url TEXT,
        created_at TEXT NOT NULL,
        last_import_at TEXT,
        alpha REAL NOT NULL DEFAULT 2.0,
        beta REAL NOT NULL DEFAULT 1.0,
        ts_quality TEXT NOT NULL DEFAULT 'unknown'
    );
    CREATE TABLE IF NOT EXISTS imports (
        id INTEGER PRIMARY KEY,
        source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
        received_at TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        objects_total INTEGER NOT NULL DEFAULT 0,
        accepted INTEGER NOT NULL DEFAULT 0,
        rejected INTEGER NOT NULL DEFAULT 0,
        duplicates INTEGER NOT NULL DEFAULT 0,
        ts_quality TEXT NOT NULL DEFAULT 'unknown',
        status TEXT NOT NULL,
        UNIQUE(source_id, content_sha256)
    );
    CREATE TABLE IF NOT EXISTS entities (
        id INTEGER PRIMARY KEY,
        etype TEXT NOT NULL,
        norm_name TEXT NOT NULL,
        display_name TEXT NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        UNIQUE(etype, norm_name)
    );
    CREATE TABLE IF NOT EXISTS entity_aliases (
        entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
        alias_norm TEXT NOT NULL,
        source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
        PRIMARY KEY(entity_id, alias_norm, source_id)
    );
    CREATE INDEX IF NOT EXISTS ix_alias_norm ON entity_aliases(alias_norm);
    CREATE TABLE IF NOT EXISTS stix_map (
        stix_id TEXT PRIMARY KEY,
        node_type TEXT NOT NULL,
        node_id INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS indicators (
        id INTEGER PRIMARY KEY,
        kind TEXT NOT NULL,
        value TEXT NOT NULL,
        root TEXT,
        shared_root INTEGER NOT NULL DEFAULT 0,
        first_seen TEXT,
        last_seen TEXT,
        analyst_verdict TEXT,
        UNIQUE(kind, value)
    );
    CREATE INDEX IF NOT EXISTS ix_ind_root ON indicators(root);
    CREATE TABLE IF NOT EXISTS observations (
        id INTEGER PRIMARY KEY,
        indicator_id INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
        source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
        import_id INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,
        stix_id TEXT,
        observed_at TEXT,
        raw_value TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_obs_ind ON observations(indicator_id);
    CREATE INDEX IF NOT EXISTS ix_obs_src ON observations(source_id);
    CREATE TABLE IF NOT EXISTS documented_edges (
        id INTEGER PRIMARY KEY,
        src_type TEXT NOT NULL,
        src_id INTEGER NOT NULL,
        dst_type TEXT NOT NULL,
        dst_id INTEGER NOT NULL,
        rel_type TEXT NOT NULL,
        source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
        import_id INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,
        stix_rel_id TEXT,
        observed_at TEXT,
        UNIQUE(src_type, src_id, dst_type, dst_id, rel_type, source_id)
    );
    CREATE INDEX IF NOT EXISTS ix_doc_src ON documented_edges(src_type, src_id);
    CREATE INDEX IF NOT EXISTS ix_doc_dst ON documented_edges(dst_type, dst_id);
    CREATE TABLE IF NOT EXISTS correlation_runs (
        id INTEGER PRIMARY KEY,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL,
        params TEXT NOT NULL,
        stats TEXT
    );
    CREATE TABLE IF NOT EXISTS inferred_edges (
        run_id INTEGER NOT NULL REFERENCES correlation_runs(id) ON DELETE CASCADE,
        src_type TEXT NOT NULL,
        src_id INTEGER NOT NULL,
        dst_type TEXT NOT NULL,
        dst_id INTEGER NOT NULL,
        rel_type TEXT NOT NULL,
        score REAL NOT NULL,
        p_value REAL,
        q_value REAL,
        basis TEXT NOT NULL,
        features TEXT NOT NULL,
        PRIMARY KEY(run_id, src_type, src_id, dst_type, dst_id, rel_type)
    );
    CREATE INDEX IF NOT EXISTS ix_inf_dst ON inferred_edges(run_id, dst_type, dst_id);
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY,
        created_at TEXT NOT NULL,
        src_type TEXT NOT NULL,
        src_id INTEGER NOT NULL,
        dst_type TEXT NOT NULL,
        dst_id INTEGER NOT NULL,
        rel_type TEXT NOT NULL,
        verdict TEXT NOT NULL CHECK (verdict IN ('confirm','reject')),
        features TEXT NOT NULL,
        sources TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_fb_edge ON feedback(src_type, src_id, dst_type, dst_id, rel_type);
    CREATE TABLE IF NOT EXISTS model_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS episodes (
        id INTEGER PRIMARY KEY,
        created_at TEXT NOT NULL,
        action TEXT NOT NULL,
        detail TEXT NOT NULL,
        outcome TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS metrics_history (
        id INTEGER PRIMARY KEY,
        created_at TEXT NOT NULL,
        run_id INTEGER,
        metrics TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY,
        created_at TEXT NOT NULL,
        client_hash TEXT NOT NULL,
        category TEXT NOT NULL,
        route TEXT NOT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS ix_obs_import ON observations(import_id);
    CREATE INDEX IF NOT EXISTS ix_episode_action ON episodes(action, created_at);
    """,
]


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Storage:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.RLock()
        self._connections: list[sqlite3.Connection] = []
        self._conn_lock = threading.Lock()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA trusted_schema=OFF")
        with self._conn_lock:
            self._connections.append(conn)
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        return conn

    def close(self) -> None:
        with self._conn_lock:
            for conn in self._connections:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
            self._connections.clear()
        self._local = threading.local()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._write_lock:
            conn = self.conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    def query(self, sql: str, params: tuple | list = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: tuple | list = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    def schema_version(self) -> int:
        return int(self.conn.execute("PRAGMA user_version").fetchone()[0])

    def backup(self, target_dir: Path) -> Path | None:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return None
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / f"mtip-v{self.schema_version()}-{int(time.time())}.sqlite3"
        dest = sqlite3.connect(target)
        try:
            self.conn.backup(dest)
        finally:
            dest.close()
        backups = sorted(target_dir.glob("mtip-v*.sqlite3"))
        for old in backups[:-5]:
            try:
                old.unlink()
            except OSError:
                pass
        return target

    def migrate(self, backup_dir: Path | None = None) -> int:
        current = self.schema_version()
        target = len(MIGRATIONS)
        if current > target:
            raise RuntimeError("database schema is newer than this application")
        if current == target:
            return current
        if backup_dir is not None and current > 0:
            self.backup(backup_dir)
        with self._write_lock:
            conn = self.conn
            for version in range(current, target):
                conn.execute("BEGIN IMMEDIATE")
                try:
                    for statement in _split_sql(MIGRATIONS[version]):
                        conn.execute(statement)
                    conn.execute(f"PRAGMA user_version={version + 1}")
                    conn.execute("COMMIT")
                except BaseException:
                    conn.execute("ROLLBACK")
                    raise
        log.info("schema migrated from=%s to=%s", current, target)
        return target

    def get_state(self, key: str, default: Any = None) -> Any:
        row = self.query_one("SELECT value FROM model_state WHERE key=?", (key,))
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except (TypeError, ValueError):
            return default

    def set_state(self, key: str, value: Any, conn: sqlite3.Connection | None = None) -> None:
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True)
        sql = "INSERT INTO model_state(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at"
        if conn is not None:
            conn.execute(sql, (key, payload, utcnow()))
        else:
            with self.transaction() as tx:
                tx.execute(sql, (key, payload, utcnow()))

    def record_episode(self, action: str, detail: dict, outcome: str) -> None:
        with self.transaction() as tx:
            tx.execute(
                "INSERT INTO episodes(created_at,action,detail,outcome) VALUES(?,?,?,?)",
                (utcnow(), action[:64], json.dumps(detail, separators=(",", ":"), default=str)[:8000], outcome[:64]),
            )
            tx.execute("DELETE FROM episodes WHERE id <= (SELECT MAX(id) FROM episodes) - 50000")


def _split_sql(script: str) -> list[str]:
    return [part.strip() for part in script.split(";") if part.strip()]
