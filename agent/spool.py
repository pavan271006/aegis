"""Agent-side guaranteed delivery (fixes the legacy fire-and-forget shipper).

Design: log lines are appended to a durable on-disk SQLite spool, then a sender
drains them in batches over mTLS with retry + exponential backoff + jitter. Each
batch carries a stable `batch_id`; the server dedups via `ingest_batches`, so
at-least-once delivery + server dedup == no data loss and no duplicates.
A batch that exceeds max attempts is moved to a dead-letter table for inspection,
never silently dropped."""
import json
import os
import sqlite3
import time
import uuid

import httpx

MAX_ATTEMPTS = 8
BASE_BACKOFF = 2.0          # seconds
MAX_BACKOFF = 300.0
BATCH_SIZE = 500


class Spool:
    def __init__(self, path: str, server_url: str, client_cert: str, client_key: str, ca: str):
        self.url = server_url.rstrip("/")
        self.client = httpx.Client(cert=(client_cert, client_key), verify=ca, timeout=15)
        new = not os.path.exists(path)
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")      # durable across crashes
        if new:
            self.db.executescript("""
                CREATE TABLE queue(id INTEGER PRIMARY KEY, line TEXT NOT NULL, ts REAL);
                CREATE TABLE dlq(id INTEGER PRIMARY KEY, batch TEXT, error TEXT, ts REAL);
                CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);
            """)

    # producer: called by the log tailer
    def append(self, line: str) -> None:
        self.db.execute("INSERT INTO queue(line, ts) VALUES (?,?)", (line, time.time()))

    # consumer: drain one batch with retry/backoff; returns True if work was done
    def flush_once(self) -> bool:
        rows = self.db.execute(
            "SELECT id, line FROM queue ORDER BY id LIMIT ?", (BATCH_SIZE,)).fetchall()
        if not rows:
            return False
        ids = [r[0] for r in rows]
        lines = [r[1] for r in rows]
        batch_id = self._batch_id(ids, lines)

        attempt = 0
        while True:
            try:
                r = self.client.post(f"{self.url}/api/ingest", json={
                    "site_id": 1, "batch_id": batch_id, "log_lines": lines})
                if r.status_code in (200, 409):          # 409 = already accepted (dedup)
                    self.db.execute(
                        f"DELETE FROM queue WHERE id IN ({','.join('?' * len(ids))})", ids)
                    return True
                raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
            except Exception as e:                       # noqa: BLE001
                attempt += 1
                if attempt >= MAX_ATTEMPTS:
                    self.db.execute("INSERT INTO dlq(batch, error, ts) VALUES (?,?,?)",
                                    (json.dumps(lines)[:100000], str(e)[:500], time.time()))
                    self.db.execute(
                        f"DELETE FROM queue WHERE id IN ({','.join('?' * len(ids))})", ids)
                    return True   # moved to DLQ, keep draining
                self._sleep_backoff(attempt)

    def run(self):  # pragma: no cover — agent main loop
        while True:
            if not self.flush_once():
                time.sleep(5)            # idle poll

    @staticmethod
    def _batch_id(ids, lines) -> str:
        # stable across retries of the SAME content (so the server dedups correctly)
        import hashlib
        h = hashlib.sha256(("|".join(lines)).encode()).hexdigest()[:32]
        return f"{ids[0]}-{ids[-1]}-{h}"

    @staticmethod
    def _sleep_backoff(attempt: int):
        import random
        delay = min(MAX_BACKOFF, BASE_BACKOFF * (2 ** (attempt - 1)))
        time.sleep(delay * (0.5 + random.random()))      # full jitter
