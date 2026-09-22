"""SQLite-хранилище записей для сервиса маскирования ПД.

Заменяет in-memory StateStore, позволяя запускать несколько воркеров
uvicorn с общим хранилищем. Использует WAL-режим для конкурентного
чтения/записи и атомарные операции (INSERT OR IGNORE) для
межпроцессной идемпотентности.

Запуск:
    DB_PATH=state.db WORKERS=4 uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
import time
from collections import OrderedDict
from typing import Optional

TTL_SECONDS = 3600
MAX_RECORDS = 100000
CACHE_MAX_RECORDS = 100000

# Параметры батчинга записи (ленивая запись)
FLUSH_INTERVAL = 0.2        # сброс буфера каждые 200 мс
FLUSH_THRESHOLD = 1000      # сброс буфера при накоплении 1000 записей


class SQLiteStore:
    """SQLite-хранилище записей с TTL.

    Один connection на воркер (SQLite connection не потокобезопасен
    между процессами). Блокирующие операции выполняются через
    asyncio.to_thread с threading.Lock для сериализации.
    In-memory кэш записей ускоряет повторные чтения.
    Ленивая запись: новые записи попадают в буфер (_pending) и
    сбрасываются в SQLite пачками (по таймеру или при пороге).
    """

    def __init__(self, db_path: str = "state.db", ttl: int = TTL_SECONDS,
                 max_records: int = MAX_RECORDS):
        self._db_path = db_path
        self._ttl = ttl
        self._max_records = max_records
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=10000")
        self._conn.execute("PRAGMA synchronous=OFF")
        self._io_lock = threading.Lock()
        self._locks: dict[str, asyncio.Lock] = {}
        self._locks_guard = asyncio.Lock()
        self._cache: "OrderedDict[str, dict]" = OrderedDict()
        # Буфер несохранённых записей (ленивая запись)
        self._pending: "OrderedDict[str, dict]" = OrderedDict()
        self._pending_lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._io_lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS records (
                    payload_id TEXT PRIMARY KEY,
                    original_text TEXT NOT NULL,
                    original_hash TEXT NOT NULL,
                    masked_text TEXT NOT NULL,
                    masked_hash TEXT NOT NULL,
                    detected_types TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metrics (
                    name TEXT PRIMARY KEY,
                    value REAL NOT NULL
                )
                """
            )
            self._conn.commit()

    def flush_metrics(self, metrics: dict) -> None:
        """Сбрасывает in-memory метрики в SQLite (UPSERT, суммирование).

        metrics — плоский словарь {имя_метрики: значение}. Имена с метками
        (например, process_requests_total{status="200"}) кодируются как
        "process_requests_total|200".
        """
        if not metrics:
            return
        with self._io_lock:
            for name, value in metrics.items():
                self._conn.execute(
                    """
                    INSERT INTO metrics (name, value) VALUES (?, ?)
                    ON CONFLICT(name) DO UPDATE SET value = value + excluded.value
                    """,
                    (name, float(value)),
                )
            self._conn.commit()

    def read_metrics(self) -> dict:
        """Читает агрегированные метрики из SQLite."""
        with self._io_lock:
            rows = self._conn.execute("SELECT name, value FROM metrics").fetchall()
            return {row["name"]: row["value"] for row in rows}

    def ping(self) -> bool:
        """Проверяет доступность SQLite (SELECT 1). Возвращает True, если БД доступна."""
        try:
            with self._io_lock:
                self._conn.execute("SELECT 1").fetchone()
            return True
        except Exception:  # noqa: BLE001
            return False

    def clear_metrics(self) -> None:
        """Очищает таблицу метрик (для selftest)."""
        with self._io_lock:
            self._conn.execute("DELETE FROM metrics")
            self._conn.commit()

    def _now(self) -> float:
        return time.time()

    def _purge_expired(self) -> None:
        now = self._now()
        with self._io_lock:
            self._conn.execute("DELETE FROM records WHERE expires_at <= ?", (now,))
            self._conn.commit()

    def _evict_if_needed(self) -> None:
        with self._io_lock:
            count = self._conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
            if count > self._max_records:
                # Удаляем самые старые записи (по created_at)
                excess = count - self._max_records
                self._conn.execute(
                    "DELETE FROM records WHERE payload_id IN "
                    "(SELECT payload_id FROM records ORDER BY created_at ASC LIMIT ?)",
                    (excess,),
                )
                self._conn.commit()

    def _row_to_record(self, row: sqlite3.Row) -> dict:
        return {
            "payload_id": row["payload_id"],
            "original_text": row["original_text"],
            "original_hash": row["original_hash"],
            "masked_text": row["masked_text"],
            "masked_hash": row["masked_hash"],
            "detected_types": json.loads(row["detected_types"]),
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
        }

    async def get(self, payload_id: str) -> Optional[dict]:
        """Читает запись по payload_id. Возвращает None, если нет или истекла."""
        # Быстрый путь 1: проверяем буфер несохранённых записей
        with self._pending_lock:
            pending = self._pending.get(payload_id)
        if pending is not None:
            if pending["expires_at"] <= self._now():
                with self._pending_lock:
                    self._pending.pop(payload_id, None)
            else:
                return pending

        # Быстрый путь 2: проверяем in-memory кэш
        cached = self._cache.get(payload_id)
        if cached is not None:
            if cached["expires_at"] <= self._now():
                self._cache.pop(payload_id, None)
            else:
                self._cache.move_to_end(payload_id)
                return cached

        await asyncio.to_thread(self._purge_expired)
        now = self._now()

        def _get():
            with self._io_lock:
                row = self._conn.execute(
                    "SELECT * FROM records WHERE payload_id = ?", (payload_id,)
                ).fetchone()
                if row is None:
                    return None
                if row["expires_at"] <= now:
                    self._conn.execute(
                        "DELETE FROM records WHERE payload_id = ?", (payload_id,)
                    )
                    self._conn.commit()
                    return None
                return self._row_to_record(row)

        record = await asyncio.to_thread(_get)
        if record is not None:
            self._cache_put(payload_id, record)
        return record

    def _cache_put(self, payload_id: str, record: dict) -> None:
        self._cache[payload_id] = record
        self._cache.move_to_end(payload_id)
        while len(self._cache) > CACHE_MAX_RECORDS:
            self._cache.popitem(last=False)

    async def put(self, payload_id: str, record: dict) -> None:
        """Записывает или заменяет запись (INSERT OR REPLACE)."""
        await asyncio.to_thread(self._purge_expired)

        def _put():
            with self._io_lock:
                self._conn.execute(
                    """
                    INSERT OR REPLACE INTO records
                    (payload_id, original_text, original_hash, masked_text,
                     masked_hash, detected_types, created_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload_id,
                        record["original_text"],
                        record["original_hash"],
                        record["masked_text"],
                        record["masked_hash"],
                        json.dumps(record["detected_types"], ensure_ascii=False),
                        record["created_at"],
                        record["expires_at"],
                    ),
                )
                self._conn.commit()

        await asyncio.to_thread(_put)
        self._cache_put(payload_id, record)
        await asyncio.to_thread(self._evict_if_needed)

    async def insert_if_absent(self, payload_id: str, record: dict) -> bool:
        """Ленивая запись: добавляет запись в буфер, сбрасывает в SQLite пачками.

        Возвращает True, если запись добавлена в буфер (создана).
        Сброс в SQLite происходит по таймеру (200 мс) или при пороге (1000).
        """
        with self._pending_lock:
            if payload_id in self._pending:
                return False
            if payload_id in self._cache:
                return False
            self._pending[payload_id] = record
            self._cache_put(payload_id, record)
            should_flush = len(self._pending) >= FLUSH_THRESHOLD
        if should_flush:
            await self.flush_pending()
        return True

    async def flush_pending(self) -> None:
        """Сбрасывает буфер несохранённых записей в SQLite одной транзакцией."""
        with self._pending_lock:
            if not self._pending:
                return
            pending = list(self._pending.items())
            self._pending.clear()

        def _flush():
            with self._io_lock:
                self._conn.executemany(
                    """
                    INSERT OR IGNORE INTO records
                    (payload_id, original_text, original_hash, masked_text,
                     masked_hash, detected_types, created_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            pid,
                            rec["original_text"],
                            rec["original_hash"],
                            rec["masked_text"],
                            rec["masked_hash"],
                            json.dumps(rec["detected_types"], ensure_ascii=False),
                            rec["created_at"],
                            rec["expires_at"],
                        )
                        for pid, rec in pending
                    ],
                )
                self._conn.commit()

        await asyncio.to_thread(_flush)
        await asyncio.to_thread(self._evict_if_needed)

    async def get_lock(self, payload_id: str) -> asyncio.Lock:
        """Возвращает локальный asyncio.Lock для гонок в рамках одного процесса."""
        async with self._locks_guard:
            lock = self._locks.get(payload_id)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[payload_id] = lock
            return lock

    def close(self) -> None:
        with self._io_lock:
            self._conn.close()