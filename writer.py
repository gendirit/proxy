"""Общий writer-процесс для записи в SQLite.

Слушает сокет (TCP), принимает записи от воркеров uvicorn и пишет
их в SQLite пачками. Устраняет конкуренцию writer-потоков за SQLite
при нескольких воркерах.

Запуск:
    python writer.py --port 8001 --db state.db
"""

from __future__ import annotations

import argparse
import json
import socket
import sqlite3
import threading
import time

TTL_SECONDS = 3600
MAX_RECORDS = 100000
FLUSH_THRESHOLD = 2000


class WriterServer:
    """Сервер записи: принимает записи по сокету и пишет в SQLite пачками."""

    def __init__(self, host: str, port: int, db_path: str):
        self._host = host
        self._port = port
        self._db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=10000")
        self._conn.execute("PRAGMA synchronous=OFF")
        self._io_lock = threading.Lock()
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
            self._conn.commit()

    def _purge_expired(self) -> None:
        now = time.time()
        with self._io_lock:
            self._conn.execute("DELETE FROM records WHERE expires_at <= ?", (now,))
            self._conn.commit()

    def _evict_if_needed(self) -> None:
        with self._io_lock:
            count = self._conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
            if count > MAX_RECORDS:
                excess = count - MAX_RECORDS
                self._conn.execute(
                    "DELETE FROM records WHERE payload_id IN "
                    "(SELECT payload_id FROM records ORDER BY created_at ASC LIMIT ?)",
                    (excess,),
                )
                self._conn.commit()

    def _write_batch(self, batch: list) -> None:
        """Пишет пачку записей в SQLite одной транзакцией."""
        try:
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
                        for pid, rec in batch
                    ],
                )
                self._conn.commit()
        except Exception:  # noqa: BLE001
            pass

    def _handle_connection(self, conn: socket.socket) -> None:
        """Обрабатывает одно соединение: читает записи и пишет пачками."""
        buffer = b""
        batch = []
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                buffer += data
                # Разбираем JSON-сообщения (разделитель — новая строка)
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        msg = json.loads(line.decode("utf-8"))
                    except Exception:  # noqa: BLE001
                        continue
                    if msg.get("type") == "insert":
                        batch.append((msg["payload_id"], msg["record"]))
                        if len(batch) >= FLUSH_THRESHOLD:
                            self._write_batch(batch)
                            batch = []
                    elif msg.get("type") == "flush":
                        if batch:
                            self._write_batch(batch)
                            batch = []
                        conn.sendall(b'{"status":"ok"}\n')
        except Exception:  # noqa: BLE001
            pass
        finally:
            if batch:
                self._write_batch(batch)
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass

    def run(self) -> None:
        """Запускает сервер: слушает сокет и обрабатывает соединения."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self._host, self._port))
        server.listen(128)
        print(f"Writer server listening on {self._host}:{self._port}", flush=True)
        try:
            while True:
                conn, _ = server.accept()
                threading.Thread(target=self._handle_connection, args=(conn,), daemon=True).start()
        except KeyboardInterrupt:
            pass
        finally:
            server.close()
            self._conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Общий writer-процесс для SQLite")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--db", default="state.db")
    args = parser.parse_args()

    server = WriterServer(args.host, args.port, args.db)
    server.run()


if __name__ == "__main__":
    main()