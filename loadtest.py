"""Нагрузочный тест POST /process: RPS и p50/p95/p99 латентность.

Эмулирует поведение проверяющей системы: пары запросов
(маскирование -> демаскирование) с одним payload_id, keep-alive
соединения, повторное использование элементов датасета.

Запуск:
    uvicorn main:app --host 127.0.0.1 --port 8000 --workers 1
    python loadtest.py
"""

import json
import threading
import time
from http.client import HTTPConnection

HOST = "127.0.0.1"
PORT = 8000
PATH = "/process"

CONCURRENCY = 100         # одновременных keep-alive соединений
PAIRS_PER_WORKER = 20     # пар на поток => 2000 пар = 4000 запросов
TIMEOUT = 10

PAYLOADS = [
    "Иванов Иван Иванович, паспорт 4509 123456",
    "Петров Пётр Петрович, телефон +7 999 123-45-67",
    "Просто текст без персональных данных",
    "Сидорова Анна Сергеевна, email a.sidorova@example.com",
    "Карта 4509 1234 5678 9012, CVV 123, PIN 1234",
    "Адрес: г. Москва, ул. Тверская, д. 1, кв. 2, индекс 123456",
]

_lock = threading.Lock()
_latencies = []
_status_errors = {}
_exceptions = 0


def _record(lat, status):
    with _lock:
        if status == 200:
            _latencies.append(lat)
        else:
            _status_errors[status] = _status_errors.get(status, 0) + 1


def _record_exc():
    global _exceptions
    with _lock:
        _exceptions += 1


def _request(conn, payload, payload_id):
    body = json.dumps({"payload": payload, "payload_id": payload_id}).encode("utf-8")
    start = time.perf_counter()
    conn.request(
        "POST",
        PATH,
        body=body,
        headers={"Content-Type": "application/json", "Connection": "keep-alive"},
    )
    resp = conn.getresponse()
    data = resp.read()
    return time.perf_counter() - start, resp.status, data


def _reconnect():
    return HTTPConnection(HOST, PORT, timeout=TIMEOUT)


def _worker(idx):
    conn = _reconnect()
    for i in range(PAIRS_PER_WORKER):
        payload = PAYLOADS[i % len(PAYLOADS)]
        payload_id = "load-%d-%d" % (idx, i)

        # Прямая проверка (маскирование)
        try:
            lat, status, data = _request(conn, payload, payload_id)
        except Exception:
            _record_exc()
            try:
                conn.close()
            except Exception:
                pass
            conn = _reconnect()
            continue
        _record(lat, status)
        if status != 200:
            continue

        try:
            masked = json.loads(data.decode("utf-8"))["result"]
        except Exception:
            _record_exc()
            continue

        # Обратная проверка (демаскирование)
        try:
            lat2, status2, _ = _request(conn, masked, payload_id)
        except Exception:
            _record_exc()
            try:
                conn.close()
            except Exception:
                pass
            conn = _reconnect()
            continue
        _record(lat2, status2)

    try:
        conn.close()
    except Exception:
        pass


def _correctness_check():
    """Одна пара запросов до прогона: убеждаемся, что сервис вообще корректен."""
    conn = _reconnect()
    try:
        payload = "Клиент Иванов Иван Иванович, паспорт 4509 123456"
        pid = "load-correctness"
        _, status, data = _request(conn, payload, pid)
        if status != 200:
            return False, "mask status %d" % status
        masked = json.loads(data.decode("utf-8"))["result"]
        if masked == payload:
            return False, "mask equals original (PII not masked)"
        _, status, data = _request(conn, masked, pid)
        if status != 200:
            return False, "unmask status %d" % status
        unmasked = json.loads(data.decode("utf-8"))["result"]
        if unmasked != payload:
            return False, "unmask mismatch"
        return True, masked
    except Exception as exc:
        return False, str(exc)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _warmup():
    conn = _reconnect()
    try:
        for i in range(50):
            _request(conn, PAYLOADS[i % len(PAYLOADS)], "load-warmup-%d" % i)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    ok, info = _correctness_check()
    print("correctness: %s (%s)" % ("OK" if ok else "FAIL", info))
    if not ok:
        raise SystemExit(1)

    _warmup()

    threads = []
    start = time.perf_counter()
    for w in range(CONCURRENCY):
        t = threading.Thread(target=_worker, args=(w,), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - start

    lats = sorted(_latencies)
    n = len(lats)
    if n == 0:
        print("no successful requests")
        raise SystemExit(1)
    total = n + sum(_status_errors.values()) + _exceptions

    def pct(p):
        return lats[min(n - 1, int(n * p))] * 1000

    print("requests ok: %d" % n)
    print("http errors: %s" % (_status_errors or "none"))
    print("connection exceptions: %d" % _exceptions)
    print("elapsed: %.2fs" % elapsed)
    print("rps (ok): %.1f" % (n / elapsed))
    print("rps (all): %.1f" % (total / elapsed))
    print("p50: %.1f ms" % pct(0.50))
    print("p95: %.1f ms" % pct(0.95))
    print("p99: %.1f ms" % pct(0.99))
    print("max: %.1f ms" % (lats[-1] * 1000))


if __name__ == "__main__":
    main()