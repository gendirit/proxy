"""Тест RPS с уникальными payload_id на разнообразном датасете."""
import json
import threading
import time
from http.client import HTTPConnection

HOST = "127.0.0.1"
PORT = 8000
PATH = "/process"

CONCURRENCY = 100
PAIRS_PER_WORKER = 20
TIMEOUT = 10

PAYLOADS = [
    "Клиент Иванов Иван Иванович",
    "Дата рождения: 12.03.1990",
    "Паспорт 4509 123456",
    "Гражданство: Российская Федерация",
    "Водительское удостоверение серия 7701 номер 123456",
    "ИНН 7707083893",
    "Карта 4509 1234 5678 9012, CVV 123, PIN 1234",
    "Адрес: г. Москва, ул. Тверская, д. 1, кв. 2, индекс 123456",
    "Почта: ivanov@example.com",
    "Телефон: +7 999 123-45-67",
    "Держатель карты IVAN IVANOV",
    "Александр Пушкин родился в Москве",
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
    conn.request("POST", PATH, body=body,
                 headers={"Content-Type": "application/json", "Connection": "keep-alive"})
    resp = conn.getresponse()
    data = resp.read()
    return time.perf_counter() - start, resp.status, data


def _reconnect():
    return HTTPConnection(HOST, PORT, timeout=TIMEOUT)


def _worker(idx):
    conn = _reconnect()
    for i in range(PAIRS_PER_WORKER):
        payload = PAYLOADS[i % len(PAYLOADS)]
        payload_id = "uniq-%d-%d" % (idx, i)
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


def main():
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

    print("=" * 50)
    print("UNIQUE payload_id test: %d payloads, 4 workers, %d concurrency" % (len(PAYLOADS), CONCURRENCY))
    print("=" * 50)
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