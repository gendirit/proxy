"""
MVP-монолит сервиса POST /process для маскирования/демаскирования ПД.

Запуск:
    uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
    python main.py --selftest

Контракт:
    POST /process
    Request:  {"payload": str, "payload_id": str}
    Response: {"result": str}

Коды ответов:
    200 — успех
    422 — стандартная ошибка валидации FastAPI
    429 — перегрузка / таймаут / не удалось получить блокировку
    409 — никогда не возвращается
"""

import asyncio
import hashlib
import json
import logging
import multiprocessing
import os
import sys
import tempfile
import time
from collections import OrderedDict
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from detectors import mask_payload, redact_for_logging, detect_spans, apply_spans
from store import SQLiteStore

# ---------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------

TTL_SECONDS = 3600
MAX_RECORDS = 100000
LOCK_TIMEOUT = 1.0
PROCESS_TIMEOUT = 8.0
LARGE_TEXT_THRESHOLD = 20000

CONFIG_PATH = "config.json"


def _default_workers() -> int:
    """Автоопределение числа воркеров по количеству ядер CPU.

    Детекторы — CPU-интенсивные, поэтому оставляем одно ядро для ОС.
    """
    cpus = multiprocessing.cpu_count() or 1
    return max(1, cpus - 1)


# Переменные окружения для многопроцессного запуска
DB_PATH = os.environ.get("DB_PATH", "state.db")
# WORKERS: если задан через env — используем его, иначе автоопределение по CPU
WORKERS = int(os.environ.get("WORKERS", str(_default_workers())))

_DEFAULT_SYSTEM = {
    "enabled": True,
    "pii_types": ["ALL"],
    "allow_unmask": True,
}


def _load_config() -> dict:
    """Загружает config.json. При ошибке — дефолты и warning в лог."""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            raise ValueError("config root must be an object")
        return cfg
    except Exception as exc:  # noqa: BLE001
        logger.warning("config.json not loaded, using defaults: %s", exc)
        return {}


def _resolve_system(cfg: dict, system_id: Optional[str]) -> Optional[dict]:
    """Возвращает настройки системы по X-System-Id или default_system."""
    if not system_id:
        return cfg.get("default_system", _DEFAULT_SYSTEM)
    for sys_cfg in cfg.get("systems", []):
        if sys_cfg.get("name") == system_id:
            return sys_cfg
    return None

# ---------------------------------------------------------------------------
# Логирование (безопасное)
# ---------------------------------------------------------------------------


class RedactFilter(logging.Filter):
    """Заменяет типовые ПД в сообщениях лога на [REDACTED]."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
            redacted = redact_for_logging(msg)
            if redacted != msg:
                record.msg = redacted
                record.args = ()
        except Exception:
            pass
        return True


def _setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(RedactFilter())
    logging.basicConfig(
        level=logging.INFO,
        handlers=[handler],
        format="%(asctime)s %(levelname)s %(message)s",
    )


logger = logging.getLogger("process")


def _log_json(**fields) -> None:
    """Логирует JSON-строку. Никогда не содержит исходный/маскированный текст."""
    logger.info(json.dumps(fields, ensure_ascii=False, default=str))


# ---------------------------------------------------------------------------
# State Store (SQLite, общее хранилище для нескольких воркеров)
# Реализация в store.py (класс SQLiteStore).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Pydantic-схемы
# ---------------------------------------------------------------------------


class ProcessRequest(BaseModel):
    payload: str = Field(default="")
    payload_id: str = Field(default="")


class ProcessResponse(BaseModel):
    result: str


# ---------------------------------------------------------------------------
# Direction Resolver
# ---------------------------------------------------------------------------


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _looks_like_mask(payload: str, masked_text: str) -> bool:
    """Эвристика: похож ли payload на сохранённую маску."""
    if payload.strip() == masked_text.strip():
        return True
    if "*" in payload and abs(len(payload) - len(masked_text)) <= 4:
        return True
    return False


CACHE_MAX_RECORDS = 100000
_RESULT_CACHE: "OrderedDict[str, tuple[str, list[str]]]" = OrderedDict()
_SPAN_CACHE: "OrderedDict[str, list]" = OrderedDict()


def _cache_get(payload_hash: str) -> Optional[tuple[str, list[str]]]:
    """LRU-чтение из кэша результатов маскирования."""
    value = _RESULT_CACHE.get(payload_hash)
    if value is not None:
        _RESULT_CACHE.move_to_end(payload_hash)
    return value


def _cache_put(payload_hash: str, value: tuple[str, list[str]]) -> None:
    """LRU-запись в кэш результатов маскирования."""
    _RESULT_CACHE[payload_hash] = value
    _RESULT_CACHE.move_to_end(payload_hash)
    while len(_RESULT_CACHE) > CACHE_MAX_RECORDS:
        _RESULT_CACHE.popitem(last=False)


def _span_cache_get(payload_hash: str):
    """LRU-чтение из кэша спанов."""
    value = _SPAN_CACHE.get(payload_hash)
    if value is not None:
        _SPAN_CACHE.move_to_end(payload_hash)
    return value


def _span_cache_put(payload_hash: str, spans) -> None:
    """LRU-запись в кэш спанов."""
    _SPAN_CACHE[payload_hash] = spans
    _SPAN_CACHE.move_to_end(payload_hash)
    while len(_SPAN_CACHE) > CACHE_MAX_RECORDS:
        _SPAN_CACHE.popitem(last=False)


class ProcessService:
    def __init__(self, store: StateStore, system_cfg: Optional[dict] = None,
                 system_name: str = "default"):
        self._store = store
        self._system_cfg = system_cfg or _DEFAULT_SYSTEM
        self._system_name = system_name

    def _allowed_types(self):
        pii = self._system_cfg.get("pii_types", ["ALL"])
        if pii == ["ALL"]:
            return None
        return pii

    def _allow_unmask(self) -> bool:
        return bool(self._system_cfg.get("allow_unmask", True))

    def _cache_key(self, payload: str) -> str:
        pii = self._system_cfg.get("pii_types", ["ALL"])
        joined = ",".join(sorted(pii))
        return _sha256(payload + "|" + self._system_name + "|" + joined)

    async def process(self, payload: str, payload_id: str) -> tuple[str, list[str], str]:
        """Основная логика: направление, идемпотентность, гонки.

        Возвращает (результат, список обнаруженных типов ПД, направление).
"""
        lock = await self._store.get_lock(payload_id)
        try:
            acquired = await asyncio.wait_for(lock.acquire(), timeout=LOCK_TIMEOUT)
        except asyncio.TimeoutError:
            raise ProcessBusyError()
        if not acquired:
            raise ProcessBusyError()

        try:
            return await self._process_locked(payload, payload_id)
        finally:
            lock.release()

    async def _process_locked(self, payload: str, payload_id: str) -> tuple[str, list[str], str]:
        # Повторная проверка после получения блокировки (double-check)
        record = await self._store.get(payload_id)

        if record is None:
            # Новый payload_id: маскируем, сохраняем, возвращаем маску
            payload_hash = self._cache_key(payload)
            cached = _cache_get(payload_hash)
            if cached is not None:
                masked, detected = cached
            else:
                # Пробуем кэш спанов (учитывает систему и pii_types)
                spans = _span_cache_get(payload_hash)
                if spans is not None:
                    masked, detected = apply_spans(payload, spans, self._allowed_types())
                else:
                    masked, detected = await self._run_mask(payload)
                    _span_cache_put(payload_hash, detect_spans(payload))
                _cache_put(payload_hash, (masked, detected))
            now = time.time()
            new_record = {
                "payload_id": payload_id,
                "original_text": payload,
                "original_hash": _sha256(payload),
                "masked_text": masked,
                "masked_hash": _sha256(masked),
                "detected_types": detected,
                "created_at": now,
                "expires_at": now + TTL_SECONDS,
            }
            # Атомарная вставка: если запись уже создана другим воркером,
            # insert_if_absent вернёт False — читаем существующую запись.
            created = await self._store.insert_if_absent(payload_id, new_record)
            if created:
                return masked, detected, "mask"
            record = await self._store.get(payload_id)
            if record is None:
                # Редкий случай: запись удалена между операциями — повторяем маскирование
                return masked, detected, "mask"

        # Запись есть — определяем направление по хэшу
        payload_hash = _sha256(payload)
        original_hash = record["original_hash"]
        masked_hash = record["masked_hash"]
        original_text = record["original_text"]
        masked_text = record["masked_text"]

        if payload_hash == original_hash or payload == original_text:
            # Пришёл оригинал -> вернуть сохранённую маску
            return masked_text, record["detected_types"], "mask"

        if payload_hash == masked_hash or payload == masked_text:
            # Пришла маска -> вернуть сохранённый оригинал
            if not self._allow_unmask():
                return masked_text, record["detected_types"], "unmask"
            return original_text, record["detected_types"], "unmask"

        if original_text == masked_text:
            # ПД нет, маска == оригинал
            return payload, [], "identity"

        # Спорный случай: хэш не совпал. Запись НЕ обновляем, НЕ перемаскируем.
        if _looks_like_mask(payload, masked_text):
            result = original_text if self._allow_unmask() else masked_text
            direction = "unmask"
        else:
            result = masked_text
            direction = "mask"
        return result, record["detected_types"], direction

    async def _run_mask(self, payload: str) -> tuple[str, list[str]]:
        """Выполняет маскирование.

        Для коротких текстов (<= 2000) — синхронно в event loop,
        для больших — в отдельном потоке.
        """
        allowed = self._allowed_types()
        if len(payload) > 2000:
            return await asyncio.wait_for(
                asyncio.to_thread(mask_payload, payload, allowed), timeout=PROCESS_TIMEOUT
            )
        return mask_payload(payload, allowed)


class ProcessBusyError(Exception):
    """Перегрузка: не удалось получить блокировку или таймаут обработки."""


# ---------------------------------------------------------------------------
# Metrics (Prometheus text format, без внешних библиотек)
# ---------------------------------------------------------------------------

_metrics_lock = asyncio.Lock()
_metrics = {
    "process_requests_total": {},   # {status: count}
    "process_latency_seconds_sum": 0.0,
    "process_latency_seconds_count": 0,
    "process_detected_total": {},   # {type: count}
    "process_429_total": 0,
    "process_tokens_total": 0,
}


def _metric_inc(name: str, value: int = 1, label: str = None) -> None:
    if label is None:
        _metrics[name] = _metrics.get(name, 0) + value
    else:
        bucket = _metrics.setdefault(name, {})
        bucket[label] = bucket.get(label, 0) + value


def _metric_observe_latency(seconds: float) -> None:
    _metrics["process_latency_seconds_sum"] += seconds
    _metrics["process_latency_seconds_count"] += 1


def _metric_add_tokens(tokens: int) -> None:
    _metrics["process_tokens_total"] += tokens


def _metric_add_detected(types: list) -> None:
    for t in types:
        _metric_inc("process_detected_total", 1, t)


def _metric_flatten() -> dict:
    """Преобразует вложенные метрики в плоский словарь для SQLite."""
    flat = {}
    for name, value in _metrics.items():
        if isinstance(value, dict):
            for label, count in value.items():
                flat["%s|%s" % (name, label)] = count
        else:
            flat[name] = value
    return flat


def _flush_metrics() -> None:
    """Сбрасывает in-memory метрики в SQLite и обнуляет локальные."""
    flat = _metric_flatten()
    if not flat:
        return
    _store.flush_metrics(flat)
    # Обнуляем локальные счётчики (после сброса)
    for name in list(_metrics.keys()):
        if isinstance(_metrics[name], dict):
            _metrics[name] = {}
        else:
            _metrics[name] = 0


async def _metrics_flush_loop() -> None:
    """Фоновая задача: периодический сброс метрик в SQLite (раз в 1 сек)."""
    while True:
        await asyncio.sleep(1.0)
        try:
            async with _metrics_lock:
                _flush_metrics()
        except Exception:  # noqa: BLE001
            pass


async def _records_flush_loop() -> None:
    """Фоновая задача: периодический сброс буфера записей в SQLite (раз в 200 мс)."""
    while True:
        await asyncio.sleep(0.2)
        try:
            await _store.flush_pending()
        except Exception:  # noqa: BLE001
            pass


def _render_metrics() -> str:
    """Рендерит метрики в Prometheus-формат из SQLite (агрегированные)."""
    data = _store.read_metrics()
    lines = []
    # process_requests_total{status="200"}
    for key, count in sorted(data.items()):
        if key.startswith("process_requests_total|"):
            status = key.split("|", 1)[1]
            lines.append("process_requests_total{status=\"" + status + "\"} " + str(int(count)))
    # process_detected_total{type="FIO"}
    for key, count in sorted(data.items()):
        if key.startswith("process_detected_total|"):
            t = key.split("|", 1)[1]
            lines.append("process_detected_total{type=\"" + t + "\"} " + str(int(count)))
    lines.append("process_latency_seconds_sum " + str(data.get("process_latency_seconds_sum", 0)))
    lines.append("process_latency_seconds_count " + str(int(data.get("process_latency_seconds_count", 0))))
    lines.append("process_429_total " + str(int(data.get("process_429_total", 0))))
    lines.append("process_tokens_total " + str(int(data.get("process_tokens_total", 0))))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="PII Masking Service")
_store = SQLiteStore(DB_PATH)
_config = _load_config()
_service = ProcessService(_store, _config.get("default_system", _DEFAULT_SYSTEM))


@app.on_event("startup")
async def _startup() -> None:
    """Запускает фоновые задачи: сброс метрик и буфера записей в SQLite."""
    asyncio.create_task(_metrics_flush_loop())
    asyncio.create_task(_records_flush_loop())


@app.on_event("shutdown")
async def _shutdown() -> None:
    """Сбрасывает метрики и буфер записей, закрывает хранилище."""
    try:
        async with _metrics_lock:
            _flush_metrics()
    except Exception:  # noqa: BLE001
        pass
    try:
        await _store.flush_pending()
    except Exception:  # noqa: BLE001
        pass
    _store.close()


@app.exception_handler(ProcessBusyError)
async def _busy_handler(request: Request, exc: ProcessBusyError):
    return JSONResponse(
        status_code=429,
        content={"result": ""},
        headers={"Retry-After": "1"},
    )


@app.post("/process")
async def process_endpoint(request: Request):
    start = time.time()
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse(status_code=422, content={"result": ""})
    payload = body.get("payload") if isinstance(body, dict) else None
    payload_id = body.get("payload_id") if isinstance(body, dict) else None
    if not isinstance(payload, str) or not isinstance(payload_id, str):
        return JSONResponse(status_code=422, content={"result": ""})

    system_id = request.headers.get("X-System-Id")
    system_name = system_id or "default"
    system_cfg = _resolve_system(_config, system_id)
    if system_cfg is None or not system_cfg.get("enabled", True):
        _log_json(
            event="request",
            payload_id=payload_id,
            status=403,
            duration_ms=round((time.time() - start) * 1000, 2),
            direction="",
            detected_types=[],
            entity_count=0,
        )
        _metric_inc("process_requests_total", 1, "403")
        return JSONResponse(status_code=403, content={"result": ""})
    service = ProcessService(_store, system_cfg, system_name)
    try:
        result, detected, direction = await service.process(payload, payload_id)
        duration_ms = (time.time() - start) * 1000
        _log_json(
            event="request",
            payload_id=payload_id,
            status=200,
            duration_ms=round(duration_ms, 2),
            direction=direction,
            detected_types=detected,
            entity_count=len(detected),
        )
        _metric_inc("process_requests_total", 1, "200")
        _metric_observe_latency(duration_ms / 1000.0)
        _metric_add_tokens(len(payload) // 4)
        _metric_add_detected(detected)
        return JSONResponse(content={"result": result})
    except ProcessBusyError:
        duration_ms = (time.time() - start) * 1000
        _log_json(
            event="request",
            payload_id=payload_id,
            status=429,
            duration_ms=round(duration_ms, 2),
            direction="",
            detected_types=[],
            entity_count=0,
        )
        _metric_inc("process_requests_total", 1, "429")
        _metric_inc("process_429_total", 1)
        return JSONResponse(
            status_code=429,
            content={"result": ""},
            headers={"Retry-After": "1"},
        )
    except Exception as exc:  # noqa: BLE001
        duration_ms = (time.time() - start) * 1000
        _log_json(
            event="request",
            payload_id=payload_id,
            status=500,
            duration_ms=round(duration_ms, 2),
            direction="",
            detected_types=[],
            entity_count=0,
            error=str(exc),
        )
        _metric_inc("process_requests_total", 1, "500")
        return JSONResponse(
            status_code=429,
            content={"result": ""},
            headers={"Retry-After": "1"},
        )


@app.get("/metrics")
async def metrics_endpoint():
    async with _metrics_lock:
        _flush_metrics()
        return Response(content=_render_metrics(), media_type="text/plain")


# ---------------------------------------------------------------------------
# LLM-прокси (демо, без сетевых вызовов)
# ---------------------------------------------------------------------------


def mock_llm(masked: str) -> str:
    """Демо-LLM: короткий ответ, использующий токены из маски."""
    tokens = []
    for part in masked.split():
        if part.startswith("[") and part.endswith("]"):
            tokens.append(part)
    if tokens:
        return "Получены данные: " + ", ".join(tokens) + ". Обработано."
    return "Данных не найдено."


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage]


class ChatResponse(BaseModel):
    result: str
    masked_prompt: str


@app.post("/v1/chat/completions", response_model=ChatResponse)
async def chat_completions(req: ChatRequest):
    joined = "\n".join(m.content for m in req.messages)
    masked, detected, token_map = mask_payload(joined, mode="tokenize")
    llm_out = mock_llm(masked)
    result = llm_out
    for token, value in token_map.items():
        result = result.replace(token, value)
    return ChatResponse(result=result, masked_prompt=masked)


# ---------------------------------------------------------------------------
# Selftest (устойчив к формату маски)
# ---------------------------------------------------------------------------


async def _run_selftest() -> bool:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    store = SQLiteStore(tmp.name)
    service = ProcessService(store)
    checks = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        checks.append((name, cond))
        status = "OK" if cond else "FAIL"
        msg = f"  [{status}] {name}"
        if detail and not cond:
            msg += f"  ({detail})"
        print(msg)

    async def _proc(payload: str, payload_id: str) -> str:
        result, _, _ = await service.process(payload, payload_id)
        return result

    # 1. Пустой payload
    r = await _proc("", "empty")
    check("empty payload returns empty", r == "", f"got: {r!r}")

    # 2. Первый запрос возвращает маску (проверяем, что ПД скрыты, а не конкретный формат)
    orig1 = "Иванов Иван Иванович, паспорт 4509 123456"
    r1 = await _proc(orig1, "p1")
    check(
        "first request returns mask",
        "*" in r1 and "Иванов" not in r1 and "4509 123456" not in r1,
        f"got: {r1!r}",
    )

    # 3. Повторный запрос с тем же оригиналом возвращает ту же маску
    r2 = await _proc(orig1, "p1")
    check("repeat original returns same mask", r1 == r2, f"got: {r2!r}")

    # 4. Запрос с маской возвращает оригинал
    r3 = await _proc(r1, "p1")
    check("mask request returns original", r3 == orig1, f"got: {r3!r}")

    # 5. Если ПД нет, маска равна оригиналу
    plain = "Просто текст без персональных данных"
    r4 = await _proc(plain, "p2")
    check("no PII mask equals original", r4 == plain, f"got: {r4!r}")

    # 6. Два одновременных запроса с одним payload_id дают одинаковый результат
    async def _concurrent():
        return await _proc(
            "Петров Пётр Петрович, телефон +7 999 123-45-67", "p3"
        )

    results = await asyncio.gather(_concurrent(), _concurrent())
    check(
        "concurrent requests same result",
        results[0] == results[1],
        f"got: {results[0]!r} vs {results[1]!r}",
    )

# 7. Запись не обновляется в спорном случае
    orig4 = "Сидоров Сидор Сидорович"
    await _proc(orig4, "p4")
    rec_before = await store.get("p4")
    # Присылаем несовпадающий payload (спорный случай)
    await _proc("Совершенно другой текст", "p4")
    rec_after = await store.get("p4")
    check(
        "record not updated on ambiguous",
        rec_before["original_text"] == rec_after["original_text"]
        and rec_before["masked_text"] == rec_after["masked_text"],
    )

    # 8. Фильтрация по pii_types: маскируются только перечисленные типы
    filt_service = ProcessService(store, {"pii_types": ["PHONE"], "allow_unmask": True})
    orig8 = "Иванов Иван Иванович, телефон +7 999 123-45-67"
    r8, _, _ = await filt_service.process(orig8, "p8")
    check(
        "pii_types filter masks only listed types",
        "+7 999 123-45-67" not in r8 and "Иванов" in r8,
        f"got: {r8!r}",
    )

    # 9. Запрет демаскирования (allow_unmask=false): маска не раскрывается
    no_unmask_service = ProcessService(store, {"pii_types": ["ALL"], "allow_unmask": False})
    orig9 = "Петров Пётр Петрович, паспорт 4509 123456"
    r9, _, _ = await no_unmask_service.process(orig9, "p9")
    r9b, _, _ = await no_unmask_service.process(r9, "p9")
    check(
        "allow_unmask=false returns mask not original",
        r9b == r9 and "Петров" not in r9b,
        f"got: {r9b!r}",
    )

# 10. Один и тот же payload с разными payload_id возвращает одинаковую маску
    shared = "Кузнецов Кузьма Кузьмич, ИНН 7707083893"
    r10a, _, _ = await service.process(shared, "p10a")
    r10b, _, _ = await service.process(shared, "p10b")
    check(
        "same payload different ids same mask",
        r10a == r10b,
        f"got: {r10a!r} vs {r10b!r}",
    )

    store.close()
    try:
        os.unlink(tmp.name)
    except OSError:
        pass

    return all(cond for _, cond in checks)


def _selftest() -> int:
    print("Running selftest...")
    try:
        ok = asyncio.run(_run_selftest())
    except Exception as exc:  # noqa: BLE001
        print(f"SELFTEST FAILED: {exc}")
        return 1
    if ok:
        print("SELFTEST OK")
        return 0
    print("SELFTEST FAILED")
    return 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    _setup_logging()
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    import uvicorn

    # workers > 1 требует передавать приложение строкой импорта
    uvicorn.run("main:app", host="0.0.0.0", port=8000, workers=WORKERS)


if __name__ == "__main__":
    main()








































