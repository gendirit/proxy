"""Детекторы и маскирование ПД.

Правила (по ответам организаторов):
- полное скрытие значений: буквы/цифры -> '*', разделители сохраняются;
- служебные слова и контекст НЕ маскируются;
- совпадающие интервалы разрешаются по длине и приоритету.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Регулярные выражения
# ---------------------------------------------------------------------------

_PASSPORT_PLAIN_RE = re.compile(r"\b(\d{4})\s*(\d{6})\b")
_PASSPORT_LABELED_RE = re.compile(
    r"(?i:(?:паспорт|серия|номер|док|удостоверение)[^\d]{0,30}?(\d{4})[^\d]{0,20}?(\d{6}))"
)

_DEPT_CODE_RE = re.compile(r"\b(\d{3})[-\s]?(\d{3})\b")
_DEPT_CODE_CTX_RE = re.compile(r"(?i:код\s+подразделения|кем|выдан|выдано)")

_ISSUER_CTX_RE = re.compile(
    r"(?i:\b(?:оуфмс|гуфмс|мвд|фмс|овд|умвд|отдел|отделение|управление)\b)"
)

_DL_RE = re.compile(r"(\d{4})(?:[^\d]{0,20}?)(\d{6})")
_DL_CTX_RE = re.compile(r"(?i:водител|в/у|водительск)")

# --- Даты ------------------------------------------------------------------
_DATE_NUM_RE = re.compile(r"\b(0?[1-9]|[12]\d|3[01])\s*[.\-/]\s*(0?[1-9]|1[0-2])\s*[.\-/]\s*(19\d{2}|20\d{2})\b")
_DATE_NUM_REV_RE = re.compile(r"\b(19\d{2}|20\d{2})\s*[.\-/]\s*(0?[1-9]|1[0-2])\s*[.\-/]\s*(0?[1-9]|[12]\d|3[01])\b")
_DATE_TEXT_RE = re.compile(
    r"\b(0?[1-9]|[12]\d|3[01])\s+"
    r"(?:январ|феврал|март|апрел|ма[йя]|июн|июл|август|сентябр|октябр|ноябр|декабр)\w*\s+"
    r"(19\d{2}|20\d{2})",
    re.IGNORECASE,
)
_DATE_TEXT_REV_RE = re.compile(
    r"\b(19\d{2}|20\d{2})\s+год[ау]?\s*"
    r"(?:январ|феврал|март|апрел|ма[йя]|июн|июл|август|сентябр|октябр|ноябр|декабр)\w*\s+"
    r"(0?[1-9]|[12]\d|3[01])",
    re.IGNORECASE,
)
_DATE_TEXT_WORD_RE = re.compile(
    r"\b(?:первое|второе|третье|четвертое|пятое|шестое|седьмое|восьмое|девятое|десятое|"
    r"одиннадцатое|двенадцатое|тринадцатое|четырнадцатое|пятнадцатое|шестнадцатое|"
    r"семнадцатое|восемнадцатое|девятнадцатое|двадцатое|двадцать\s+первое|двадцать\s+второе|"
    r"двадцать\s+третье|двадцать\s+четвертое|двадцать\s+пятое|двадцать\s+шестое|"
    r"двадцать\s+седьмое|двадцать\s+восьмое|двадцать\s+девятое|тридцатое|тридцать\s+первое)\s+"
    r"(?:январ|феврал|март|апрел|ма[йя]|июн|июл|август|сентябр|октябр|ноябр|декабр)\w*\s+"
    r"(19\d{2}|20\d{2})",
    re.IGNORECASE,
)

_BIRTH_CTX_RE = re.compile(r"(?i:рожд|родил|урожен|дата\s+рождения|место\s+рождения)")
_ISSUE_DATE_CTX_RE = re.compile(r"(?i:выдан|выдано|дата\s+выдачи)")

# --- Контакты и документы ---------------------------------------------------
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?:\+7|8)?[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}")
_INN_RE = re.compile(r"\b\d{12}\b|\b\d{10}\b")
_CARD_RE = re.compile(r"\b\d{4}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}\b|\b\d{15,19}\b")
_CVV_RE = re.compile(r"(?i:cvv|cvc|cvv2|cvc2)[^\d]{0,15}(\d{3})\b")
_PIN_RE = re.compile(r"(?i:пин[\-\s]?код|пин|pin|puk)[^\d]{0,15}(\d{4})\b")

# --- Адрес ------------------------------------------------------------------
_ADDR_INDEX_RE = re.compile(r"\b(\d{6})\b")
_ADDR_CITY_RE = re.compile(r"\b(г|город|с|село|дер|деревня|пос|поселок|станица|хутор)\.\s*([А-ЯЁ][\w\-]*)", re.IGNORECASE)
_ADDR_STREET_RE = re.compile(r"\b(ул|улица|пр|проспект|пер|переулок|пл|площадь|б-р|бульвар|ш|шоссе|наб|набережная)\.\s*([А-ЯЁ][\w\-]*)", re.IGNORECASE)
_ADDR_HOUSE_RE = re.compile(r"\b(д|дом|вл|владение)\.\s*(\d+[А-ЯЁа-яё]?)", re.IGNORECASE)
_ADDR_APT_RE = re.compile(r"\b(кв|квартира|ком|комната|оф|офис|пом|помещение|этаж|корп|корпус|литера|лит)\.\s*([\dА-ЯЁа-яё]+)", re.IGNORECASE)

# --- ФИО и держатель карты ---------------------------------------------------
_FIO_RE = re.compile(
    r"(?<![А-ЯЁа-яё])"
    r"([А-ЯЁ][а-яё]+)\s+([А-ЯЁ][а-яё]+)\s+([А-ЯЁ][а-яё]+(?:ович|овна|евич|евна|ич|ина))"
    r"(?![А-ЯЁа-яё])"
)
_CARD_HOLDER_RE = re.compile(r"\b([A-Z]{2,}(?:\s+[A-Z]{2,}){1,3})\b")

# --- Контекстные регэкспы (компилируются один раз) --------------------------
_ADDR_INDEX_CTX_RE = re.compile(r"(?i:индекс|адрес|ул\.|д\.|кв\.|г\.)")
_CARD_HOLDER_CTX_RE = re.compile(r"(?i:держатель|карта|карты|карту|картой|владелец)")
_INN_CTX_RE = re.compile(r"(?i:инн)")
_CITIZENSHIP_RE = re.compile(
    r"(?i:гражданин|гражданка|гражданство)\s*:?\s*"
    r"([А-ЯЁа-яёA-Za-z][\w\-]*(?:\s+[А-ЯЁа-яёA-Za-z][\w\-]*){0,3})"
)

# ---------------------------------------------------------------------------

@dataclass
class Span:
    start: int
    end: int
    replacement: str
    priority: int
    type_: str


_PUBLIC_PERSONS = [
    "пушкин", "толстой", "чехов", "лермонтов", "гоголь", "достоевский",
    "есенин", "маяковский", "горький", "булгаков", "грибоедов", "фонвизин",
    "некрасов", "тютчев", "фет", "блока", "ахматова", "цветаева",
]

_FIO_DOC_CTX_RE = re.compile(
    r"(?i:клиент|заемщик|заёмщик|заявител|держател|пассажир|вкладчик|получател|отправител|пайщик|абонент)"
)
_PATR_RE = re.compile(r"(?:ович|овна|евич|евна|ич|ина)$", re.IGNORECASE)

_ISSUER_NAME_RE = re.compile(
    r"(?i:(?:оуфмс|гуфмс|мвд|фмс|овд|умвд|отдел|отделение|управление|министерство)"
    r"(?:\s+по[\w.\s,\-]{0,50})?)"
)
_PLACE_BIRTH_VALUE_RE = re.compile(
    r"(?i:(?:г|город|с|село|дер|деревня|пос|поселок|станица|хутор|респ|республика|обл|область|край|страна)\.?\s*[\w.\-]+(?:\s+[\w.\-]+){0,3})"
)


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

# Таблица перевода для mask_value: буквы/цифры -> '*', остальное сохраняется.
_MASK_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдеёжзийклмнопрстуфхцчшщъыьэюя"
_MASK_TRANSLATE = str.maketrans(_MASK_CHARS, "*" * len(_MASK_CHARS))


def mask_value(text: str) -> str:
    """Полное скрытие: буквы/цифры -> '*', разделители сохраняются."""
    return text.translate(_MASK_TRANSLATE)


def mask_all(text: str) -> str:
    """Полное скрытие: все символы -> '*' той же длины."""
    return "*" * len(text)


def resolve_overlaps(spans):
    """Выбрать непересекающиеся спаны: длиннее -> выше приоритет -> раньше."""
    ordered = sorted(spans, key=lambda s: (-(s.end - s.start), s.priority, s.start))
    selected = []
    for span in ordered:
        if all(span.end <= sel.start or span.start >= sel.end for sel in selected):
            selected.append(span)
    selected.sort(key=lambda s: (s.start, -s.priority))
    return selected


def _has_context(pattern: re.Pattern, text: str, start: int, end: int, window: int = 80) -> bool:
    ctx_start = max(0, start - window)
    ctx_end = min(len(text), end + window)
    return pattern.search(text, ctx_start, ctx_end) is not None


def _add_spans(out, pattern: re.Pattern, text: str, type_: str,
               repl_func, priority: int = 10, groups=(0,)):
    for m in pattern.finditer(text):
        parts = []
        for g in groups:
            if g == 0:
                parts.append((m.start(0), m.end(0)))
            else:
                try:
                    if m.group(g) is not None:
                        parts.append((m.start(g), m.end(g)))
                except (IndexError, error):
                    pass
        for s, e in parts:
            out.append(Span(s, e, repl_func(text[s:e]), priority, type_))


from re import error as _re_error  # noqa: E402  (для обработки ошибок групп)


# ---------------------------------------------------------------------------
# Основной конвейер
# ---------------------------------------------------------------------------

def _detect(text: str):
    spans = []
    has_card = bool(_CARD_RE.search(text))

    # ФИО
    for m in _FIO_RE.finditer(text):
        full = m.group(0)
        words = [w.lower() for w in full.split()]
        if any(p in words for p in _PUBLIC_PERSONS):
            continue
        has_patr = any(_PATR_RE.search(w) for w in full.split())
        has_ctx = _has_context(_FIO_DOC_CTX_RE, text, m.start(), m.end(), 120)
        if not (has_patr or has_ctx):
            continue
        spans.append(Span(m.start(), m.end(), mask_value(full), 6, "FIO"))

    # Место рождения
    if _has_context(_BIRTH_CTX_RE, text, 0, len(text), len(text)):
        for m in _PLACE_BIRTH_VALUE_RE.finditer(text):
            if _has_context(_BIRTH_CTX_RE, text, m.start(), m.end(), 60):
                # Пропускаем, если рядом упоминается публичная личность
                ctx = text[max(0, m.start() - 120):min(len(text), m.end() + 120)].lower()
                if any(p in ctx for p in _PUBLIC_PERSONS):
                    continue
                spans.append(Span(m.start(), m.end(), mask_value(m.group(0)), 5, "PLACE_OF_BIRTH"))

    # Паспорт
    dl_present = _has_context(_DL_CTX_RE, text, 0, len(text), len(text))
    if not dl_present:
        for m in _PASSPORT_LABELED_RE.finditer(text):
            spans.append(Span(m.start(1), m.end(1), mask_value(m.group(1)), 8, "PASSPORT"))
            spans.append(Span(m.start(2), m.end(2), mask_value(m.group(2)), 8, "PASSPORT"))
        labeled_zones = {(m.start(1), m.end(2)) for m in _PASSPORT_LABELED_RE.finditer(text)}
        for m in _PASSPORT_PLAIN_RE.finditer(text):
            inside = any(ls <= m.start() and m.end() <= le for ls, le in labeled_zones)
            if inside:
                continue
            if _has_context(_DEPT_CODE_CTX_RE, text, m.start(), m.end(), 60):
                spans.append(Span(m.start(1), m.end(1), mask_value(m.group(1)), 8, "PASSPORT"))
                spans.append(Span(m.start(2), m.end(2), mask_value(m.group(2)), 8, "PASSPORT"))

    # Код подразделения
    for m in _DEPT_CODE_RE.finditer(text):
        if _has_context(_DEPT_CODE_CTX_RE, text, m.start(), m.end(), 60):
            spans.append(Span(m.start(), m.end(), mask_value(m.group(0)), 7, "DEPARTMENT_CODE"))

    # Орган выдачи
    for m in _ISSUER_NAME_RE.finditer(text):
        if _has_context(_DEPT_CODE_CTX_RE, text, m.start(), m.end(), 80):
            spans.append(Span(m.start(), m.end(), mask_value(m.group(0)), 5, "ISSUER"))

    # Даты
    for pattern in (_DATE_NUM_RE, _DATE_NUM_REV_RE, _DATE_TEXT_RE, _DATE_TEXT_REV_RE, _DATE_TEXT_WORD_RE):
        for m in pattern.finditer(text):
            if _has_context(_ISSUE_DATE_CTX_RE, text, m.start(), m.end(), 60):
                spans.append(Span(m.start(), m.end(), mask_value(m.group(0)), 6, "ISSUE_DATE"))
            elif _has_context(_BIRTH_CTX_RE, text, m.start(), m.end(), 60):
                spans.append(Span(m.start(), m.end(), mask_value(m.group(0)), 6, "BIRTH_DATE"))

# Водительское удостоверение
    if dl_present:
        for m in _DL_RE.finditer(text):
            if _has_context(_DL_CTX_RE, text, m.start(), m.end(), 80):
                spans.append(Span(m.start(1), m.end(1), mask_value(m.group(1)), 5, "DRIVER_LICENSE"))
                spans.append(Span(m.start(2), m.end(2), mask_value(m.group(2)), 5, "DRIVER_LICENSE"))

# Адрес
    for pattern, type_ in (
        (_ADDR_CITY_RE, "ADDRESS"),
        (_ADDR_STREET_RE, "ADDRESS"),
    ):
        for m in pattern.finditer(text):
            spans.append(Span(m.start(2), m.end(2), mask_value(m.group(2)), 8, type_))
    for pattern in (_ADDR_HOUSE_RE, _ADDR_APT_RE):
        for m in pattern.finditer(text):
            spans.append(Span(m.start(2), m.end(2), mask_value(m.group(2)), 8, "ADDRESS"))
    for m in _ADDR_INDEX_RE.finditer(text):
        if _has_context(_ADDR_INDEX_CTX_RE, text, m.start(), m.end(), 60):
            spans.append(Span(m.start(), m.end(), mask_value(m.group(0)), 8, "ADDRESS"))

    # Гражданство
    for m in _CITIZENSHIP_RE.finditer(text):
        spans.append(Span(m.start(1), m.end(1), mask_value(m.group(1)), 8, "CITIZENSHIP"))

    # ИНН
    for m in _INN_RE.finditer(text):
        spans.append(Span(m.start(), m.end(), mask_value(m.group(0)), 9, "INN"))

    # Карта
    for m in _CARD_RE.finditer(text):
        spans.append(Span(m.start(), m.end(), mask_value(m.group(0)), 4, "CARD"))

# Держатель карты
    for m in _CARD_HOLDER_RE.finditer(text):
        near_card = False
        for cm in _CARD_RE.finditer(text):
            if abs(cm.start() - m.end()) <= 120 or abs(m.start() - cm.end()) <= 120:
                near_card = True
                break
        near_holder = _has_context(
            _CARD_HOLDER_CTX_RE,
            text, m.start(), m.end(), 80,
        )
        if near_card or near_holder:
            spans.append(Span(m.start(), m.end(), mask_value(m.group(0)), 6, "CARD_HOLDER"))

    # Телефон
    for m in _PHONE_RE.finditer(text):
        if _has_context(_INN_CTX_RE, text, m.start(), m.end(), 40):
            continue
        spans.append(Span(m.start(), m.end(), mask_value(m.group(0)), 9, "PHONE"))

    # Email
    for m in _EMAIL_RE.finditer(text):
        spans.append(Span(m.start(), m.end(), mask_value(m.group(0)), 9, "EMAIL"))

    # CVV / ПИН — только при найденной карте
    if has_card:
        for m in _CVV_RE.finditer(text):
            spans.append(Span(m.start(1), m.end(1), "***", 5, "CVV"))
        for m in _PIN_RE.finditer(text):
            spans.append(Span(m.start(1), m.end(1), "****", 5, "PIN"))

    return spans


# ---------------------------------------------------------------------------
# Публичные функции
# ---------------------------------------------------------------------------

def mask_payload(text: str, allowed_types=None, mode="mask"):
    """Маскирует ПД в тексте.

    allowed_types: список типов ПД для маскирования (None = все типы).
    mode: "mask" — замена на "*", "tokenize" — замена на токены [TYPE_N].
    Возвращает кортеж (замаскированный текст, список типов ПД).
    В режиме "tokenize" дополнительно возвращает карту токенов
    {токен: исходное значение} третьим элементом.
    """
    if not text:
        return (text, [], {}) if mode == "tokenize" else (text, [])

    spans = _detect(text)
    if not spans:
        return (text, [], {}) if mode == "tokenize" else (text, [])
    if allowed_types is not None:
        allowed = set(allowed_types)
        spans = [s for s in spans if s.type_ in allowed]

    selected = resolve_overlaps(spans)
    result = text
    detected = []
    token_map = {}
    counters = {}
    # Применяем с конца, чтобы не сбивать индексы
    for span in sorted(selected, key=lambda s: s.start, reverse=True):
        if mode == "tokenize":
            counters[span.type_] = counters.get(span.type_, 0) + 1
            token = "[%s_%d]" % (span.type_, counters[span.type_])
            token_map[token] = text[span.start:span.end]
            replacement = token
        else:
            replacement = span.replacement
        result = result[:span.start] + replacement + result[span.end:]
        if span.type_ not in detected:
            detected.append(span.type_)

    if mode == "tokenize":
        return result, detected, token_map
    return result, detected


_LOG_PATTERNS = [
    _PASSPORT_PLAIN_RE,
    _PHONE_RE,
    _INN_RE,
    _CARD_RE,
    _EMAIL_RE,
]


def redact_for_logging(text: str) -> str:
    """Заменяет типовые ПД на [REDACTED] для безопасного логирования."""
    if not text:
        return text
    result = text
    for pattern in _LOG_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result

