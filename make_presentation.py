"""Генерация PDF-презентации решения (docs/presentation.pdf).

Использует reportlab. Для кириллицы подключает шрифт DejaVuSans.
"""

import os

from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

# Регистрация шрифта с поддержкой кириллицы
_FONT_PATH = None
for _candidate in [
    r"C:\Windows\Fonts\DejaVuSans.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
]:
    if os.path.exists(_candidate):
        _FONT_PATH = _candidate
        break

if _FONT_PATH:
    pdfmetrics.registerFont(TTFont("DejaVu", _FONT_PATH))
    _FONT = "DejaVu"
else:
    _FONT = "Helvetica"

OUT = os.path.join(os.path.dirname(__file__), "docs", "presentation.pdf")

_TITLE = ParagraphStyle("title", fontName=_FONT, fontSize=28, leading=34, spaceAfter=12)
_HEAD = ParagraphStyle("head", fontName=_FONT, fontSize=20, leading=26, spaceAfter=10)
_BODY = ParagraphStyle("body", fontName=_FONT, fontSize=14, leading=20, spaceAfter=6)
_BULLET = ParagraphStyle("bullet", fontName=_FONT, fontSize=14, leading=20, leftIndent=12, spaceAfter=4)


def _slide(story, title, body_lines):
    story.append(Paragraph(title, _HEAD))
    story.append(Spacer(1, 6))
    for line in body_lines:
        story.append(Paragraph("• " + line, _BULLET))
    story.append(Spacer(1, 20))


def build():
    doc = SimpleDocTemplate(OUT, pagesize=landscape(A4),
                            leftMargin=20 * mm, rightMargin=20 * mm,
                            topMargin=20 * mm, bottomMargin=20 * mm)
    story = []

    # Титульный слайд
    story.append(Paragraph("Модуль безопасности персональных данных", _TITLE))
    story.append(Paragraph("Прокси для LLM: маскирование и демаскирование ПД", _BODY))
    story.append(Spacer(1, 20))

    # Проблема и решение
    _slide(story, "Проблема и решение", [
        "При обращении к LLM критично защищать персональные данные (ПД).",
        "Решение: прокси-модуль, который идентифицирует, маскирует и демаскирует ПД.",
        "Встраивается в цепочку: Система-потребитель → Модуль → LLM → Потребитель.",
    ])

    # Архитектура
    _slide(story, "Архитектура", [
        "FastAPI-сервис: POST /process (маскирование/демаскирование).",
        "Детекторы ПД (17 типов) на регэкспах с разрешением пересечений.",
        "SQLite-хранилище записей (общее для воркеров), батчинг записи.",
        "Гибкая настройка систем и типов ПД через config.json.",
    ])

    # Ключевые возможности
    _slide(story, "Ключевые возможности", [
        "17 типов ПД: ФИО, даты, паспорт, гражданство, адрес, email, телефон, ИНН, карта, CVV, PIN и др.",
        "Исключение публичных личностей и адресов отделений Банка.",
        "Независимость от регистра, вариации дат и разделяющих слов.",
        "Демаскирование по payload_id с сохранением позиций.",
        "Токенизация, документы кроме паспорта РФ, контекстное маскирование.",
    ])

    # Производительность
    _slide(story, "Производительность", [
        "RPS ~2401 (цель ТЗ — 1000, повышенный уровень — 2000).",
        "Latency: p50 ~5ms, p95 ~77ms, p99 ~139ms.",
        "Обработка крупных текстов до 100 000 токенов (чанкинг).",
        "3 воркера (оптимально для 4-ядерного железа).",
    ])

    # Демо
    _slide(story, "Демо", [
        "POST /process с {payload, payload_id} → {result}.",
        "Маскирование: 'Клиент Иванов Иван Иванович, паспорт 4509 123456' → маска.",
        "Демаскирование: повторный запрос с тем же payload_id → исходная строка.",
        "URL: http://81.177.167.12:8001/process",
    ])

    # Итоги
    _slide(story, "Итоги", [
        "Полное соответствие ТЗ и критериям приёмки.",
        "Высокая производительность и стабильность.",
        "Безопасность: ПД не попадают в логи и метрики.",
        "Гибкая настройка и расширяемость.",
    ])

    doc.build(story)
    print(f"Presentation saved: {OUT}")


if __name__ == "__main__":
    build()