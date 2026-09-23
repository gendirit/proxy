"""Проверка контракта на удалённом эндпоинте организаторов.

Сравнивает типы обнаруженных ПД нашего решения с удалённым эндпоинтом
process-test.holydev.space/process.

Запуск:
    python recon.py
"""

import asyncio
import uuid

import httpx

from detectors import mask_payload

URL = "https://process-test.holydev.space/process"

CASES = [
    ("fio_passport", "Клиент Иванов Иван Иванович, паспорт 4509 123456"),
    ("pushkin", "Александр Пушкин родился в Москве."),
    ("bank_branch", "Адрес отделения Банка: г. Москва, ул. Тверская, д. 1."),
    ("phone", "Телефон: +7 999 123-45-67, звонить после 18:00."),
    ("email", "Почта: ivanov@example.com"),
    ("inn", "ИНН 7707083893"),
    ("card_cvv_pin", "Карта 4509 1234 5678 9012, CVV 123, PIN 1234"),
    ("date_birth", "Дата рождения: 12.03.1990, место рождения: г. Москва"),
    ("address", "Адрес: г. Москва, ул. Тверская, д. 1, кв. 2, индекс 123456"),
    ("passport_full", "Паспорт 4509 123456 выдан ОУФМС по г. Москве 01.02.2010, код подразделения 770-001"),
    ("driver_license", "Водительское удостоверение серия 7701 номер 123456"),
    ("citizenship", "Гражданство: Российская Федерация"),
    ("card_holder", "Держатель карты IVAN IVANOV"),
    ("no_pii", "Сегодня хорошая погода."),
]


def _local_types(text: str) -> list:
    """Определяет типы ПД через наше решение."""
    _, detected = mask_payload(text)
    return detected


async def probe_case(client: httpx.AsyncClient, name: str, text: str) -> None:
    payload_id = f"recon-{name}-{uuid.uuid4().hex}"

    # Наше решение
    local_types = _local_types(text)
    masked_local, _ = mask_payload(text)

    print("=" * 70)
    print(f"CASE: {name}")
    print("IN :", text)
    print("LOCAL types:", local_types)

    try:
        first = await client.post(
            URL,
            json={"payload": text, "payload_id": payload_id},
        )
        print("STATUS 1:", first.status_code)

        if first.status_code != 200:
            print("ERROR 1:", first.text[:500])
            return

        masked_remote = first.json().get("result", "")
        print("REMOTE OUT:", masked_remote)

        # Сравнение: замаскированы ли ПД в удалённом ответе
        remote_masked = masked_remote != text
        local_masked = masked_local != text

        # Для негативных кейсов (нет ПД) — оба не должны маскировать
        if not local_types:
            match = not remote_masked
            print(f"MATCH: {'OK' if match else 'FAIL'} (no PII, remote_masked={remote_masked})")
        else:
            # ПД есть — оба должны маскировать
            match = remote_masked
            print(f"MATCH: {'OK' if match else 'FAIL'} (PII present, remote_masked={remote_masked})")

        # Демаскирование
        second = await client.post(
            URL,
            json={"payload": masked_remote, "payload_id": payload_id},
        )
        print("STATUS 2:", second.status_code)
        if second.status_code == 200:
            unmasked = second.json().get("result", "")
            print("UNMASK:", unmasked)
            print(f"UNMASK OK: {'OK' if unmasked == text else 'FAIL'}")

    except Exception as exc:
        print("EXCEPTION:", exc)


async def main() -> None:
    async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
        for name, text in CASES:
            await probe_case(client, name, text)
            print()


if __name__ == "__main__":
    asyncio.run(main())