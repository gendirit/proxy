# Модуль: Конфигурация (`config.json`)

Гибкая настройка систем-потребителей, типов ПД и флага демаскирования.

## Назначение

Определяет, какие системы могут обращаться к сервису, какие типы ПД маскировать для каждой системы и разрешено ли демаскирование.

## Структура

```json
{
  "default_system": {"enabled": true, "pii_types": ["ALL"], "allow_unmask": true},
  "systems": [
    {"name": "crm-assistant", "enabled": true, "pii_types": ["ALL"], "allow_unmask": true},
    {"name": "blocked-bot", "enabled": false, "pii_types": [], "allow_unmask": false}
  ]
}
```

### Поля

| Поле | Тип | Описание |
|------|-----|----------|
| `default_system` | объект | Настройки по умолчанию для запросов без заголовка `X-System-Id`. |
| `systems` | массив | Список систем-потребителей. |
| `name` | строка | Имя системы (совпадает с `X-System-Id`). |
| `enabled` | bool | Разрешено ли обращение к модулю. |
| `pii_types` | массив | Список типов ПД для маскирования. `["ALL"]` — все типы. |
| `allow_unmask` | bool | Разрешено ли демаскирование. `false` — возвращать маску вместо оригинала. |

## Логика выбора системы

- Запрос с заголовком `X-System-Id` → ищется система с `name == X-System-Id`.
- Если система не найдена или `enabled=false` → ответ `403`.
- Запрос без заголовка → используется `default_system`.
- Если `config.json` не загружен (ошибка) → используются дефолты `_DEFAULT_SYSTEM` из `main.py`.

## Примеры настройки

### Только телефон, без демаскирования

```json
{"name": "support-bot", "enabled": true, "pii_types": ["PHONE"], "allow_unmask": false}
```

### Все типы ПД, с демаскированием

```json
{"name": "crm-assistant", "enabled": true, "pii_types": ["ALL"], "allow_unmask": true}
```

### Отключённая система

```json
{"name": "legacy-bot", "enabled": false, "pii_types": [], "allow_unmask": false}
```

## Краткая инструкция по настройке (≤ 5 предложений)

1. Откройте `config.json`.
2. Добавьте систему в массив `systems` с полями `name`, `enabled`, `pii_types`, `allow_unmask`.
3. Укажите `pii_types` — список типов ПД для маскирования (или `["ALL"]`).
4. Установите `allow_unmask` — разрешено ли демаскирование.
5. Перезапустите сервис; запросы с `X-System-Id` будут обрабатываться по настройкам системы.

## Загрузка

Загрузка выполняется в `main.py` функцией `_load_config()` при старте. При ошибке — дефолты и warning в лог.