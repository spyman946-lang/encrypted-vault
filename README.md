# Encrypted Vault

**Encrypted Vault** — программа для хранения файлов в одном зашифрованном контейнере (формат `.evlt`). Поддерживаются графический интерфейс (GUI) и командная строка (CLI). Данные шифруются **AES-256-GCM**, ключи выводятся через **Argon2id** (или PBKDF2 в старых контейнерах), для каждого файла внутри контейнера — отдельный ключ через **HKDF-SHA512**.

---

## Содержание

- [Возможности](#возможности)
- [Требования](#требования)
- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [Режимы защиты](#режимы-защиты)
- [Графический интерфейс](#графический-интерфейс)
- [Командная строка](#командная-строка)
- [Формат контейнера](#формат-контейнера)
- [Настройки безопасности](#настройки-безопасности)
- [Блокировка по времени (timelock)](#блокировка-по-времени-timelock)
- [Сборка исполняемого файла](#сборка-исполняемого-файла)
- [Структура проекта](#структура-проекта)
- [Ограничения и рекомендации](#ограничения-и-рекомендации)
- [Лицензия](#лицензия)

---

## Возможности

| Функция | Описание |
|--------|----------|
| **Контейнер `.evlt`** | Один файл на диске; внутри — произвольное число зашифрованных файлов |
| **Пароль** | Argon2id с настраиваемой «тяжестью» (память, итерации) |
| **Защита от перебора** | Нарастающие задержки, счётчик попыток, опциональное **самоуничтожение** контейнера |
| **Timelock** | Открытие только в заданном окне UTC (с проверкой времени по сети) |
| **Режим «пароль + время»** | Нужны и пароль, и наступление нужной даты |
| **GUI** | Встроенное хранилище, пароль входа в программу, мастер первого запуска, настройки |
| **CLI** | Полный набор операций для скриптов и автоматизации |
| **Сборка в exe** | Windows: один файл `EncryptedVault.exe` через PyInstaller |

---

## Требования

- **Python 3.10+**
- Зависимости: `cryptography`, `argon2-cffi` (см. `requirements.txt`)
- Для timelock с проверкой сети — доступ в интернет (NTP, HTTP API, заголовки `Date`)
- GUI: **tkinter** (обычно входит в установку Python на Windows)

---

## Установка

### Из исходников

```powershell
cd encrypted-vault
pip install -r requirements.txt
```

Или установка пакета в режиме разработки:

```powershell
pip install -e .
```

### Windows (батники)

| Файл | Назначение |
|------|------------|
| `install.bat` | Установка зависимостей в виртуальное окружение |
| `Запуск GUI.bat` | Запуск графического интерфейса |
| `run_gui_debug.bat` | GUI с выводом ошибок в консоль |
| `build_exe.bat` | Сборка `dist\EncryptedVault.exe` |

---

## Быстрый старт

### GUI (рекомендуется для повседневной работы)

```powershell
python run_gui.py
```

При **первом запуске** откроется мастер настройки:

1. Опционально — **пароль входа** в программу (отдельно от пароля хранилища).
2. Создание **встроенного контейнера** `vault.evlt` в папке данных программы.
3. Опционально — **пароль хранилища** для файлов внутри.

При следующих запусках: окно входа (если задан пароль входа) → главное окно со списком файлов.

### CLI (внешний контейнер)

```powershell
# Создать контейнер
python main.py create -c myvault.evlt --protection password

# Добавить файл
python main.py add -c myvault.evlt document.pdf

# Список
python main.py list -c myvault.evlt

# Извлечь
python main.py extract -c myvault.evlt document.pdf -o .

# Сменить пароль
python main.py passwd -c myvault.evlt

# Информация
python main.py info -c myvault.evlt
```

Пароль можно передать флагом `-p` (осторожно: попадает в историю командной строки). Без `-p` программа запросит пароль интерактивно.

Справка по всем командам:

```powershell
python main.py --help
python main.py create --help
```

---

## Режимы защиты

Задаются при создании (`create --protection …`) или читаются из заголовка контейнера.

| Режим | CLI | Пароль | Timelock | Когда использовать |
|-------|-----|--------|----------|-------------------|
| **password** | `--protection password` | Да | Нет | Обычное секретное хранилище |
| **timelock** | `--protection timelock --unlock-after "…"` | **Нет** | Да | Открыть «после даты» без пароля (см. предупреждение ниже) |
| **both** | `--protection both --unlock-after "…"` | Да | Да | Максимум: пароль + окно по UTC |

### Примеры создания

**Только пароль:**

```powershell
python main.py create -c vault.evlt --protection password
```

**Открыть не раньше указанной даты (UTC), без пароля:**

```powershell
python main.py create -c release.evlt --protection timelock `
  --unlock-after "2026-12-01 00:00:00"
```

**Пароль + окно доступа:**

```powershell
python main.py create -c secure.evlt --protection both `
  --unlock-after "2026-06-01 00:00:00" `
  --unlock-before "2026-12-31 23:59:59"
```

Формат даты: `YYYY-MM-DD HH:MM:SS` в **UTC** (как в `timelock` и `info`).

> **Важно (режим `timelock`):** после наступления даты открытия **любой**, у кого есть файл контейнера, может его расшифровать — пароль не требуется. Физическая защита файла на диске остаётся на вас (шифрование диска, права доступа, офлайн-хранение до даты).

---

## Графический интерфейс

### Где хранятся данные

| Режим | Папка данных | Контейнер | Настройки |
|-------|--------------|-----------|-----------|
| **Разработка** (`python run_gui.py`) | `encrypted-vault/data/` | `data/vault.evlt` | `data/vault-settings.json` |
| **Собранный exe** | `%APPDATA%\EncryptedVault\` | `vault.evlt` | `vault-settings.json` |

Дополнительно в папке данных:

- `app_config.json` — хэш пароля входа, флаг «хранилище создано»
- `vault-error.log` — ошибки GUI (при сбоях)

При первом запуске, если нет `vault-settings.json`, он копируется из `vault-settings.example.json` в папку программы.

### Окна и действия

1. **Первый запуск** — мастер: пароль входа (опционально), пароль хранилища (опционально), создание `vault.evlt`.
2. **Вход** — если в `app_config.json` задан пароль входа (Argon2).
3. **Главное окно** — список файлов, кнопки:
   - Добавить / Извлечь / Удалить
   - Сменить пароль хранилища
   - Информация о контейнере
   - **Настройки** (вкладки: Пароли, Защита, Время, Система)

Длительные операции (открытие, Argon2) выполняются в фоновом потоке, интерфейс не блокируется.

### Пароли в GUI

| Пароль | Назначение |
|--------|------------|
| **Входа в программу** | Блокирует запуск GUI; хранится как Argon2-хэш в `app_config.json` |
| **Хранилища** | Расшифровка `vault.evlt`; задаётся при создании контейнера |

Их можно сделать разными или одинаковыми — это независимые механизмы.

---

## Командная строка

Общие параметры для команд работы с контейнером:

| Параметр | Описание |
|----------|----------|
| `-c`, `--container` | Путь к `.evlt` (по умолчанию `vault.evlt`) |
| `-p`, `--password` | Пароль (не для режима `timelock` при открытии) |
| `--settings-file` | Путь к `vault-settings.json` |

### Команды

| Команда | Описание |
|---------|----------|
| `create` | Создать новый контейнер |
| `add` | Добавить файл (`-n` — имя внутри контейнера) |
| `list` / `ls` | Список файлов |
| `extract` | Извлечь файл (`-o` — каталог вывода) |
| `remove` / `rm` | Удалить файл из контейнера |
| `passwd` | Сменить пароль контейнера |
| `info` | Заголовок, режим защиты, KDF, timelock, число файлов |
| `timelock` | Управление временной блокировкой (см. ниже) |
| `config` | Инициализация и правка `vault-settings.json` |

### Timelock в CLI

```powershell
# Статус окна доступа
python main.py timelock -c vault.evlt --status

# Проверить источники времени (сеть + локальные часы)
python main.py timelock --check-time

# Добавить timelock к контейнеру с паролем (режим both)
python main.py timelock -c vault.evlt --enable --after "2026-01-01 00:00:00"

# Снять timelock (остаётся только пароль)
python main.py timelock -c vault.evlt --disable
```

### Настройки через CLI

```powershell
python main.py config --init
python main.py config --show
python main.py config --set max_failed_attempts=10
```

---

## Формат контейнера

- **Магическая сигнатура:** `EVLT`
- **Версии формата:**
  - **v1** — PBKDF2-SHA256 (600 000 итераций), legacy
  - **v2** — Argon2id, счётчик неудачных попыток в зашифрованном виде
  - **v3** — Argon2id + режим защиты (`password` / `timelock` / `both`) + печать timelock

**Шифрование содержимого:** AES-256-GCM, уникальный nonce на blob.  
**Ключ файла:** HKDF от мастер-ключа контейнера + имя файла + nonce.  
**Проверка пароля:** зашифрованный маркер (не сравнение открытого текста).

При неверном пароле (если включено в настройках):

1. Увеличивается счётчик попыток (в v2+ — в зашифрованном блоке).
2. Применяется задержка: `min_delay × multiplier^attempt` (с потолком `max_delay`).
3. При достижении `max_failed_attempts` контейнер **безвозвратно перезаписывается и удаляется** (`destroy_on_max_attempts`).

---

## Настройки безопасности

Файл: `vault-settings.json` (шаблон: `vault-settings.example.json`).

Поиск настроек (CLI без `--settings-file`):

1. `./vault-settings.json` (текущая папка)
2. `%APPDATA%\encrypted-vault\settings.json`
3. `~/.encrypted-vault/settings.json`
4. `vault-settings.json` рядом с пакетом

### Параметры

| Параметр | По умолчанию (example) | Описание |
|----------|------------------------|----------|
| `max_failed_attempts` | `5` | Лимит неверных паролей; `0` — отключить |
| `destroy_on_max_attempts` | `true` | Уничтожить файл контейнера при лимите |
| `min_delay_seconds` | `3.0` | Базовая задержка после ошибки |
| `delay_multiplier` | `2.0` | Множитель задержки |
| `max_delay_seconds` | `180.0` | Потолок задержки |
| `argon2_time_cost` | `4` | Итерации Argon2id |
| `argon2_memory_kib` | `262144` | Память Argon2id (256 MiB) |
| `argon2_parallelism` | `4` | Потоки Argon2id |
| `kdf_pepper` | `""` | Доп. секрет для KDF (храните отдельно от контейнера) |

### Проверка времени (timelock)

| Параметр | По умолчанию | Описание |
|----------|--------------|----------|
| `time_lock_enabled` | `false` | Глобальный флаг (логика в заголовке контейнера) |
| `time_lock_require_network` | `true` | Требовать согласованное сетевое время |
| `time_lock_require_local_match` | `true` | Сверять локальные часы с сетью |
| `time_lock_min_network_sources` | `3` | Минимум согласованных источников |
| `time_lock_network_agreement_seconds` | `120` | Допуск расхождения источников (с) |
| `time_lock_max_local_skew_seconds` | `300` | Допуск смещения локальных часов (с) |
| `time_lock_allow_offline` | `false` | Разрешить только локальные часы без сети |

**Источники времени** (при открытии с timelock): WorldTimeAPI, TimeAPI.io, HTTP `Date` (Google, Microsoft), Cloudflare trace, NTP (`pool.ntp.org`, `time.google.com`), локальные часы UTC.

Команда проверки без открытия контейнера:

```powershell
python main.py timelock --check-time
```

---

## Блокировка по времени (timelock)

**До** `unlock_after` — контейнер не открывается (даже с верным паролем в режиме `both`).  
**После** `unlock_before` (если задано) — доступ закрыт.

В режиме **`timelock`** пароль не используется: ключ выводится из печати времени в заголовке (после проверки trusted UTC).

В режиме **`both`** нужны пароль и прохождение проверки времени.

Отключить подделку даты: timelock опирается на **кворум сетевых источников** и сверку с локальными часами — сдвиг системного времени в одиночку обычно недостаточен, если включены `time_lock_require_network` и `time_lock_require_local_match`.

---

## Сборка исполняемого файла

```powershell
pip install pyinstaller
build_exe.bat
```

Результат: `dist\EncryptedVault.exe`.

Перед пересборкой **закройте** запущенный exe — иначе PyInstaller может выдать `PermissionError`.

Данные exe-приложения: `%APPDATA%\EncryptedVault\` (не рядом с exe).

---

## Структура проекта

```
encrypted-vault/
├── vault/                  # Ядро: криптография, контейнер, GUI, CLI
│   ├── container.py        # Формат .evlt, CRUD файлов
│   ├── crypto_utils.py     # Argon2id, AES-GCM, HKDF
│   ├── protection.py       # Режимы password / timelock / both
│   ├── timelock.py         # Политика окон UTC
│   ├── time_verify.py      # Сверка времени по сети
│   ├── settings.py         # vault-settings.json
│   ├── app_store.py        # Встроенное хранилище GUI, пароль входа
│   ├── gui_app.py          # Tkinter GUI
│   └── cli.py              # CLI
├── main.py                 # Точка входа CLI
├── run_gui.py              # Точка входа GUI
├── vault-settings.example.json
├── requirements.txt
├── pyproject.toml
├── EncryptedVault.spec     # PyInstaller
├── build_exe.bat
├── install.bat
├── Запуск GUI.bat
├── .github/workflows/ci.yml
└── README.md
```

### Запуск как модуль

```powershell
python -m vault
python -m vault create -c test.evlt
```

---

## Ограничения и рекомендации

1. **Резервные копии** — при включённом `destroy_on_max_attempts` одна серия неверных паролей уничтожит контейнер без восстановления.
2. **Режим `timelock` без пароля** — файл контейнера после даты открытия = секрет для любого, кто скопировал файл.
3. **`kdf_pepper`** — при потере pepper старые контейнеры не откроются; pepper не храните в том же месте, что и контейнер.
4. **Пароль в `-p`** — виден в истории shell; для скриптов предпочтительнее переменные окружения или интерактивный ввод.
5. **Производительность** — Argon2 с 256 MiB и `time_cost=4` намеренно медленный; на слабых ПК можно снизить `argon2_memory_kib` / `argon2_time_cost` в настройках (меньше стойкость к перебору).
6. **Не коммитьте** в git: `data/`, `*.evlt`, `vault-settings.json` с реальным pepper — см. `.gitignore`.

---

## Лицензия

Проект распространяется под лицензией **MIT** — см. файл [LICENSE](LICENSE).

---

## Краткая шпаргалка

```powershell
# GUI
python run_gui.py

# Новый контейнер с защитой
python main.py create -c vault.evlt -p "секрет" --protection password

# Timelock + пароль
python main.py create -c x.evlt --protection both `
  --unlock-after "2026-01-01 00:00:00" -p "секрет"

# Настройки по умолчанию
copy vault-settings.example.json vault-settings.json
python main.py config --show
```
