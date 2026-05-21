# Encrypted Vault

Зашифрованный контейнер для файлов: GUI, CLI, AES-256-GCM, Argon2id.

## Быстрый запуск

```powershell
pip install -r requirements.txt
python run_gui.py
```

Сборка exe: `build_exe.bat` → `dist\EncryptedVault.exe`

CLI: `python main.py --help`

Настройки: скопируйте `vault-settings.example.json` в `data\vault-settings.json` (создаётся автоматически при первом запуске GUI).

## Публикация на GitHub

Готовая копия репозитория: папка **[github-publish/](github-publish/)**  
(полный README, LICENSE, CI, инструкции — см. `github-publish/START_HERE.txt`)

## Структура

- `vault/` — исходный код
- `run_gui.py` — графический интерфейс
- `main.py` — командная строка

Данные пользователя (`data/`, `dist/`, `*.evlt`) не хранятся в git — см. `.gitignore`.
