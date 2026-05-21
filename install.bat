@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Установка зависимостей Encrypted Vault...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo Ошибка установки.
    pause
    exit /b 1
)
echo Готово.
pause
