@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo Encrypted Vault
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ОШИБКА] Python не установлен.
    echo Установите с https://www.python.org/downloads/
    echo Отметьте "Add python to PATH"
    pause
    exit /b 1
)

pip show cryptography >nul 2>&1
if errorlevel 1 (
    echo Установка библиотек...
    pip install -r requirements.txt
)

if exist "dist\EncryptedVault.exe" (
    echo Запуск EncryptedVault.exe ...
    start "" "dist\EncryptedVault.exe"
    exit /b 0
)

echo Запуск через Python...
python run_gui.py
if errorlevel 1 (
    echo.
    echo Ошибка. Смотрите data\vault-error.log (рядом с программой)
    pause
)
