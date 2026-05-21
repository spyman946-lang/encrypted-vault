@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo === Сборка EncryptedVault.exe ===
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo Установите Python 3.10+ с https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/3] Зависимости...
pip install -r requirements.txt pyinstaller -q
if errorlevel 1 (
    echo Ошибка pip install
    pause
    exit /b 1
)

echo [2/3] Сборка exe (1–3 минуты)...
pyinstaller --noconfirm --clean EncryptedVault.spec
if errorlevel 1 (
    echo Ошибка PyInstaller
    pause
    exit /b 1
)

echo [3/3] Копирование...
copy /Y vault-settings.example.json dist\ 2>nul
echo.
echo Готово: dist\EncryptedVault.exe
echo Запустите dist\EncryptedVault.exe
echo.
explorer dist
pause
