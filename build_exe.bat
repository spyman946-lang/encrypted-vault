@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo === Сборка EncryptedVault (чистая установка) ===
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo Установите Python 3.10+ с https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [1/4] Очистка...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

echo [2/4] Зависимости...
pip install -r requirements.txt pyinstaller -q
if errorlevel 1 (
    echo Ошибка pip install
    pause
    exit /b 1
)

echo [3/4] Сборка exe (без data/, настроек и контейнеров)...
pyinstaller --noconfirm --clean EncryptedVault.spec
if errorlevel 1 (
    echo Ошибка PyInstaller
    pause
    exit /b 1
)

echo [4/4] Финальная проверка dist...
if not exist "dist\EncryptedVault.exe" (
    echo Не найден dist\EncryptedVault.exe
    pause
    exit /b 1
)

REM Только «как после установки»: exe + краткая справка, без пользовательских файлов
del /F /Q dist\vault-settings.json 2>nul
del /F /Q dist\vault-settings.example.json 2>nul
del /F /Q dist\app_config.json 2>nul
del /F /Q dist\*.evlt 2>nul
if exist dist\data rmdir /s /q dist\data

copy /Y packaging\DIST_README.txt dist\README.txt >nul

echo.
echo Готово — содержимое dist:
dir /b dist
echo.
echo Контейнер встроится в exe при первом запуске; data\ — только настройки
echo.
explorer dist
pause
