"""Встроенное хранилище и пароль входа в программу."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_PH = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


@dataclass
class AppConfig:
    """Настройки внутри программы (data/app_config.json)."""

    # Пароль для входа в приложение (хэш; пусто = вход без пароля)
    login_password_hash: str = ""
    vault_initialized: bool = False
    vault_uses_password: bool = True

    @classmethod
    def from_dict(cls, data: dict) -> AppConfig:
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def login_required(self) -> bool:
        return bool(self.login_password_hash.strip())


def program_dir() -> Path:
    """Папка программы (рядом с exe или проектом)."""
    import sys

    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    """Внутренние данные программы (не отдельный файл «рядом» для пользователя)."""
    if getattr(__import__("sys"), "frozen", False):
        base = Path(os.environ.get("APPDATA", program_dir())) / "EncryptedVault"
    else:
        base = program_dir() / "data"
    base.mkdir(parents=True, exist_ok=True)
    return base


def config_path() -> Path:
    return data_dir() / "app_config.json"


def vault_path() -> Path:
    return data_dir() / "vault.evlt"


def settings_path() -> Path:
    p = data_dir() / "vault-settings.json"
    if not p.is_file():
        src = program_dir() / "vault-settings.example.json"
        if src.is_file():
            p.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return p


def load_app_config() -> AppConfig:
    path = config_path()
    if not path.is_file():
        return AppConfig()
    return AppConfig.from_dict(json.loads(path.read_text(encoding="utf-8")))


def save_app_config(cfg: AppConfig) -> None:
    config_path().write_text(
        json.dumps(cfg.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def set_login_password(password: str) -> None:
    cfg = load_app_config()
    cfg.login_password_hash = _PH.hash(password)
    save_app_config(cfg)


def clear_login_password() -> None:
    cfg = load_app_config()
    cfg.login_password_hash = ""
    save_app_config(cfg)


def verify_login_password(password: str) -> bool:
    cfg = load_app_config()
    if not cfg.login_required:
        return True
    if not password:
        return False
    try:
        _PH.verify(cfg.login_password_hash, password)
        return True
    except VerifyMismatchError:
        return False


def mark_vault_initialized(*, uses_password: bool = True) -> None:
    cfg = load_app_config()
    cfg.vault_initialized = True
    cfg.vault_uses_password = uses_password
    save_app_config(cfg)
