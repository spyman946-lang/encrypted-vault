"""Program settings (brute-force protection, self-destruct)."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

# Argon2id — максимально стойкий профиль по умолчанию (медленный перебор)
DEFAULT_ARGON2_TIME = 4
DEFAULT_ARGON2_MEMORY_KIB = 262_144  # 256 MiB
DEFAULT_ARGON2_PARALLELISM = 4

DEFAULT_MIN_DELAY = 2.0
DEFAULT_DELAY_MULTIPLIER = 2.0
DEFAULT_MAX_DELAY = 120.0


@dataclass
class VaultSettings:
    """Настройки безопасности (файл vault-settings.json)."""

    # 0 = отключено; при достижении лимита контейнер безвозвратно уничтожается
    max_failed_attempts: int = 0
    destroy_on_max_attempts: bool = True

    # Задержка после неверного пароля: min_delay * multiplier^attempt (сек)
    min_delay_seconds: float = DEFAULT_MIN_DELAY
    delay_multiplier: float = DEFAULT_DELAY_MULTIPLIER
    max_delay_seconds: float = DEFAULT_MAX_DELAY

    # Argon2id (чем выше — тем медленнее перебор пароля)
    argon2_time_cost: int = DEFAULT_ARGON2_TIME
    argon2_memory_kib: int = DEFAULT_ARGON2_MEMORY_KIB
    argon2_parallelism: int = DEFAULT_ARGON2_PARALLELISM

    # Доп. ключ для KDF (опционально, храните отдельно от контейнера)
    kdf_pepper: str = ""

    # --- Временная блокировка (открытие только в заданном окне UTC) ---
    time_lock_enabled: bool = False
    time_lock_require_network: bool = True
    time_lock_require_local_match: bool = True
    time_lock_min_network_sources: int = 3
    time_lock_network_agreement_seconds: float = 120.0
    time_lock_max_local_skew_seconds: float = 300.0
    time_lock_allow_offline: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> VaultSettings:
        known = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_dict(self) -> dict:
        return asdict(self)


def _settings_search_paths() -> list[Path]:
    paths: list[Path] = [Path.cwd() / "vault-settings.json"]
    appdata = os.environ.get("APPDATA")
    if appdata:
        paths.append(Path(appdata) / "encrypted-vault" / "settings.json")
    home = Path.home() / ".encrypted-vault" / "settings.json"
    if home not in paths:
        paths.append(home)
    module_dir = Path(__file__).resolve().parent.parent / "vault-settings.json"
    if module_dir not in paths:
        paths.append(module_dir)
    return paths


def load_settings(explicit: Path | None = None) -> VaultSettings:
    if explicit is not None:
        if not explicit.is_file():
            raise FileNotFoundError(f"Файл настроек не найден: {explicit}")
        return VaultSettings.from_dict(json.loads(explicit.read_text(encoding="utf-8")))

    for path in _settings_search_paths():
        if path.is_file():
            return VaultSettings.from_dict(json.loads(path.read_text(encoding="utf-8")))

    return VaultSettings()


def save_settings(settings: VaultSettings, path: Path | None = None) -> Path:
    target = path or (Path.cwd() / "vault-settings.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(settings.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return target


def write_default_settings(path: Path | None = None) -> Path:
    """Создать пример настроек с включённым самоуничтожением."""
    s = VaultSettings(
        max_failed_attempts=5,
        destroy_on_max_attempts=True,
        min_delay_seconds=3.0,
        delay_multiplier=2.0,
        max_delay_seconds=180.0,
        argon2_time_cost=DEFAULT_ARGON2_TIME,
        argon2_memory_kib=DEFAULT_ARGON2_MEMORY_KIB,
        argon2_parallelism=DEFAULT_ARGON2_PARALLELISM,
    )
    return save_settings(s, path or Path.cwd() / "vault-settings.json")
