"""Режимы защиты контейнера."""

from __future__ import annotations

from enum import IntEnum

from .timelock import TimeLockPolicy


class ProtectionMode(IntEnum):
    PASSWORD = 1
    TIMELOCK = 2
    BOTH = 3

    @classmethod
    def parse(cls, text: str) -> ProtectionMode:
        key = text.strip().lower()
        mapping = {
            "password": cls.PASSWORD,
            "пароль": cls.PASSWORD,
            "timelock": cls.TIMELOCK,
            "time": cls.TIMELOCK,
            "время": cls.TIMELOCK,
            "both": cls.BOTH,
            "all": cls.BOTH,
            "оба": cls.BOTH,
            "все": cls.BOTH,
        }
        if key not in mapping:
            raise ValueError(
                f"Неизвестный режим защиты: {text!r}. "
                "Допустимо: password, timelock, both"
            )
        return mapping[key]

    def label_ru(self) -> str:
        return {
            ProtectionMode.PASSWORD: "только пароль",
            ProtectionMode.TIMELOCK: "только по дате/времени",
            ProtectionMode.BOTH: "пароль и дата/время",
        }[self]


def validate_create(
    mode: ProtectionMode,
    password: str | None,
    timelock: TimeLockPolicy | None,
    *,
    allow_empty_password: bool = False,
) -> tuple[str | None, TimeLockPolicy]:
    tl = timelock or TimeLockPolicy()

    if mode == ProtectionMode.PASSWORD:
        if not password and not allow_empty_password:
            raise ValueError("Для режима password нужен пароль.")
        if tl.unlock_after_unix or tl.unlock_before_unix:
            raise ValueError("Для режима password не указывайте --unlock-after/--unlock-before.")
        return password, TimeLockPolicy(enabled=False)

    if mode == ProtectionMode.TIMELOCK:
        if password:
            raise ValueError("Для режима timelock пароль не используется (не указывайте -p).")
        if tl.unlock_after_unix <= 0:
            raise ValueError("Для режима timelock укажите --unlock-after (UTC).")
        return None, TimeLockPolicy(
            enabled=True,
            unlock_after_unix=tl.unlock_after_unix,
            unlock_before_unix=tl.unlock_before_unix,
        )

    if mode == ProtectionMode.BOTH:
        if not password:
            raise ValueError("Для режима both нужен пароль.")
        if tl.unlock_after_unix <= 0 and tl.unlock_before_unix <= 0:
            raise ValueError("Для режима both укажите --unlock-after и/или --unlock-before.")
        return password, TimeLockPolicy(
            enabled=True,
            unlock_after_unix=tl.unlock_after_unix,
            unlock_before_unix=tl.unlock_before_unix,
        )

    raise ValueError(f"Неизвестный режим: {mode}")


def legacy_byte_to_mode(enabled_byte: int, after: int, before: int) -> ProtectionMode:
    """Старые контейнеры: enabled=1 → both, иначе password."""
    if enabled_byte in (ProtectionMode.PASSWORD, ProtectionMode.TIMELOCK, ProtectionMode.BOTH):
        return ProtectionMode(enabled_byte)
    if enabled_byte == 1 or after > 0 or before > 0:
        return ProtectionMode.BOTH
    return ProtectionMode.PASSWORD


def mode_uses_password(mode: ProtectionMode) -> bool:
    return mode in (ProtectionMode.PASSWORD, ProtectionMode.BOTH)


def mode_uses_timelock(mode: ProtectionMode) -> bool:
    return mode in (ProtectionMode.TIMELOCK, ProtectionMode.BOTH)
