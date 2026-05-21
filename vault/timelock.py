"""Временная блокировка контейнера (открытие только в заданном окне UTC)."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from datetime import datetime, timezone

from .crypto_utils import NONCE_SIZE, TAG_SIZE, TIMELOCK_SEAL_MAX, decrypt_blob, encrypt_blob
from .time_verify import TrustedTime, format_utc

TIMELOCK_SEAL_MAGIC = b"VAULT_TIMELOCK_v2"


@dataclass
class TimeLockPolicy:
    enabled: bool = False
    unlock_after_unix: int = 0  # 0 = не задано
    unlock_before_unix: int = 0  # 0 = без срока истечения

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "unlock_after_unix": self.unlock_after_unix,
            "unlock_before_unix": self.unlock_before_unix,
        }

    @classmethod
    def from_dict(cls, data: dict) -> TimeLockPolicy:
        return cls(
            enabled=bool(data.get("enabled", False)),
            unlock_after_unix=int(data.get("unlock_after_unix", 0) or 0),
            unlock_before_unix=int(data.get("unlock_before_unix", 0) or 0),
        )


class TimeLockError(RuntimeError):
    pass


def parse_datetime_utc(text: str) -> int:
    text = text.strip().replace("T", " ")
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%d.%m.%Y %H:%M:%S",
        "%d.%m.%Y %H:%M",
        "%d.%m.%Y",
    ):
        try:
            dt = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            continue
    raise ValueError(
        f"Не удалось разобрать дату/время: {text!r}. "
        "Формат: YYYY-MM-DD HH:MM:SS (UTC)"
    )


def policy_digest(key: bytes, policy: TimeLockPolicy) -> bytes:
    payload = struct.pack(
        ">BQQ",
        1 if policy.enabled else 0,
        policy.unlock_after_unix,
        policy.unlock_before_unix,
    )
    return hashlib.sha256(key + TIMELOCK_SEAL_MAGIC + payload).digest()[:16]


def _seal_plaintext(policy: TimeLockPolicy, digest: bytes) -> bytes:
    return (
        TIMELOCK_SEAL_MAGIC
        + struct.pack(">BQQ", 1 if policy.enabled else 0, policy.unlock_after_unix, policy.unlock_before_unix)
        + digest
    )


def seal_timelock(key: bytes, policy: TimeLockPolicy) -> bytes:
    digest = policy_digest(key, policy)
    plain = _seal_plaintext(policy, digest)
    nonce, ct = encrypt_blob(key, plain)
    blob = nonce + ct
    if len(blob) > TIMELOCK_SEAL_MAX:
        raise ValueError("Слишком большие данные timelock для заголовка")
    return blob


def open_timelock(key: bytes, blob: bytes) -> TimeLockPolicy | None:
    if len(blob) < NONCE_SIZE + len(TIMELOCK_SEAL_MAGIC) + 17 + TAG_SIZE:
        return None
    try:
        plain = decrypt_blob(key, blob[:NONCE_SIZE], blob[NONCE_SIZE:])
        if not plain.startswith(TIMELOCK_SEAL_MAGIC):
            return None
        rest = plain[len(TIMELOCK_SEAL_MAGIC) :]
        enabled, after, before = struct.unpack(">BQQ", rest[:17])
        digest = rest[17:33]  # 16 bytes SHA-256 truncated
        policy = TimeLockPolicy(enabled=bool(enabled), unlock_after_unix=after, unlock_before_unix=before)
        if policy_digest(key, policy) != digest:
            return None
        return policy
    except Exception:
        return None


def check_timelock_pre_password(header_policy: TimeLockPolicy, trusted: TrustedTime) -> None:
    """Проверка по открытым полям заголовка до ввода пароля (экономит KDF)."""
    if not header_policy.enabled:
        return
    now = trusted.unix
    if header_policy.unlock_after_unix > 0 and now < header_policy.unlock_after_unix:
        raise TimeLockError(
            f"Контейнер откроется не раньше {format_utc(header_policy.unlock_after_unix)}. "
            f"Сейчас (проверенное время): {format_utc(now)}."
        )
    if header_policy.unlock_before_unix > 0 and now > header_policy.unlock_before_unix:
        raise TimeLockError(
            f"Срок доступа истёк {format_utc(header_policy.unlock_before_unix)}. "
            f"Сейчас: {format_utc(now)}."
        )


def verify_timelock_sealed(key: bytes, header_policy: TimeLockPolicy, sealed: bytes) -> None:
    """После правильного пароля — сверка, что заголовок не подделан."""
    if not header_policy.enabled:
        return
    opened = open_timelock(key, sealed)
    if opened is None:
        raise TimeLockError("Повреждена или подделана метка времени в контейнере.")
    if (
        opened.unlock_after_unix != header_policy.unlock_after_unix
        or opened.unlock_before_unix != header_policy.unlock_before_unix
        or opened.enabled != header_policy.enabled
    ):
        raise TimeLockError(
            "Обнаружена подделка времени открытия в файле контейнера. Открытие запрещено."
        )
