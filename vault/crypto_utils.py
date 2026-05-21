"""Key derivation and authenticated encryption (maximum security profile)."""

from __future__ import annotations

import hashlib
import os
import secrets
import time

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b"EVLT"
VERSION_LEGACY = 1
VERSION_SECURE = 2
VERSION_TIMELOCK = 3

KDF_ARGON2ID = 1
KDF_PBKDF2 = 0

SALT_SIZE = 32
GUARD_SALT_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
PWD_CHECK_SIZE = NONCE_SIZE + 20 + TAG_SIZE

# Legacy v1
KDF_ITERATIONS = 600_000
PASSWORD_CHECK_PLAIN = b"VAULT_PASSWORD_OK_v1"
FAIL_SEAL_PLAIN = b"VAULT_FAILCOUNT_v2"

# Argon2id — профиль «максимум» (OWASP / пароли)
ARGON2_TIME_COST = 4
ARGON2_MEMORY_KIB = 262_144
ARGON2_PARALLELISM = 4

_FAIL_OPEN_OFFSET_V2 = 84
_TIMELOCK_ENABLED_OFFSET_V3 = 152
_TIMELOCK_AFTER_OFFSET_V3 = 153
_TIMELOCK_BEFORE_OFFSET_V3 = 161
TIMELOCK_SEAL_MAX = 80


class WrongPasswordError(ValueError):
    def __init__(self, message: str, *, attempts: int, remaining: int | None):
        super().__init__(message)
        self.attempts = attempts
        self.remaining = remaining


class VaultDestroyedError(RuntimeError):
    pass


def derive_key_pbkdf2(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(_password_bytes(password))


def derive_key_argon2id(
    password: str,
    salt: bytes,
    time_cost: int = ARGON2_TIME_COST,
    memory_kib: int = ARGON2_MEMORY_KIB,
    parallelism: int = ARGON2_PARALLELISM,
    pepper: str = "",
) -> bytes:
    pwd = _password_bytes(password, pepper)
    return hash_secret_raw(
        secret=pwd,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def derive_key(
    password: str,
    salt: bytes,
    *,
    kdf_type: int = KDF_ARGON2ID,
    iterations: int = KDF_ITERATIONS,
    argon_time: int = ARGON2_TIME_COST,
    argon_memory_kib: int = ARGON2_MEMORY_KIB,
    argon_parallel: int = ARGON2_PARALLELISM,
    pepper: str = "",
) -> bytes:
    if kdf_type == KDF_PBKDF2:
        return derive_key_pbkdf2(password, salt, iterations)
    return derive_key_argon2id(
        password, salt, argon_time, argon_memory_kib, argon_parallel, pepper
    )


def derive_timelock_key(
    salt: bytes,
    guard_salt: bytes,
    unlock_after_unix: int,
    unlock_before_unix: int,
    *,
    argon_time: int = ARGON2_TIME_COST,
    argon_memory_kib: int = ARGON2_MEMORY_KIB,
    argon_parallel: int = ARGON2_PARALLELISM,
    pepper: str = "",
) -> bytes:
    """Ключ контейнера без пароля (только режим timelock)."""
    material = (
        salt
        + guard_salt
        + unlock_after_unix.to_bytes(8, "big")
        + unlock_before_unix.to_bytes(8, "big")
        + b"evlt-timelock-master-v2"
    )
    time_salt = hashlib.sha256(material).digest()[:SALT_SIZE]
    return derive_key_argon2id(
        "",
        time_salt,
        time_cost=argon_time,
        memory_kib=argon_memory_kib,
        parallelism=argon_parallel,
        pepper=pepper + "timelock",
    )


def derive_file_key(master_key: bytes, file_name: str) -> bytes:
    """Отдельный ключ AES на каждый файл (HKDF-SHA512)."""
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=KEY_SIZE,
        salt=None,
        info=f"evlt-file-v2:{file_name}".encode("utf-8"),
    )
    return hkdf.derive(master_key)


def encrypt_blob(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(NONCE_SIZE)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_blob(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None
) -> bytes:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, aad)


def make_password_check(key: bytes) -> bytes:
    nonce, ct = encrypt_blob(key, PASSWORD_CHECK_PLAIN)
    return nonce + ct


def verify_password(key: bytes, blob: bytes) -> bool:
    if len(blob) != PWD_CHECK_SIZE:
        return False
    nonce = blob[:NONCE_SIZE]
    ct = blob[NONCE_SIZE:]
    try:
        return decrypt_blob(key, nonce, ct) == PASSWORD_CHECK_PLAIN
    except Exception:
        return False


def seal_fail_count(key: bytes, count: int) -> bytes:
    payload = count.to_bytes(4, "big") + FAIL_SEAL_PLAIN
    nonce, ct = encrypt_blob(key, payload)
    return nonce + ct


def open_fail_count(key: bytes, blob: bytes) -> int | None:
    if len(blob) < NONCE_SIZE + 4 + len(FAIL_SEAL_PLAIN) + TAG_SIZE:
        return None
    try:
        plain = decrypt_blob(key, blob[:NONCE_SIZE], blob[NONCE_SIZE:])
        if not plain.endswith(FAIL_SEAL_PLAIN):
            return None
        return int.from_bytes(plain[:4], "big")
    except Exception:
        return None


def brute_force_delay(
    attempt: int,
    *,
    min_delay: float,
    multiplier: float,
    max_delay: float,
) -> None:
    if attempt <= 0 or min_delay <= 0:
        return
    delay = min(min_delay * (multiplier ** min(attempt - 1, 16)), max_delay)
    time.sleep(delay)


def secure_destroy_file(path: os.PathLike[str] | str, passes: int = 3) -> None:
    """Перезапись случайными данными и удаление файла."""
    p = os.fspath(path)
    if not os.path.isfile(p):
        return
    size = os.path.getsize(p)
    try:
        with open(p, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
    except OSError:
        pass
    try:
        os.remove(p)
    except OSError:
        # Windows: файл мог быть заблокирован — переименовать и удалить
        trash = p + ".destroyed"
        try:
            os.replace(p, trash)
            os.remove(trash)
        except OSError:
            pass


def _password_bytes(password: str, pepper: str = "") -> bytes:
    return (password + pepper).encode("utf-8")


def fail_open_offset_v2() -> int:
    return _FAIL_OPEN_OFFSET_V2


def timelock_enabled_offset_v3() -> int:
    return _TIMELOCK_ENABLED_OFFSET_V3
