"""Встроенное хранилище .evlt в хвосте exe: LZMA (max) + AES-256-GCM."""

from __future__ import annotations

import atexit
import hashlib
import lzma
import os
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .crypto_utils import KEY_SIZE, MAGIC, NONCE_SIZE

FOOTER_MAGIC = b"EVLTEND1"
FOOTER_VERSION_RAW = 1
FOOTER_VERSION_SECURE = 2
FOOTER_TAIL_V1 = 20
FOOTER_TAIL_V2 = 32
EMBED_AAD = b"EncryptedVault-exe-embed-v2"
EMBED_IKM = b"EncryptedVault-Exe-Embed-Key-v1"

_pending_updates: list[tuple[Path, Path]] = []


def is_frozen_app() -> bool:
    return bool(getattr(sys, "frozen", False))


def embedded_exe_path() -> Path:
    return Path(sys.executable).resolve()


def is_embed_target(path: Path) -> bool:
    if not is_frozen_app():
        return False
    try:
        return path.resolve() == embedded_exe_path()
    except OSError:
        return False


def _embed_pepper() -> str:
    try:
        from .app_store import settings_path
        from .settings import load_settings

        return load_settings(settings_path()).kdf_pepper
    except Exception:
        return ""


def derive_embed_key(pepper: str = "") -> bytes:
    ikm = hashlib.sha512(EMBED_IKM + pepper.encode("utf-8")).digest()
    return HKDF(
        algorithm=hashes.SHA512(),
        length=KEY_SIZE,
        salt=b"EVLT-EXE-EMBED",
        info=b"v2",
    ).derive(ikm)


def _compress_vault(vault: bytes) -> bytes:
    return lzma.compress(
        vault,
        format=lzma.FORMAT_XZ,
        filters=[
            {"id": lzma.FILTER_LZMA2, "preset": 9 | lzma.PRESET_EXTREME},
        ],
    )


def _decompress_vault(data: bytes) -> bytes:
    return lzma.decompress(data)


def pack_vault_payload(vault: bytes, *, pepper: str | None = None) -> bytes:
    """Сжатие (LZMA extreme) + шифрование AES-256-GCM для вшивания в exe."""
    if len(vault) < 4 or vault[:4] != MAGIC:
        raise ValueError("Некорректные данные контейнера для вшивания в exe")
    pepper = _embed_pepper() if pepper is None else pepper
    compressed = _compress_vault(vault)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_embed_key(pepper)
    ciphertext = AESGCM(key).encrypt(nonce, compressed, EMBED_AAD)
    return nonce + ciphertext


def unpack_vault_payload(blob: bytes, *, pepper: str | None = None) -> bytes:
    if len(blob) < NONCE_SIZE + 17:
        raise ValueError("Повреждён встроенный блок в exe")
    pepper = _embed_pepper() if pepper is None else pepper
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    key = derive_embed_key(pepper)
    compressed = AESGCM(key).decrypt(nonce, ciphertext, EMBED_AAD)
    vault = _decompress_vault(compressed)
    if len(vault) < 4 or vault[:4] != MAGIC:
        raise ValueError("Встроенный контейнер повреждён после расшифровки")
    return vault


def _parse_footer(blob: bytes) -> tuple[bytes, int, int, bytes | None]:
    """base, version, payload_size, nonce (v2 only)."""
    if len(blob) < FOOTER_TAIL_V1 or blob[-8:] != FOOTER_MAGIC:
        return blob, 0, 0, None
    payload_size = struct.unpack_from("<Q", blob, len(blob) - 16)[0]
    version = struct.unpack_from("<I", blob, len(blob) - 20)[0]
    if version == FOOTER_VERSION_SECURE:
        if len(blob) < FOOTER_TAIL_V2 or payload_size <= 0:
            return blob, 0, 0, None
        nonce = blob[len(blob) - FOOTER_TAIL_V2 : len(blob) - 20]
        total = FOOTER_TAIL_V2 + payload_size
        if len(blob) < total:
            return blob, 0, 0, None
        return blob[:-total], version, payload_size, nonce
    if version == FOOTER_VERSION_RAW and payload_size > 0:
        total = FOOTER_TAIL_V1 + payload_size
        if len(blob) < total:
            return blob, 0, 0, None
        return blob[:-total], version, payload_size, None
    return blob, 0, 0, None


def parse_overlay(blob: bytes, *, pepper: str | None = None) -> tuple[bytes, bytes | None]:
    base, version, payload_size, nonce = _parse_footer(blob)
    if version == 0:
        return blob, None
    payload = blob[len(base) : len(base) + payload_size]
    if version == FOOTER_VERSION_RAW:
        if len(payload) < 4 or payload[:4] != MAGIC:
            return blob, None
        return base, payload
    if version == FOOTER_VERSION_SECURE and nonce is not None:
        try:
            return base, unpack_vault_payload(nonce + payload, pepper=pepper)
        except Exception:
            return blob, None
    return blob, None


def attach_overlay(base: bytes, vault: bytes, *, pepper: str | None = None) -> bytes:
    packed = pack_vault_payload(vault, pepper=pepper)
    nonce = packed[:NONCE_SIZE]
    ciphertext = packed[NONCE_SIZE:]
    footer = nonce + struct.pack("<IQ", FOOTER_VERSION_SECURE, len(ciphertext)) + FOOTER_MAGIC
    return base + ciphertext + footer


def read_embedded_vault_bytes(exe: Path, *, pepper: str | None = None) -> bytes | None:
    return parse_overlay(exe.read_bytes(), pepper=pepper)[1]


def embedded_payload_stats(exe: Path) -> dict | None:
    """Размеры для отладки: сжатый/зашифрованный блок в exe."""
    blob = exe.read_bytes()
    base, version, payload_size, nonce = _parse_footer(blob)
    if version != FOOTER_VERSION_SECURE:
        return None
    return {
        "exe_size": len(blob),
        "payload_encrypted": payload_size,
        "footer_version": version,
    }


def _work_path(exe: Path) -> Path:
    digest = hashlib.sha256(str(exe).casefold().encode("utf-8")).hexdigest()[:12]
    root = Path(os.environ.get("TEMP", ".")) / "EncryptedVault"
    root.mkdir(parents=True, exist_ok=True)
    return root / f"vault_{digest}.evlt"


def materialize_work_copy(exe: Path) -> Path:
    vault = read_embedded_vault_bytes(exe)
    if vault is None:
        raise FileNotFoundError(f"В exe нет встроенного контейнера: {exe}")
    work = _work_path(exe)
    work.write_bytes(vault)
    return work


def write_embedded_vault(exe: Path, vault_bytes: bytes, *, work_file: Path | None = None) -> None:
    exe = exe.resolve()
    base, _ = parse_overlay(exe.read_bytes())
    payload = attach_overlay(base, vault_bytes)
    tmp = exe.with_name(exe.name + ".tmpvault")
    tmp.write_bytes(payload)
    try:
        os.replace(tmp, exe)
        pending = exe.with_suffix(exe.suffix + ".vault_pending")
        if pending.exists():
            pending.unlink(missing_ok=True)
    except OSError:
        pending = exe.with_suffix(exe.suffix + ".vault_pending")
        if tmp.exists():
            os.replace(tmp, pending)
        _queue_pending(exe, work_file or _work_path(exe))


def strip_embedded_vault(exe: Path) -> None:
    exe = exe.resolve()
    base, vault = parse_overlay(exe.read_bytes())
    if vault is None:
        return
    tmp = exe.with_name(exe.name + ".tmpvault")
    tmp.write_bytes(base)
    try:
        os.replace(tmp, exe)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise


def _queue_pending(exe: Path, work: Path) -> None:
    pair = (exe, work)
    if pair not in _pending_updates:
        _pending_updates.append(pair)


def flush_pending_updates() -> None:
    for exe, work in list(_pending_updates):
        if not work.is_file():
            continue
        try:
            write_embedded_vault(exe, work.read_bytes(), work_file=work)
            _pending_updates.remove((exe, work))
        except OSError:
            pass


def resolve_vault_path(path: Path) -> tuple[Path, Path | None]:
    path = Path(path)
    if is_embed_target(path):
        if not has_embedded_vault(path):
            raise FileNotFoundError(f"В exe нет встроенного контейнера: {path}")
        return materialize_work_copy(path), path
    return path, None


def resolve_vault_path_for_create(path: Path) -> tuple[Path, Path | None]:
    path = Path(path)
    if is_embed_target(path):
        if not path.is_file():
            raise FileNotFoundError(f"Не найден exe: {path}")
        if has_embedded_vault(path):
            raise FileExistsError(f"В exe уже есть контейнер: {path}")
        work = _work_path(path)
        if work.exists():
            work.unlink(missing_ok=True)
        return work, path
    if path.exists():
        raise FileExistsError(f"Контейнер уже существует: {path}")
    return path, None


def has_embedded_vault(exe: Path | None = None) -> bool:
    exe = exe or embedded_exe_path()
    if not exe.is_file():
        return False
    return read_embedded_vault_bytes(exe) is not None


def vault_is_ready(path: Path) -> bool:
    path = Path(path)
    if is_embed_target(path):
        return has_embedded_vault(path)
    return path.is_file()


def after_persist(work: Path, embed_exe: Path | None) -> None:
    if embed_exe is None:
        return
    write_embedded_vault(embed_exe, work.read_bytes(), work_file=work)


def after_create(work: Path, embed_exe: Path | None) -> None:
    if embed_exe is None:
        return
    write_embedded_vault(embed_exe, work.read_bytes(), work_file=work)


def destroy_embedded(exe: Path) -> None:
    strip_embedded_vault(exe)
    work = _work_path(exe)
    if work.exists():
        work.unlink(missing_ok=True)


atexit.register(flush_pending_updates)
