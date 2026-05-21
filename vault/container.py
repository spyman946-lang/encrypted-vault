"""Encrypted vault container format and operations."""

from __future__ import annotations

import json
import os
import struct
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from .crypto_utils import (
    MAGIC,
    VERSION_LEGACY,
    VERSION_SECURE,
    VERSION_TIMELOCK,
    KDF_ARGON2ID,
    KDF_PBKDF2,
    SALT_SIZE,
    GUARD_SALT_SIZE,
    KDF_ITERATIONS,
    PWD_CHECK_SIZE,
    TIMELOCK_SEAL_MAX,
    derive_key,
    derive_timelock_key,
    derive_file_key,
    encrypt_blob,
    decrypt_blob,
    make_password_check,
    verify_password,
    seal_fail_count,
    open_fail_count,
    brute_force_delay,
    secure_destroy_file,
    fail_open_offset_v2,
    WrongPasswordError,
    VaultDestroyedError,
)
from .settings import VaultSettings, load_settings
from .time_verify import TimeVerificationError, get_trusted_time
from .protection import (
    ProtectionMode,
    legacy_byte_to_mode,
    mode_uses_password,
    mode_uses_timelock,
    validate_create,
)
from .timelock import (
    TimeLockError,
    TimeLockPolicy,
    check_timelock_pre_password,
    seal_timelock,
    verify_timelock_sealed,
)

FAIL_SEAL_MAX = 64
FLAG_TIMELOCK = 0x0001


@dataclass
class VaultEntry:
    name: str
    size: int
    mtime: str
    nonce: str
    offset: int
    length: int


@dataclass
class VaultHeader:
    version: int
    salt: bytes
    pwd_check: bytes
    kdf_type: int = KDF_ARGON2ID
    iterations: int = KDF_ITERATIONS
    argon_time: int = 4
    argon_memory_kib: int = 262_144
    argon_parallel: int = 4
    guard_salt: bytes = field(default_factory=lambda: b"")
    fail_open: int = 0
    fail_sealed: bytes = b""
    timelock: TimeLockPolicy = field(default_factory=TimeLockPolicy)
    time_sealed: bytes = b""
    protection: ProtectionMode = ProtectionMode.PASSWORD

    @property
    def timelock_policy(self) -> TimeLockPolicy:
        return self.timelock


@dataclass
class VaultContainer:
    path: Path
    key: bytes
    salt: bytes
    header: VaultHeader
    entries: dict[str, VaultEntry] = field(default_factory=dict)
    data_start: int = 0
    settings: VaultSettings = field(default_factory=load_settings)

    @property
    def iterations(self) -> int:
        return self.header.iterations

    @classmethod
    def create(
        cls,
        path: Path,
        settings: VaultSettings | None = None,
        *,
        protection: ProtectionMode = ProtectionMode.PASSWORD,
        password: str | None = None,
        timelock: TimeLockPolicy | None = None,
    ) -> VaultContainer:
        path = Path(path)
        if path.exists():
            raise FileExistsError(f"Контейнер уже существует: {path}")

        cfg = settings or load_settings()
        pwd, tl = validate_create(
            protection,
            password,
            timelock,
            allow_empty_password=(password == "" and protection == ProtectionMode.PASSWORD),
        )

        salt = os.urandom(SALT_SIZE)
        guard_salt = os.urandom(GUARD_SALT_SIZE)

        if protection == ProtectionMode.TIMELOCK:
            key = derive_timelock_key(
                salt,
                guard_salt,
                tl.unlock_after_unix,
                tl.unlock_before_unix,
                argon_time=cfg.argon2_time_cost,
                argon_memory_kib=cfg.argon2_memory_kib,
                argon_parallel=cfg.argon2_parallelism,
                pepper=cfg.kdf_pepper,
            )
        else:
            key = derive_key(
                pwd or "",
                salt,
                kdf_type=KDF_ARGON2ID,
                argon_time=cfg.argon2_time_cost,
                argon_memory_kib=cfg.argon2_memory_kib,
                argon_parallel=cfg.argon2_parallelism,
                pepper=cfg.kdf_pepper,
            )

        use_v3 = protection != ProtectionMode.PASSWORD
        header = VaultHeader(
            version=VERSION_TIMELOCK if use_v3 else VERSION_SECURE,
            salt=salt,
            pwd_check=make_password_check(key),
            kdf_type=KDF_ARGON2ID,
            argon_time=cfg.argon2_time_cost,
            argon_memory_kib=cfg.argon2_memory_kib,
            argon_parallel=cfg.argon2_parallelism,
            guard_salt=guard_salt,
            fail_open=0,
            fail_sealed=seal_fail_count(key, 0) if mode_uses_password(protection) else b"",
            timelock=tl,
            time_sealed=seal_timelock(key, tl) if mode_uses_timelock(protection) else b"",
            protection=protection,
        )
        manifest = {"files": {}}

        with open(path, "wb") as f:
            cls._write_header(f, header)
            data_start = cls._write_manifest(f, key, manifest)

        return cls(
            path=path,
            key=key,
            salt=salt,
            header=header,
            entries={},
            data_start=data_start,
            settings=cfg,
        )

    @classmethod
    def open(
        cls,
        path: Path,
        password: str | None = None,
        settings: VaultSettings | None = None,
        *,
        skip_timelock_check: bool = False,
    ) -> VaultContainer:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Контейнер не найден: {path}")

        cfg = settings or load_settings()

        with open(path, "rb") as f:
            header = cls._read_header(f)

        mode = header.protection

        if mode_uses_timelock(mode) and not skip_timelock_check:
            try:
                trusted = get_trusted_time(cfg)
                check_timelock_pre_password(header.timelock, trusted)
            except TimeVerificationError as e:
                raise TimeLockError(str(e)) from e

        if mode_uses_password(mode):
            cls._apply_pre_delay(path, header, cfg)

        if mode == ProtectionMode.TIMELOCK:
            key = derive_timelock_key(
                header.salt,
                header.guard_salt,
                header.timelock.unlock_after_unix,
                header.timelock.unlock_before_unix,
                argon_time=header.argon_time,
                argon_memory_kib=header.argon_memory_kib,
                argon_parallel=header.argon_parallel,
                pepper=cfg.kdf_pepper,
            )
            if not verify_password(key, header.pwd_check):
                raise TimeLockError("Повреждён контейнер или неверные параметры времени.")
        else:
            if password is None:
                raise ValueError("Для этого контейнера требуется пароль.")
            key = derive_key(
                password,
                header.salt,
                kdf_type=header.kdf_type,
                iterations=header.iterations,
                argon_time=header.argon_time,
                argon_memory_kib=header.argon_memory_kib,
                argon_parallel=header.argon_parallel,
                pepper=cfg.kdf_pepper,
            )
            if not verify_password(key, header.pwd_check):
                cls._on_wrong_password(path, header, cfg)

        if mode_uses_timelock(mode):
            try:
                verify_timelock_sealed(key, header.timelock, header.time_sealed)
            except TimeLockError:
                raise
            except Exception as e:
                raise TimeLockError("Ошибка проверки метки времени.") from e

        if header.version >= VERSION_SECURE:
            sealed = open_fail_count(key, header.fail_sealed) or 0
            effective = max(header.fail_open, sealed)
            if cfg.max_failed_attempts > 0 and effective >= cfg.max_failed_attempts:
                cls._destroy_vault(path, cfg)
                raise VaultDestroyedError(
                    "Контейнер уничтожен: превышен лимит неверных попыток (в т.ч. до прошлого открытия)."
                )
            header.fail_open = 0
            header.fail_sealed = seal_fail_count(key, 0)
            cls._write_header_fields(path, header)

        with open(path, "rb") as f:
            cls._read_header(f)
            manifest, data_start = cls._read_manifest(f, key)

        entries = {}
        for name, meta in manifest.get("files", {}).items():
            entries[name] = VaultEntry(
                name=name,
                size=meta["size"],
                mtime=meta["mtime"],
                nonce=meta["nonce"],
                offset=meta["offset"],
                length=meta["length"],
            )

        return cls(
            path=path,
            key=key,
            salt=header.salt,
            header=header,
            entries=entries,
            data_start=data_start,
            settings=cfg,
        )

    @classmethod
    def _apply_pre_delay(cls, path: Path, header: VaultHeader, cfg: VaultSettings) -> None:
        if header.version < VERSION_SECURE or header.fail_open <= 0:
            return
        brute_force_delay(
            header.fail_open,
            min_delay=cfg.min_delay_seconds,
            multiplier=cfg.delay_multiplier,
            max_delay=cfg.max_delay_seconds,
        )

    @classmethod
    def _on_wrong_password(cls, path: Path, header: VaultHeader, cfg: VaultSettings) -> None:
        if header.version >= VERSION_SECURE:
            header.fail_open += 1
            cls._write_header_fields(path, header)
            brute_force_delay(
                header.fail_open,
                min_delay=cfg.min_delay_seconds,
                multiplier=cfg.delay_multiplier,
                max_delay=cfg.max_delay_seconds,
            )
            limit = cfg.max_failed_attempts
            if limit > 0 and header.fail_open >= limit:
                if cfg.destroy_on_max_attempts:
                    cls._destroy_vault(path, cfg)
                    raise VaultDestroyedError(
                        f"Контейнер уничтожен после {header.fail_open} неверных попыток ввода пароля."
                    )
                raise WrongPasswordError(
                    "Превышен лимит попыток. Контейнер заблокирован (самоуничтожение отключено в настройках).",
                    attempts=header.fail_open,
                    remaining=0,
                )
            remaining = limit - header.fail_open if limit > 0 else None
            msg = f"Неверный пароль. Неудачных попыток: {header.fail_open}"
            if remaining is not None:
                msg += f". Осталось до уничтожения: {remaining}"
            raise WrongPasswordError(msg, attempts=header.fail_open, remaining=remaining)

        raise WrongPasswordError(
            "Неверный пароль",
            attempts=1,
            remaining=None,
        )

    @classmethod
    def _destroy_vault(cls, path: Path, cfg: VaultSettings) -> None:
        secure_destroy_file(path, passes=3)
        sidecar = Path(str(path) + ".attempts")
        if sidecar.exists():
            secure_destroy_file(sidecar, passes=1)

    @staticmethod
    def _write_header(f: BinaryIO, header: VaultHeader) -> None:
        if header.version >= VERSION_SECURE:
            fail_sealed = header.fail_sealed[:FAIL_SEAL_MAX]
            ver = VERSION_TIMELOCK if header.protection != ProtectionMode.PASSWORD else VERSION_SECURE
            flags = FLAG_TIMELOCK if mode_uses_timelock(header.protection) else 0
            f.write(MAGIC)
            f.write(struct.pack("<B", ver))
            f.write(struct.pack("<H", flags))
            f.write(struct.pack("<B", header.kdf_type))
            f.write(struct.pack("<I", header.argon_time))
            f.write(struct.pack("<I", header.argon_memory_kib))
            f.write(struct.pack("<I", header.argon_parallel))
            f.write(header.salt)
            f.write(header.guard_salt)
            f.write(struct.pack("<I", header.fail_open))
            f.write(fail_sealed.ljust(FAIL_SEAL_MAX, b"\x00"))
            if ver >= VERSION_TIMELOCK:
                tl = header.timelock
                f.write(struct.pack("<B", int(header.protection)))
                f.write(struct.pack("<Q", tl.unlock_after_unix))
                f.write(struct.pack("<Q", tl.unlock_before_unix))
                sealed = header.time_sealed[:TIMELOCK_SEAL_MAX]
                f.write(sealed.ljust(TIMELOCK_SEAL_MAX, b"\x00"))
            f.write(header.pwd_check)
        else:
            f.write(MAGIC)
            f.write(struct.pack("<B", VERSION_LEGACY))
            f.write(struct.pack("<I", header.iterations))
            f.write(header.salt)
            f.write(header.pwd_check)

    @classmethod
    def _write_header_fields(cls, path: Path, header: VaultHeader) -> None:
        with open(path, "r+b") as f:
            if header.version >= VERSION_SECURE:
                f.seek(fail_open_offset_v2())
                f.write(struct.pack("<I", header.fail_open))
                f.seek(fail_open_offset_v2() + 4)
                sealed = header.fail_sealed[:FAIL_SEAL_MAX]
                f.write(sealed.ljust(FAIL_SEAL_MAX, b"\x00"))
            # v1 has no counter

    @staticmethod
    def _read_header(f: BinaryIO) -> VaultHeader:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("Это не файл зашифрованного контейнера (неверная сигнатура)")
        version = struct.unpack("<B", f.read(1))[0]

        if version >= VERSION_SECURE:
            flags = struct.unpack("<H", f.read(2))[0]
            kdf_type = struct.unpack("<B", f.read(1))[0]
            argon_time = struct.unpack("<I", f.read(4))[0]
            argon_memory = struct.unpack("<I", f.read(4))[0]
            argon_parallel = struct.unpack("<I", f.read(4))[0]
            salt = f.read(SALT_SIZE)
            guard_salt = f.read(GUARD_SALT_SIZE)
            fail_open = struct.unpack("<I", f.read(4))[0]
            fail_sealed = f.read(FAIL_SEAL_MAX).rstrip(b"\x00")
            timelock = TimeLockPolicy()
            time_sealed = b""
            protection = ProtectionMode.PASSWORD
            if version >= VERSION_TIMELOCK or (flags & FLAG_TIMELOCK):
                mode_byte = struct.unpack("<B", f.read(1))[0]
                after = struct.unpack("<Q", f.read(8))[0]
                before = struct.unpack("<Q", f.read(8))[0]
                time_sealed = f.read(TIMELOCK_SEAL_MAX).rstrip(b"\x00")
                protection = legacy_byte_to_mode(mode_byte, after, before)
                timelock = TimeLockPolicy(
                    enabled=mode_uses_timelock(protection),
                    unlock_after_unix=after,
                    unlock_before_unix=before,
                )
            pwd_check = f.read(PWD_CHECK_SIZE)
            if len(pwd_check) != PWD_CHECK_SIZE:
                raise ValueError("Повреждённый заголовок контейнера")
            return VaultHeader(
                version=version,
                salt=salt,
                pwd_check=pwd_check,
                kdf_type=kdf_type,
                argon_time=argon_time,
                argon_memory_kib=argon_memory,
                argon_parallel=argon_parallel,
                guard_salt=guard_salt,
                fail_open=fail_open,
                fail_sealed=fail_sealed,
                timelock=timelock,
                time_sealed=time_sealed,
                protection=protection,
            )

        if version != VERSION_LEGACY:
            raise ValueError(f"Неподдерживаемая версия контейнера: {version}")
        iterations = struct.unpack("<I", f.read(4))[0]
        salt = f.read(SALT_SIZE)
        pwd_check = f.read(PWD_CHECK_SIZE)
        if len(pwd_check) != PWD_CHECK_SIZE:
            raise ValueError("Повреждённый заголовок контейнера")
        return VaultHeader(
            version=version,
            salt=salt,
            pwd_check=pwd_check,
            kdf_type=KDF_PBKDF2,
            iterations=iterations,
        )

    @staticmethod
    def _write_manifest(f: BinaryIO, key: bytes, manifest: dict) -> int:
        plain = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
        nonce, ct = encrypt_blob(key, plain)
        f.write(nonce)
        f.write(struct.pack("<I", len(ct)))
        f.write(ct)
        return f.tell()

    @staticmethod
    def _read_manifest(f: BinaryIO, key: bytes) -> tuple[dict, int]:
        nonce = f.read(12)
        (length,) = struct.unpack("<I", f.read(4))
        ct = f.read(length)
        plain = decrypt_blob(key, nonce, ct)
        return json.loads(plain.decode("utf-8")), f.tell()

    def _encrypt_file_data(self, name: str, data: bytes) -> tuple[str, bytes]:
        file_key = derive_file_key(self.key, name)
        nonce, packed = encrypt_blob(file_key, data)
        return nonce.hex(), packed

    def _decrypt_file_data(self, name: str, entry: VaultEntry) -> bytes:
        with open(self.path, "rb") as f:
            f.seek(entry.offset)
            packed = f.read(entry.length)
        nonce = bytes.fromhex(entry.nonce)
        if self.header.version >= VERSION_SECURE:
            file_key = derive_file_key(self.key, name)
            return decrypt_blob(file_key, nonce, packed)
        return decrypt_blob(self.key, nonce, packed)

    def _header_size(self) -> int:
        if self.header.version >= VERSION_TIMELOCK or mode_uses_timelock(self.header.protection):
            return (
                4 + 1 + 2 + 1 + 4 + 4 + 4 + SALT_SIZE + GUARD_SALT_SIZE + 4
                + FAIL_SEAL_MAX + 1 + 8 + 8 + TIMELOCK_SEAL_MAX + PWD_CHECK_SIZE
            )
        if self.header.version >= VERSION_SECURE:
            return (
                4 + 1 + 2 + 1 + 4 + 4 + 4 + SALT_SIZE + GUARD_SALT_SIZE + 4 + FAIL_SEAL_MAX + PWD_CHECK_SIZE
            )
        return 4 + 1 + 4 + SALT_SIZE + PWD_CHECK_SIZE

    def _encrypted_manifest_size(self, manifest_files: dict[str, dict]) -> int:
        plain = json.dumps({"files": manifest_files}, ensure_ascii=False).encode("utf-8")
        _, ct = encrypt_blob(self.key, plain)
        return 12 + 4 + len(ct)

    def _build_manifest_files(self, blobs: dict[str, bytes]) -> dict[str, dict]:
        names = sorted(blobs.keys())
        manifest_files: dict[str, dict] = {}
        for _ in range(16):
            offset = self._header_size() + self._encrypted_manifest_size(manifest_files)
            new_manifest: dict[str, dict] = {}
            for name in names:
                entry = self.entries[name]
                packed = blobs[name]
                new_manifest[name] = {
                    "size": entry.size,
                    "mtime": entry.mtime,
                    "nonce": entry.nonce,
                    "offset": offset,
                    "length": len(packed),
                }
                offset += len(packed)
            if new_manifest == manifest_files:
                return manifest_files
            manifest_files = new_manifest
        return manifest_files

    def _persist(self, blobs: dict[str, bytes]) -> None:
        manifest_files = self._build_manifest_files(blobs)
        fd, tmp_name = tempfile.mkstemp(
            dir=self.path.parent,
            prefix=f".{self.path.stem}_",
            suffix=".tmp",
        )
        os.close(fd)
        tmp_path = Path(tmp_name)
        try:
            with open(tmp_path, "wb") as out:
                self.header.pwd_check = make_password_check(self.key)
                if self.header.version >= VERSION_SECURE:
                    self.header.fail_sealed = seal_fail_count(self.key, self.header.fail_open)
                if mode_uses_timelock(self.header.protection):
                    self.header.version = VERSION_TIMELOCK
                    self.header.time_sealed = seal_timelock(self.key, self.header.timelock)
                self._write_header(out, self.header)
                self._write_manifest(out, self.key, {"files": manifest_files})
                for name in sorted(blobs.keys()):
                    out.write(blobs[name])
                for name, meta in manifest_files.items():
                    self.entries[name] = VaultEntry(
                        name=name,
                        size=meta["size"],
                        mtime=meta["mtime"],
                        nonce=meta["nonce"],
                        offset=meta["offset"],
                        length=meta["length"],
                    )

            os.replace(tmp_path, self.path)
            with open(self.path, "rb") as f:
                self.header = self._read_header(f)
                _, self.data_start = self._read_manifest(f, self.key)
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise

    def _collect_blobs(self) -> dict[str, bytes]:
        blobs = {}
        with open(self.path, "rb") as f:
            for name, entry in self.entries.items():
                f.seek(entry.offset)
                blobs[name] = f.read(entry.length)
        return blobs

    def add_file(self, source: Path, arc_name: str | None = None) -> VaultEntry:
        source = Path(source)
        if not source.is_file():
            raise FileNotFoundError(f"Файл не найден: {source}")
        name = (arc_name or source.name).replace("\\", "/")
        if name in self.entries:
            raise ValueError(f"Файл уже есть в контейнере: {name}")

        data = source.read_bytes()
        nonce_hex, packed = self._encrypt_file_data(name, data)
        mtime = datetime.fromtimestamp(source.stat().st_mtime, tz=timezone.utc).isoformat()

        self.entries[name] = VaultEntry(
            name=name,
            size=len(data),
            mtime=mtime,
            nonce=nonce_hex,
            offset=0,
            length=len(packed),
        )
        blobs = self._collect_blobs()
        blobs[name] = packed
        self._persist(blobs)
        return self.entries[name]

    def extract_file(self, name: str, dest_dir: Path) -> Path:
        if name not in self.entries:
            raise KeyError(f"Файл не найден в контейнере: {name}")
        data = self._decrypt_file_data(name, self.entries[name])
        dest_dir = Path(dest_dir)
        dest_dir.mkdir(parents=True, exist_ok=True)
        out = dest_dir / Path(name).name
        out.write_bytes(data)
        return out

    def remove_file(self, name: str) -> None:
        if name not in self.entries:
            raise KeyError(f"Файл не найден в контейнере: {name}")
        del self.entries[name]
        blobs = self._collect_blobs()
        blobs.pop(name, None)
        self._persist(blobs)

    def list_files(self) -> list[VaultEntry]:
        return sorted(self.entries.values(), key=lambda e: e.name.lower())

    def change_password(self, new_password: str) -> None:
        if not mode_uses_password(self.header.protection):
            raise ValueError("Контейнер без пароля (режим timelock). Смена пароля недоступна.")
        blobs = self._collect_blobs()
        plaintexts = {name: self._decrypt_file_data(name, self.entries[name]) for name in blobs}

        new_salt = os.urandom(SALT_SIZE)
        new_key = derive_key(
            new_password,
            new_salt,
            kdf_type=self.header.kdf_type,
            iterations=self.header.iterations,
            argon_time=self.header.argon_time,
            argon_memory_kib=self.header.argon_memory_kib,
            argon_parallel=self.header.argon_parallel,
            pepper=self.settings.kdf_pepper,
        )
        self.salt = new_salt
        self.key = new_key
        self.header.salt = new_salt
        self.header.fail_open = 0
        self.header.fail_sealed = seal_fail_count(new_key, 0)

        reencrypted: dict[str, bytes] = {}
        for name, plain in plaintexts.items():
            nonce_hex, new_packed = self._encrypt_file_data(name, plain)
            entry = self.entries[name]
            self.entries[name] = VaultEntry(
                name=name,
                size=entry.size,
                mtime=entry.mtime,
                nonce=nonce_hex,
                offset=0,
                length=len(new_packed),
            )
            reencrypted[name] = new_packed
        self._persist(reencrypted)

    def set_timelock(self, policy: TimeLockPolicy) -> None:
        if self.header.protection == ProtectionMode.TIMELOCK:
            raise ValueError("Контейнер только с защитой по времени — создайте новый контейнер.")
        if policy.unlock_after_unix <= 0 and policy.unlock_before_unix <= 0:
            raise ValueError("Укажите --after и/или --before для временной блокировки.")
        self.header.protection = ProtectionMode.BOTH
        self.header.timelock = TimeLockPolicy(
            enabled=True,
            unlock_after_unix=policy.unlock_after_unix,
            unlock_before_unix=policy.unlock_before_unix,
        )
        self.header.version = VERSION_TIMELOCK
        self.header.time_sealed = seal_timelock(self.key, self.header.timelock)
        self._persist(self._collect_blobs())

    def clear_timelock(self) -> None:
        if self.header.protection == ProtectionMode.TIMELOCK:
            raise ValueError("Нельзя отключить единственную защиту по времени. Создайте контейнер с режимом password.")
        if self.header.protection == ProtectionMode.PASSWORD:
            return
        self.header.protection = ProtectionMode.PASSWORD
        self.header.timelock = TimeLockPolicy(enabled=False)
        self.header.time_sealed = b""
        self.header.version = VERSION_SECURE
        self._persist(self._collect_blobs())

    @classmethod
    def read_header_public(cls, path: Path) -> VaultHeader:
        with open(path, "rb") as f:
            return cls._read_header(f)

    @classmethod
    def read_protection_mode(cls, path: Path) -> ProtectionMode:
        return cls.read_header_public(path).protection

    @classmethod
    def read_timelock_public(cls, path: Path) -> TimeLockPolicy:
        return cls.read_header_public(path).timelock

    @classmethod
    def check_time_sources(cls, settings: VaultSettings | None = None) -> dict:
        cfg = settings or load_settings()
        trusted = get_trusted_time(cfg)
        return {
            "trusted_utc": trusted.utc.isoformat(),
            "network_median": trusted.network_median,
            "local_skew_seconds": trusted.local_skew_seconds,
            "sources": [
                {"name": s.source, "utc": datetime.fromtimestamp(s.unix, tz=timezone.utc).isoformat(), "local": s.is_local}
                for s in trusted.samples
            ],
        }

    def security_info(self) -> dict:
        h = self.header
        info = {
            "version": h.version,
            "kdf": "Argon2id" if h.kdf_type == KDF_ARGON2ID else "PBKDF2",
            "argon2_time": h.argon_time,
            "argon2_memory_mib": h.argon_memory_kib // 1024,
            "file_keys": "HKDF-SHA512 per file" if h.version >= VERSION_SECURE else "master key",
            "failed_attempts": h.fail_open,
            "max_failed_attempts": self.settings.max_failed_attempts,
            "destroy_enabled": self.settings.destroy_on_max_attempts,
            "protection": h.protection.label_ru(),
            "protection_mode": int(h.protection),
            "timelock_enabled": mode_uses_timelock(h.protection),
        }
        if mode_uses_timelock(h.protection):
            from .time_verify import format_utc

            if h.timelock.unlock_after_unix:
                info["unlock_after"] = format_utc(h.timelock.unlock_after_unix)
            if h.timelock.unlock_before_unix:
                info["unlock_before"] = format_utc(h.timelock.unlock_before_unix)
        return info
