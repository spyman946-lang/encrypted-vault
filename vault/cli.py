"""Command-line interface for encrypted vault."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .container import VaultContainer
from .crypto_utils import VaultDestroyedError, WrongPasswordError
from .protection import ProtectionMode
from .settings import VaultSettings, load_settings, save_settings, write_default_settings
from .time_verify import TimeVerificationError, format_utc, get_trusted_time
from .timelock import TimeLockError, TimeLockPolicy, check_timelock_pre_password, parse_datetime_utc


def _password(prompt: str, confirm: bool = False) -> str:
    p1 = getpass.getpass(prompt)
    if not p1:
        print("Пароль не может быть пустым.", file=sys.stderr)
        sys.exit(1)
    if confirm:
        p2 = getpass.getpass("Повторите пароль: ")
        if p1 != p2:
            print("Пароли не совпадают.", file=sys.stderr)
            sys.exit(1)
    return p1


def _load_cfg(args: argparse.Namespace) -> VaultSettings:
    if getattr(args, "settings_file", None):
        return load_settings(Path(args.settings_file))
    return load_settings()


def _resolve_protection(args: argparse.Namespace) -> ProtectionMode:
    if getattr(args, "protection", None):
        return ProtectionMode.parse(args.protection)
    after = getattr(args, "unlock_after", None)
    before = getattr(args, "unlock_before", None)
    if after or before:
        return ProtectionMode.BOTH if getattr(args, "password", None) else ProtectionMode.TIMELOCK
    return ProtectionMode.PASSWORD


def _build_timelock_from_args(args: argparse.Namespace) -> TimeLockPolicy:
    after = getattr(args, "unlock_after", None)
    before = getattr(args, "unlock_before", None)
    return TimeLockPolicy(
        enabled=bool(after or before),
        unlock_after_unix=parse_datetime_utc(after) if after else 0,
        unlock_before_unix=parse_datetime_utc(before) if before else 0,
    )


def _open_vault(
    path: Path,
    password: str | None,
    cfg: VaultSettings,
    *,
    skip_timelock_check: bool = False,
) -> VaultContainer:
    if not path.exists():
        print(
            f"Контейнер не найден: {path}. "
            "Возможно, он был уничтожен после превышения лимита неверных паролей.",
            file=sys.stderr,
        )
        sys.exit(2)

    mode = VaultContainer.read_protection_mode(path)
    pwd: str | None = password
    if mode == ProtectionMode.TIMELOCK:
        pwd = None
    elif pwd is None:
        pwd = _password("Пароль: ")

    try:
        return VaultContainer.open(path, pwd, cfg, skip_timelock_check=skip_timelock_check)
    except VaultDestroyedError as e:
        print(str(e), file=sys.stderr)
        sys.exit(2)
    except WrongPasswordError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except TimeLockError as e:
        print(str(e), file=sys.stderr)
        sys.exit(3)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


def cmd_create(args: argparse.Namespace) -> None:
    path = Path(args.container)
    cfg = _load_cfg(args)
    mode = _resolve_protection(args)
    tl = _build_timelock_from_args(args)

    password: str | None = None
    if mode in (ProtectionMode.PASSWORD, ProtectionMode.BOTH):
        password = args.password or _password("Задайте пароль контейнера: ", confirm=True)
    elif args.password:
        print("Предупреждение: для режима timelock пароль не используется.", file=sys.stderr)

    VaultContainer.create(
        path,
        cfg,
        protection=mode,
        password=password,
        timelock=tl,
    )
    print(f"Контейнер создан: {path}")
    print(f"Защита: {mode.label_ru()}")
    if cfg.max_failed_attempts > 0 and mode != ProtectionMode.TIMELOCK:
        print(
            f"  После {cfg.max_failed_attempts} неверных попыток пароля контейнер будет уничтожен."
        )
    if mode != ProtectionMode.PASSWORD:
        if tl.unlock_after_unix:
            print(f"  Открытие не раньше: {format_utc(tl.unlock_after_unix)}")
        if tl.unlock_before_unix:
            print(f"  Доступ до: {format_utc(tl.unlock_before_unix)}")
    if mode == ProtectionMode.TIMELOCK:
        print(
            "  Внимание: после наступления даты любой, у кого есть файл, сможет открыть контейнер "
            "(пароль не требуется)."
        )


def cmd_add(args: argparse.Namespace) -> None:
    vault = _open_vault(Path(args.container), args.password, _load_cfg(args))
    source = Path(args.file)
    entry = vault.add_file(source, args.name)
    print(f"Добавлено: {entry.name} ({entry.size} байт)")


def cmd_list(args: argparse.Namespace) -> None:
    vault = _open_vault(Path(args.container), args.password, _load_cfg(args))
    entries = vault.list_files()
    if not entries:
        print("(пусто)")
        return
    print(f"{'Имя':<40} {'Размер':>12}  Дата")
    print("-" * 70)
    for e in entries:
        print(f"{e.name:<40} {e.size:>12}  {e.mtime[:19]}")


def cmd_extract(args: argparse.Namespace) -> None:
    vault = _open_vault(Path(args.container), args.password, _load_cfg(args))
    out = vault.extract_file(args.name, Path(args.output))
    print(f"Извлечено: {out}")


def cmd_remove(args: argparse.Namespace) -> None:
    vault = _open_vault(Path(args.container), args.password, _load_cfg(args))
    vault.remove_file(args.name)
    print(f"Удалено из контейнера: {args.name}")


def cmd_passwd(args: argparse.Namespace) -> None:
    path = Path(args.container)
    if VaultContainer.read_protection_mode(path) == ProtectionMode.TIMELOCK:
        print("У контейнера нет пароля (режим timelock).", file=sys.stderr)
        sys.exit(1)
    vault = _open_vault(path, args.password, _load_cfg(args))
    new_pwd = args.new_password or _password("Новый пароль: ", confirm=True)
    vault.change_password(new_pwd)
    print("Пароль контейнера изменён.")


def cmd_info(args: argparse.Namespace) -> None:
    path = Path(args.container)
    cfg = _load_cfg(args)
    if not path.exists():
        print(f"Файл не найден: {path}", file=sys.stderr)
        sys.exit(1)
    hdr = VaultContainer.read_header_public(path)
    print(f"Контейнер: {path}")
    print(f"Размер на диске: {path.stat().st_size} байт")
    print(f"Защита: {hdr.protection.label_ru()}")
    if cfg.max_failed_attempts > 0 and hdr.protection != ProtectionMode.TIMELOCK:
        print(
            f"Лимит попыток пароля: {cfg.max_failed_attempts} "
            f"({'уничтожение' if cfg.destroy_on_max_attempts else 'блокировка'})"
        )
    if hdr.protection != ProtectionMode.PASSWORD:
        if hdr.timelock.unlock_after_unix:
            print(f"Открытие с: {format_utc(hdr.timelock.unlock_after_unix)}")
        if hdr.timelock.unlock_before_unix:
            print(f"Доступ до: {format_utc(hdr.timelock.unlock_before_unix)}")
    can_open = True
    if hdr.protection != ProtectionMode.PASSWORD:
        try:
            check_timelock_pre_password(hdr.timelock, get_trusted_time(cfg))
        except (TimeVerificationError, TimeLockError) as e:
            can_open = False
            print(f"Сейчас открыть нельзя: {e}")
    if can_open:
        try:
            vault = _open_vault(path, args.password, cfg)
            sec = vault.security_info()
            print(f"Версия формата: {sec['version']}")
            print(f"KDF: {sec['kdf']}")
            if sec["kdf"] == "Argon2id":
                print(f"Argon2id: time={sec['argon2_time']}, memory={sec['argon2_memory_mib']} MiB")
            print(f"Файлов внутри: {len(vault.entries)}")
            total = sum(e.size for e in vault.entries.values())
            print(f"Суммарный размер данных: {total} байт")
        except SystemExit:
            raise


def cmd_timelock(args: argparse.Namespace) -> None:
    path = Path(args.container)
    cfg = _load_cfg(args)

    if args.check_time:
        try:
            report = VaultContainer.check_time_sources(cfg)
        except TimeVerificationError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
        print(f"Проверенное UTC: {report['trusted_utc']}")
        print(f"Смещение локальных часов: {report['local_skew_seconds']:.1f} с")
        for s in report["sources"]:
            tag = " (локально)" if s["local"] else ""
            print(f"  - {s['name']}: {s['utc']}{tag}")
        return

    if args.status:
        if not path.exists():
            print(f"Контейнер не найден: {path}", file=sys.stderr)
            sys.exit(1)
        hdr = VaultContainer.read_header_public(path)
        print(f"Защита: {hdr.protection.label_ru()}")
        if hdr.protection != ProtectionMode.PASSWORD:
            if hdr.timelock.unlock_after_unix:
                print(f"  Открытие не раньше: {format_utc(hdr.timelock.unlock_after_unix)}")
            if hdr.timelock.unlock_before_unix:
                print(f"  Доступ до: {format_utc(hdr.timelock.unlock_before_unix)}")
            try:
                trusted = get_trusted_time(cfg)
                print(f"  Сейчас (сеть+сверка): {format_utc(trusted.unix)}")
            except TimeVerificationError as e:
                print(f"  Сейчас: не удалось проверить ({e})")
        return

    if args.disable:
        if VaultContainer.read_protection_mode(path) == ProtectionMode.TIMELOCK:
            print("Нельзя отключить единственную защиту по времени.", file=sys.stderr)
            sys.exit(1)
        vault = _open_vault(path, args.password, cfg, skip_timelock_check=True)
        vault.clear_timelock()
        print("Временная блокировка снята. Осталась защита паролем.")
        return

    if args.enable or args.after or args.before:
        if VaultContainer.read_protection_mode(path) == ProtectionMode.TIMELOCK:
            print("Контейнер уже защищён только временем.", file=sys.stderr)
            sys.exit(1)
        if not args.after and not args.before:
            print("Укажите --after и/или --before.", file=sys.stderr)
            sys.exit(1)
        policy = TimeLockPolicy(
            enabled=True,
            unlock_after_unix=parse_datetime_utc(args.after) if args.after else 0,
            unlock_before_unix=parse_datetime_utc(args.before) if args.before else 0,
        )
        vault = _open_vault(path, args.password, cfg)
        vault.set_timelock(policy)
        print("Добавлена защита по времени (режим: пароль + дата/время).")
        return

    print("timelock: --enable --after \"...\" | --disable | --status | --check-time")


def cmd_config(args: argparse.Namespace) -> None:
    if args.init:
        path = write_default_settings(Path(args.output) if args.output else None)
        print(f"Создан файл настроек: {path}")
        return

    cfg = _load_cfg(args)
    if args.show:
        print(json.dumps(cfg.to_dict(), ensure_ascii=False, indent=2))
        return

    if args.set:
        data = cfg.to_dict()
        key, _, value = args.set.partition("=")
        key = key.strip()
        if key not in data:
            print(f"Неизвестный параметр: {key}", file=sys.stderr)
            sys.exit(1)
        if isinstance(data[key], bool):
            data[key] = value.lower() in ("1", "true", "yes", "on", "да")
        elif isinstance(data[key], int):
            data[key] = int(value)
        elif isinstance(data[key], float):
            data[key] = float(value)
        else:
            data[key] = value
        cfg = VaultSettings.from_dict(data)
        out = save_settings(cfg, Path(args.output) if args.output else None)
        print(f"Настройки сохранены: {out}")
        return

    print("Используйте: config --init | config --show | config --set key=value")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--container", default="vault.evlt")
    common.add_argument("-p", "--password", help="Пароль (не для режима timelock)")
    common.add_argument("--settings-file", help="Путь к vault-settings.json")

    p = argparse.ArgumentParser(
        prog="vault",
        description="Зашифрованный контейнер: пароль, время или оба.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("create", parents=[common], help="Создать контейнер")
    s.add_argument(
        "--protection",
        choices=["password", "timelock", "both"],
        help="Режим: password | timelock | both (по умолчанию — password)",
    )
    s.add_argument("--unlock-after", metavar="UTC", help="Не открывать раньше (timelock / both)")
    s.add_argument("--unlock-before", metavar="UTC", help="Закрыть после (timelock / both)")
    s.set_defaults(func=cmd_create)

    s = sub.add_parser("add", parents=[common], help="Добавить файл")
    s.add_argument("file")
    s.add_argument("-n", "--name")
    s.set_defaults(func=cmd_add)

    s = sub.add_parser("list", parents=[common], aliases=["ls"], help="Список файлов")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("extract", parents=[common], help="Извлечь файл")
    s.add_argument("name")
    s.add_argument("-o", "--output", default=".")
    s.set_defaults(func=cmd_extract)

    s = sub.add_parser("remove", parents=[common], aliases=["rm"], help="Удалить файл")
    s.add_argument("name")
    s.set_defaults(func=cmd_remove)

    s = sub.add_parser("passwd", parents=[common], help="Сменить пароль")
    s.add_argument("--new-password")
    s.set_defaults(func=cmd_passwd)

    s = sub.add_parser("info", parents=[common], help="Информация")
    s.set_defaults(func=cmd_info)

    s = sub.add_parser("timelock", parents=[common], help="Управление блокировкой по времени")
    s.add_argument("--enable", action="store_true")
    s.add_argument("--disable", action="store_true")
    s.add_argument("--status", action="store_true")
    s.add_argument("--check-time", action="store_true")
    s.add_argument("--after")
    s.add_argument("--before")
    s.set_defaults(func=cmd_timelock)

    s = sub.add_parser("config", help="Настройки")
    s.add_argument("--init", action="store_true")
    s.add_argument("--show", action="store_true")
    s.add_argument("--set", metavar="KEY=VALUE")
    s.add_argument("-o", "--output")
    s.set_defaults(func=cmd_config)

    return p


def _print_quick_start() -> None:
    print("Encrypted Vault — зашифрованный контейнер для файлов\n")
    print("Запуск из папки encrypted-vault:\n")
    print('  python main.py create -c vault.evlt --protection password')
    print('  python main.py add -c vault.evlt secret.pdf')
    print('  python main.py list -c vault.evlt')
    print('  python main.py extract -c vault.evlt secret.pdf -o .')
    print("\nРежимы защиты при создании:")
    print("  --protection password   только пароль")
    print("  --protection timelock --unlock-after \"2026-12-01 00:00:00\"")
    print("  --protection both       пароль + дата/время")
    print("\nСправка по команде:")
    print("  python main.py create --help")
    print("\nИли дважды щёлкните start.bat (Windows).")


def main(argv: list[str] | None = None) -> None:
    if argv is not None and len(argv) == 0:
        _print_quick_start()
        return
    parser = build_parser()
    if argv is None and len(sys.argv) <= 1:
        _print_quick_start()
        return
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        if e.code == 2 and (argv is None or len(argv) <= 1):
            _print_quick_start()
            return
        raise
    args.func(args)


if __name__ == "__main__":
    main()
