"""Графический интерфейс: встроенный контейнер и пароль входа."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path
from tkinter import END, BooleanVar, StringVar, Tk, Toplevel, filedialog, messagebox, ttk

from .app_store import (
    clear_login_password,
    data_dir,
    load_app_config,
    mark_vault_initialized,
    save_app_config,
    set_login_password,
    settings_path,
    vault_path,
    verify_login_password,
)
from .container import VaultContainer
from .protection import ProtectionMode
from .settings import VaultSettings, load_settings, save_settings
from .timelock import TimeLockPolicy


class PasswordDialog(Toplevel):
    def __init__(
        self,
        parent: Tk,
        *,
        title: str = "Пароль",
        confirm: bool = False,
        hint: str = "",
        allow_empty: bool = False,
    ) -> None:
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.result: str | None = None
        self._allow_empty = allow_empty
        self.transient(parent)
        self.grab_set()

        frm = ttk.Frame(self, padding=12)
        frm.grid(sticky="nsew")
        if hint:
            ttk.Label(frm, text=hint, wraplength=380).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

        ttk.Label(frm, text="Пароль:").grid(row=1, column=0, sticky="w")
        self._pwd = ttk.Entry(frm, width=32, show="•")
        self._pwd.grid(row=1, column=1, sticky="ew", padx=(8, 0))
        self._pwd.focus_set()

        row = 2
        self._pwd2: ttk.Entry | None = None
        if confirm:
            ttk.Label(frm, text="Повтор:").grid(row=2, column=0, sticky="w", pady=(8, 0))
            self._pwd2 = ttk.Entry(frm, width=32, show="•")
            self._pwd2.grid(row=2, column=1, sticky="ew", padx=(8, 0), pady=(8, 0))
            row = 3

        btns = ttk.Frame(frm)
        btns.grid(row=row, column=0, columnspan=2, pady=(12, 0))
        ttk.Button(btns, text="OK", command=self._ok).pack(side="left", padx=4)
        ttk.Button(btns, text="Отмена", command=self._cancel).pack(side="left", padx=4)

        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    def _ok(self) -> None:
        p1 = self._pwd.get()
        if not p1 and not self._allow_empty:
            messagebox.showwarning("Пароль", "Введите пароль.", parent=self)
            return
        if self._pwd2 is not None and p1 != self._pwd2.get():
            messagebox.showwarning("Пароль", "Пароли не совпадают.", parent=self)
            return
        self.result = p1
        self.grab_release()
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.grab_release()
        self.destroy()


def _ask_password(
    parent: Tk,
    *,
    title: str = "Пароль",
    confirm: bool = False,
    hint: str = "",
    allow_empty: bool = False,
) -> str | None:
    dlg = PasswordDialog(parent, title=title, confirm=confirm, hint=hint, allow_empty=allow_empty)
    parent.wait_window(dlg)
    return dlg.result


def _log_error(text: str) -> None:
    try:
        (data_dir() / "vault-error.log").write_text(text, encoding="utf-8")
    except OSError:
        pass


def run_first_setup() -> str | None:
    """Первый запуск: пароль входа (опционально) и создание встроенного контейнера."""
    win = Tk()
    win.title("Encrypted Vault — настройка")
    win.resizable(False, False)
    win.geometry("460x320")

    use_login = BooleanVar(value=True)
    use_vault_pwd = BooleanVar(value=True)
    done = {"session": None, "cancelled": True}

    frm = ttk.Frame(win, padding=16)
    frm.pack(fill="both", expand=True)

    ttk.Label(
        frm,
        text="Первый запуск\n\nХранилище создаётся внутри программы.\n"
        f"Папка данных:\n{data_dir()}",
        justify="center",
    ).pack(pady=(0, 12))

    ttk.Checkbutton(frm, text="Пароль для входа в программу", variable=use_login).pack(anchor="w")
    ttk.Checkbutton(frm, text="Пароль встроенного хранилища", variable=use_vault_pwd).pack(anchor="w", pady=4)

    def on_create() -> None:
        login_pwd: str | None = None
        vault_pwd: str | None = None
        if use_login.get():
            login_pwd = _ask_password(
                win,
                title="Пароль входа",
                confirm=True,
                hint="Пароль при каждом запуске.",
            )
            if login_pwd is None:
                return
        if use_vault_pwd.get():
            vault_pwd = _ask_password(
                win,
                title="Пароль хранилища",
                confirm=True,
                hint="Пароль для файлов внутри программы.",
            )
            if vault_pwd is None:
                return
        elif use_login.get():
            vault_pwd = login_pwd

        if login_pwd:
            set_login_password(login_pwd)
        else:
            clear_login_password()

        try:
            VaultContainer.create(
                vault_path(),
                load_settings(settings_path()),
                protection=ProtectionMode.PASSWORD,
                password=vault_pwd or "",
            )
            mark_vault_initialized(uses_password=bool(vault_pwd))
        except Exception as e:
            messagebox.showerror("Ошибка", str(e), parent=win)
            return

        done["session"] = login_pwd or vault_pwd or ""
        done["cancelled"] = False
        win.quit()

    def on_exit() -> None:
        win.quit()

    ttk.Button(frm, text="Создать хранилище", command=on_create).pack(pady=(16, 0))
    ttk.Button(frm, text="Выход", command=on_exit).pack(pady=6)

    win.protocol("WM_DELETE_WINDOW", on_exit)
    win.lift()
    win.attributes("-topmost", True)
    win.after(200, lambda: win.attributes("-topmost", False))
    win.mainloop()
    win.destroy()

    if done["cancelled"]:
        return None
    return done["session"]


def run_login() -> str | None:
    """Вход в программу. Без пароля — только если пароль не настроен."""
    app_cfg = load_app_config()
    if not app_cfg.login_required:
        return ""

    win = Tk()
    win.title("Encrypted Vault — вход")
    win.resizable(False, False)
    win.geometry("400x200")

    result: dict = {"pwd": None, "cancelled": True}
    frm = ttk.Frame(win, padding=16)
    frm.pack(fill="both", expand=True)
    ttk.Label(frm, text="Введите пароль входа в программу", font=("", 11)).pack(pady=(0, 8))
    pwd_entry = ttk.Entry(frm, width=30, show="•")
    pwd_entry.pack(pady=4)
    pwd_entry.focus_set()
    err_lbl = ttk.Label(frm, text="", foreground="red")
    err_lbl.pack()

    def submit() -> None:
        pwd = pwd_entry.get()
        if not verify_login_password(pwd):
            err_lbl.config(text="Неверный пароль")
            pwd_entry.delete(0, END)
            return
        result["pwd"] = pwd
        result["cancelled"] = False
        win.quit()

    def cancel() -> None:
        win.quit()

    ttk.Button(frm, text="Войти", command=submit).pack(pady=(12, 4))
    ttk.Button(frm, text="Выход", command=cancel).pack()
    win.bind("<Return>", lambda _e: submit())
    win.protocol("WM_DELETE_WINDOW", cancel)
    win.lift()
    win.attributes("-topmost", True)
    win.after(200, lambda: win.attributes("-topmost", False))
    win.mainloop()
    win.destroy()

    if result["cancelled"]:
        return None
    return result["pwd"] or ""


class SettingsDialog(Toplevel):
    """Окно настроек программы."""

    def __init__(self, parent: VaultGuiApp) -> None:
        super().__init__(parent.root)
        self.app = parent
        self.title("Настройки")
        self.geometry("520x480")
        self.resizable(False, False)
        self.transient(parent.root)
        self.grab_set()

        self.cfg = VaultSettings.from_dict(parent.cfg.to_dict())
        self._vars: dict[str, StringVar | BooleanVar] = {}

        nb = ttk.Notebook(self, padding=8)
        nb.pack(fill="both", expand=True)

        nb.add(self._tab_passwords(), text="Пароли")
        nb.add(self._tab_security(), text="Защита")
        nb.add(self._tab_timelock(), text="Время")
        nb.add(self._tab_system(), text="Система")

        btns = ttk.Frame(self, padding=8)
        btns.pack(fill="x")
        ttk.Button(btns, text="Сохранить", command=self._save).pack(side="right", padx=4)
        ttk.Button(btns, text="Отмена", command=self.destroy).pack(side="right")
        ttk.Button(btns, text="По умолчанию", command=self._reset_defaults).pack(side="left")

    def _tab_passwords(self) -> ttk.Frame:
        frm = ttk.Frame(self, padding=12)
        ttk.Label(
            frm,
            text="Пароли хранятся внутри программы (зашифрованный хэш и контейнер).",
            wraplength=460,
        ).pack(anchor="w", pady=(0, 12))

        login_on = BooleanVar(value=self.app.app_cfg.login_required)
        self._vars["login_required"] = login_on
        ttk.Checkbutton(frm, text="Требовать пароль при запуске программы", variable=login_on).pack(
            anchor="w"
        )
        ttk.Button(frm, text="Сменить пароль входа…", command=self._change_login).pack(anchor="w", pady=8)
        ttk.Button(frm, text="Сменить пароль хранилища…", command=self.app._change_vault_password).pack(
            anchor="w"
        )
        return frm

    def _tab_security(self) -> ttk.Frame:
        frm = ttk.Frame(self, padding=12)
        self._field(frm, 0, "Лимит неверных паролей (0 = выкл.)", "max_failed_attempts", "5")
        destroy = BooleanVar(value=self.cfg.destroy_on_max_attempts)
        self._vars["destroy_on_max_attempts"] = destroy
        ttk.Checkbutton(
            frm, text="Уничтожить контейнер при превышении лимита", variable=destroy
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=8)

        ttk.Separator(frm, orient="horizontal").grid(row=2, column=0, columnspan=2, sticky="ew", pady=8)
        self._field(frm, 3, "Задержка после ошибки (сек)", "min_delay_seconds", "3")
        self._field(frm, 4, "Множитель задержки", "delay_multiplier", "2")
        self._field(frm, 5, "Макс. задержка (сек)", "max_delay_seconds", "180")

        ttk.Separator(frm, orient="horizontal").grid(row=6, column=0, columnspan=2, sticky="ew", pady=8)
        self._field(frm, 7, "Argon2: итерации", "argon2_time_cost", "4")
        self._field(frm, 8, "Argon2: память (KiB)", "argon2_memory_kib", "262144")
        self._field(frm, 9, "Argon2: потоки", "argon2_parallelism", "4")
        frm.columnconfigure(1, weight=1)
        return frm

    def _tab_timelock(self) -> ttk.Frame:
        frm = ttk.Frame(self, padding=12)
        ttk.Label(frm, text="Проверка времени (для блокировки по дате)", font=("", 10, "bold")).pack(
            anchor="w"
        )
        net = BooleanVar(value=self.cfg.time_lock_require_network)
        local = BooleanVar(value=self.cfg.time_lock_require_local_match)
        offline = BooleanVar(value=self.cfg.time_lock_allow_offline)
        self._vars["time_lock_require_network"] = net
        self._vars["time_lock_require_local_match"] = local
        self._vars["time_lock_allow_offline"] = offline

        ttk.Checkbutton(frm, text="Требовать время из интернета", variable=net).pack(anchor="w", pady=(8, 0))
        ttk.Checkbutton(frm, text="Сверять с часами компьютера", variable=local).pack(anchor="w")
        ttk.Checkbutton(frm, text="Разрешить работу без интернета", variable=offline).pack(anchor="w", pady=(0, 8))

        inner = ttk.Frame(frm)
        inner.pack(fill="x")
        self._field(inner, 0, "Мин. серверов времени", "time_lock_min_network_sources", "3")
        self._field(inner, 1, "Допуск серверов (сек)", "time_lock_network_agreement_seconds", "120")
        self._field(inner, 2, "Допуск локальных часов (сек)", "time_lock_max_local_skew_seconds", "300")
        return frm

    def _tab_system(self) -> ttk.Frame:
        frm = ttk.Frame(self, padding=12)
        ttk.Label(frm, text=f"Папка данных:\n{data_dir()}", wraplength=460).pack(anchor="w")
        ttk.Label(frm, text=f"Настройки: {settings_path()}", wraplength=460).pack(anchor="w", pady=8)
        ttk.Button(frm, text="Открыть папку данных", command=self._open_data_dir).pack(anchor="w", pady=4)
        ttk.Button(frm, text="О хранилище", command=self.app._show_info).pack(anchor="w", pady=4)
        return frm

    def _field(self, parent: ttk.Frame, row: int, label: str, key: str, default: str) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4)
        var = StringVar(value=str(getattr(self.cfg, key, default)))
        self._vars[key] = var
        ttk.Entry(parent, textvariable=var, width=18).grid(row=row, column=1, sticky="e", pady=4)

    def _change_login(self) -> None:
        if self._vars["login_required"].get():
            p = _ask_password(self, confirm=True, hint="Новый пароль входа.")
            if p:
                set_login_password(p)
                self.app.session_password = p
                self.app.app_cfg = load_app_config()
        else:
            clear_login_password()
            self.app.app_cfg = load_app_config()
            messagebox.showinfo("Пароли", "Пароль входа отключён.", parent=self)

    def _open_data_dir(self) -> None:
        path = str(data_dir())
        try:
            os.startfile(path)
        except AttributeError:
            subprocess.run(["xdg-open", path], check=False)

    def _reset_defaults(self) -> None:
        self.cfg = VaultSettings(max_failed_attempts=5, destroy_on_max_attempts=True)
        self.destroy()
        SettingsDialog(self.app)

    def _save(self) -> None:
        try:
            new_cfg = VaultSettings(
                max_failed_attempts=int(self._vars["max_failed_attempts"].get()),
                destroy_on_max_attempts=bool(self._vars["destroy_on_max_attempts"].get()),
                min_delay_seconds=float(self._vars["min_delay_seconds"].get()),
                delay_multiplier=float(self._vars["delay_multiplier"].get()),
                max_delay_seconds=float(self._vars["max_delay_seconds"].get()),
                argon2_time_cost=int(self._vars["argon2_time_cost"].get()),
                argon2_memory_kib=int(self._vars["argon2_memory_kib"].get()),
                argon2_parallelism=int(self._vars["argon2_parallelism"].get()),
                time_lock_require_network=bool(self._vars["time_lock_require_network"].get()),
                time_lock_require_local_match=bool(self._vars["time_lock_require_local_match"].get()),
                time_lock_allow_offline=bool(self._vars["time_lock_allow_offline"].get()),
                time_lock_min_network_sources=int(self._vars["time_lock_min_network_sources"].get()),
                time_lock_network_agreement_seconds=float(
                    self._vars["time_lock_network_agreement_seconds"].get()
                ),
                time_lock_max_local_skew_seconds=float(
                    self._vars["time_lock_max_local_skew_seconds"].get()
                ),
            )
        except ValueError:
            messagebox.showerror("Настройки", "Проверьте числа в полях.", parent=self)
            return

        save_settings(new_cfg, settings_path())
        self.app.cfg = new_cfg

        want_login = bool(self._vars["login_required"].get())
        if want_login and not load_app_config().login_required:
            p = _ask_password(self, confirm=True, hint="Задайте пароль входа в программу.")
            if p:
                set_login_password(p)
                self.app.session_password = p
            else:
                messagebox.showwarning(
                    "Настройки",
                    "Пароль входа не задан — опция будет отключена.",
                    parent=self,
                )
                clear_login_password()
        elif not want_login:
            clear_login_password()

        self.app.app_cfg = load_app_config()
        self.app._refresh_header()
        messagebox.showinfo("Настройки", "Сохранено.", parent=self)
        self.destroy()


class VaultGuiApp:
    def __init__(self, session_password: str) -> None:
        self.session_password = session_password
        self.root = Tk()
        self.root.title("Encrypted Vault")
        self.root.minsize(720, 480)
        self.root.geometry("900x520")

        self.cfg = load_settings(settings_path())
        self.app_cfg = load_app_config()
        self.vault: VaultContainer | None = None
        self._busy = False
        self._internal_vault = vault_path()

        self.status_text = StringVar(value="Загрузка…")
        self._login_status = StringVar()

        self._build_ui()
        self._refresh_header()
        self.root.after(100, self._auto_open_vault)

    def _build_ui(self) -> None:
        top = ttk.LabelFrame(self.root, text="Встроенное хранилище (внутри программы)", padding=10)
        top.pack(fill="x", padx=10, pady=10)
        self._header = top

        ttk.Label(top, text="Данные программы:").grid(row=0, column=0, sticky="w")
        self._path_lbl = ttk.Label(top, text=str(data_dir()), wraplength=620)
        self._path_lbl.grid(row=0, column=1, sticky="w", padx=8)

        ttk.Label(top, text="Пароль входа:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self._login_lbl = ttk.Label(top, textvariable=self._login_status)
        self._login_lbl.grid(row=1, column=1, sticky="w", padx=8, pady=(6, 0))
        top.columnconfigure(1, weight=1)

        mid = ttk.Frame(self.root, padding=(10, 0))
        mid.pack(fill="both", expand=True)

        cols = ("name", "size", "mtime")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=14)
        self.tree.heading("name", text="Имя файла")
        self.tree.heading("size", text="Размер")
        self.tree.heading("mtime", text="Дата")
        self.tree.column("name", width=360)
        self.tree.column("size", width=100, anchor="e")
        self.tree.column("mtime", width=180)
        scroll = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        actions = ttk.Frame(self.root, padding=10)
        actions.pack(fill="x")
        ttk.Button(actions, text="Добавить файл…", command=self._add_file).pack(side="left", padx=2)
        ttk.Button(actions, text="Извлечь…", command=self._extract_file).pack(side="left", padx=2)
        ttk.Button(actions, text="Удалить", command=self._remove_file).pack(side="left", padx=2)
        ttk.Button(actions, text="Обновить", command=self._refresh_list).pack(side="left", padx=2)
        ttk.Button(actions, text="Настройки", command=self._open_settings).pack(side="right", padx=4)
        ttk.Button(actions, text="О хранилище", command=self._show_info).pack(side="right", padx=2)

        bar = ttk.Frame(self.root, padding=(10, 6))
        bar.pack(fill="x")
        ttk.Label(bar, textvariable=self.status_text).pack(side="left")

    def _vault_password(self) -> str | None:
        if self.app_cfg.vault_uses_password:
            return self.session_password if self.session_password else None
        return None

    def _auto_open_vault(self) -> None:
        if not self._internal_vault.is_file():
            messagebox.showerror(
                "Хранилище",
                "Встроенный контейнер не найден. Удалите папку data и запустите снова.",
                parent=self.root,
            )
            self.root.destroy()
            return

        pwd = self._vault_password()
        if pwd is None and self.app_cfg.vault_uses_password:
            pwd = _ask_password(self.root, hint="Пароль встроенного хранилища.")
            if pwd is None:
                self.root.destroy()
                return

        def work() -> None:
            self.vault = VaultContainer.open(self._internal_vault, pwd or "", self.cfg)

        self._run_async("Открытие хранилища", work)

    def _run_async(self, title: str, work) -> None:
        if self._busy:
            return
        self._busy = True
        self.status_text.set(f"{title}…")
        self.root.config(cursor="watch")

        def runner() -> None:
            err: str | None = None
            try:
                work()
            except Exception as e:
                err = f"{e}\n\n{traceback.format_exc()}"
            self.root.after(0, lambda: self._async_done(title, err))

        threading.Thread(target=runner, daemon=True).start()

    def _async_done(self, title: str, err: str | None) -> None:
        self._busy = False
        self.root.config(cursor="")
        if err:
            _log_error(err)
            messagebox.showerror(title, err.split("\n\n")[0], parent=self.root)
            self.status_text.set("Ошибка")
        elif self.vault:
            self.status_text.set(f"Файлов: {len(self.vault.entries)}")
            self._refresh_list()

    def _require_vault(self) -> VaultContainer | None:
        if self.vault is None:
            messagebox.showinfo("Хранилище", "Подождите, идёт открытие…", parent=self.root)
            return None
        return self.vault

    def _refresh_list(self) -> None:
        self.tree.delete(*self.tree.get_children())
        if not self.vault:
            return
        for e in self.vault.list_files():
            self.tree.insert(
                "",
                END,
                values=(e.name, f"{e.size:,}", e.mtime[:19].replace("T", " ")),
            )

    def _add_file(self) -> None:
        vault = self._require_vault()
        if not vault:
            return
        paths = filedialog.askopenfilenames(title="Добавить в хранилище")
        if not paths:
            return

        def work() -> None:
            for p in paths:
                vault.add_file(Path(p))

        self._run_async("Добавление", work)

    def _extract_file(self) -> None:
        vault = self._require_vault()
        if not vault:
            return
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Извлечь", "Выберите файл.", parent=self.root)
            return
        name = self.tree.item(sel[0])["values"][0]
        dest = filedialog.askdirectory(title="Куда сохранить")
        if not dest:
            return

        def work() -> None:
            out = vault.extract_file(name, Path(dest))
            self.root.after(0, lambda: messagebox.showinfo("Готово", f"Сохранено:\n{out}", parent=self.root))

        self._run_async("Извлечение", work)

    def _remove_file(self) -> None:
        vault = self._require_vault()
        if not vault:
            return
        sel = self.tree.selection()
        if not sel:
            return
        name = self.tree.item(sel[0])["values"][0]
        if not messagebox.askyesno("Удалить", f"Удалить «{name}»?", parent=self.root):
            return

        def work() -> None:
            vault.remove_file(name)

        self._run_async("Удаление", work)

    def _change_vault_password(self) -> None:
        vault = self._require_vault()
        if not vault:
            return
        new_pwd = _ask_password(self.root, confirm=True, hint="Новый пароль встроенного хранилища.")
        if new_pwd is None:
            return

        def work() -> None:
            vault.change_password(new_pwd)
            self.session_password = new_pwd
            self.root.after(0, lambda: messagebox.showinfo("Пароль", "Пароль хранилища изменён.", parent=self.root))

        self._run_async("Смена пароля", work)

    def _refresh_header(self) -> None:
        self.app_cfg = load_app_config()
        if self.app_cfg.login_required:
            self._login_status.set("включён")
        else:
            self._login_status.set("отключён (вход без пароля)")

    def _open_settings(self) -> None:
        SettingsDialog(self)

    def _show_info(self) -> None:
        path = self._internal_vault
        if not path.is_file():
            return
        hdr = VaultContainer.read_header_public(path)
        lines = [
            "Встроенное хранилище",
            f"Путь: {path}",
            f"Размер: {path.stat().st_size:,} байт",
            f"Защита: {hdr.protection.label_ru()}",
            f"Пароль входа в программу: {'да' if self.app_cfg.login_required else 'нет'}",
        ]
        if self.vault:
            lines.append(f"Файлов: {len(self.vault.entries)}")
        messagebox.showinfo("О хранилище", "\n".join(lines), parent=self.root)

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    try:
        data_dir()
        app_cfg = load_app_config()

        if not app_cfg.vault_initialized or not vault_path().is_file():
            session_pwd = run_first_setup()
        else:
            session_pwd = run_login()

        if session_pwd is None:
            return

        VaultGuiApp(session_password=session_pwd).run()
    except Exception:
        err = traceback.format_exc()
        _log_error(err)
        try:
            r = Tk()
            r.withdraw()
            messagebox.showerror(
                "Encrypted Vault",
                f"Ошибка запуска:\n{err[:800]}\n\nПодробности: {data_dir() / 'vault-error.log'}",
            )
            r.destroy()
        except Exception:
            pass
        raise
