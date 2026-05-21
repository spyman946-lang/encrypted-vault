"""Проверка вшивания контейнера (имитация exe без PyInstaller)."""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

# Имитируем собранное приложение
sys.frozen = True  # type: ignore[attr-defined]
sys.executable = str(_ROOT / "out" / "test_fake.exe")

from vault.container import VaultContainer
from vault.exe_embed import has_embedded_vault, read_embedded_vault_bytes
from vault.settings import VaultSettings

exe = Path(sys.executable)
exe.parent.mkdir(parents=True, exist_ok=True)
exe.write_bytes(b"MZ" + b"\x00" * 200)

cfg = VaultSettings(max_failed_attempts=0)
c = VaultContainer.create(exe, cfg, password="test")
c.add_file(_ROOT / "vault-settings.example.json", "sample.json")
assert has_embedded_vault(exe), "overlay missing"
c2 = VaultContainer.open(exe, "test")
assert "sample.json" in c2.entries
assert read_embedded_vault_bytes(exe)[:4] == b"EVLT"
print("embed test OK")
