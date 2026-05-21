#!/usr/bin/env python3
"""Запуск CLI зашифрованного контейнера."""

import sys
from pathlib import Path

# Чтобы работало при запуске из любой папки (двойной клик, ярлык)
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from vault.cli import main

if __name__ == "__main__":
    main()
