#!/usr/bin/env python3
"""Точка входа GUI (и сборка в exe)."""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from vault.gui_app import main

if __name__ == "__main__":
    main()
