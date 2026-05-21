# -*- mode: python ; coding: utf-8 -*-
# pyinstaller EncryptedVault.spec

block_cipher = None

a = Analysis(
    ['run_gui.py'],
    pathex=[],
    binaries=[],
    datas=[('vault-settings.example.json', '.')],
    hiddenimports=[
        'argon2',
        'argon2.low_level',
        'cryptography',
        'cryptography.hazmat.primitives.ciphers.aead',
        'vault',
        'vault.container',
        'vault.crypto_utils',
        'vault.protection',
        'vault.settings',
        'vault.timelock',
        'vault.time_verify',
        'vault.gui_app',
        'vault.app_store',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='EncryptedVault',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
