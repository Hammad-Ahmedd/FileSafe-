# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller one-folder packaging spec for Assembly-Assisted Malware Analysis (CSC-203).

IMPORTANT: PyInstaller builds are OS-specific. This spec must be built and tested
on a Windows 10/11 x64 machine:
    pyinstaller --clean --noconfirm coalscan.spec
"""

from pathlib import Path

block_cipher = None
project_root = Path(SPECPATH)
local_site = project_root / ".site-packages"
pathex = [str(project_root)]
if local_site.exists():
    pathex.append(str(local_site))

a = Analysis(
    [str(project_root / "coalscan" / "__main__.py")],
    pathex=pathex,
    binaries=[],
    datas=[
        (str(project_root / "coalscan" / "fixtures" / "manifest.csv"), "coalscan/fixtures"),
        (str(project_root / "coalscan" / "docs"), "coalscan/docs"),
    ],
    hiddenimports=[
        "pefile",
        "capstone",
        "reportlab",
        "sqlite3",
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
        "PySide6.QtSvg",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "scipy", "sklearn", "torch"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="coalscan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch="x86_64",
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="coalscan",
)
