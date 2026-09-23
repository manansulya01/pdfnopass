# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build for the Universal PDF Password Recovery Utility.

Produces a self-contained directory (``dist/pdf-recovery/`` containing the
``pdf-recovery`` executable, ``dist/pdf-recovery.exe`` on Windows) that runs
without Python installed.

Build (from the project root)::

    pip install pyinstaller
    pyinstaller pdf-recovery.spec

Result: ``dist/pdf-recovery/pdf-recovery`` (or ``dist/pdf-recovery.exe``
inside ``dist/pdf-recovery/`` on Windows). Only application code plus the
pypdf/tqdm dependencies are bundled; no test fixtures, docs, or
checkpoints are included.

For a single-file executable instead, run::

    pyinstaller --onefile --name pdf-recovery pdf_recovery/__main__.py
"""

block_cipher = None

a = Analysis(
    ["pdf_recovery/__main__.py"],
    pathex=["."],
    binaries=[],
    datas=[],
    hiddenimports=["pypdf", "tqdm"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "unittest", "pydoc", "doctest",
               # Image/data-science stacks are never needed: recovery only
               # uses pypdf's decrypt/page-count path, never image extraction.
               "numpy", "PIL", "matplotlib", "pandas", "scipy", "IPython"],
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
    name="pdf-recovery",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # reproducible builds; UPX optional and platform-dependent
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # CLI tool: keep the console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
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
    name="pdf-recovery",
)
