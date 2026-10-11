# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['_entry.py'],
    pathex=['C:/Users/j4gu4/Documents/jaguarRat/build_jaguar'],
    binaries=[],
    datas=[],
    hiddenimports=['PIL', 'PIL.Image', 'PIL.ImageGrab', 'cv2', 'winreg'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='factura',
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
)
