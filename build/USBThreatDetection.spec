# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification file for USB Threat Detection."""

block_cipher = None

a = Analysis(
    ['../src/ThreatDetectionSoftware.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('../config/default_config.yaml', 'config'),
        ('../README.md', '.'),
    ],
    hiddenimports=[
        'win32timezone',
        'win32com.client',
        'wmi',
        'pyusb',
        'usb.core',
        'usb.util',
        'psutil',
        'yaml',
        'src.feed_integration',
        'src.database',
        'src.database.models',
        'src.monitors',
        'src.monitors.windows_monitor',
        'src.monitors.linux_monitor',
        'src.detectors',
        'src.detectors.signature_detector',
        'src.detectors.heuristic_detector',
        'src.detectors.threat_engine',
        'src.gui',
        'src.gui.main_window',
        'src.config',
        'PyQt5.QtCore',
        'PyQt5.QtWidgets',
        'PyQt5.QtGui',
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
    [],
    exclude_binaries=True,
    name='USBThreatDetection',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,  # Set to True to show console window
    disable_windowed_traceback=False,
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
    upx=True,
    upx_exclude=[],
    name='USBThreatDetection',
)
