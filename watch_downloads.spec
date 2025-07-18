# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['watch_downloads.py'],
    pathex=[],
    binaries=[],
    datas=[('extractor.dll', '.'), ('yara64.exe', '.'), ('m1\\\\m1_model.pkl', 'm1'), ('m1\\\\m1_vectorizer.pkl', 'm1'), ('rules\\\\rules-master', 'rules\\\\rules-master')],
    hiddenimports=['sklearn', 'sklearn.ensemble._forest', 'sklearn.feature_extraction.text', 'sklearn.utils._openmp_helpers', 'sklearn.tree._tree', 'scipy', 'scipy._lib', 'scipy._lib._util', 'scipy.sparse', 'scipy.sparse._csr', 'scipy.sparse._lil', 'scipy._cython_utils', 'pystray', 'PIL.Image'],
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
    name='watch_downloads',
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
    icon=['ico.ico'],
)
