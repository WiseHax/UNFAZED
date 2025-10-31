
a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[('extractor.dll', '.'), ('rust_core\\rust_analysis_lib\\target\\release\\rust_analysis_lib.dll', '.')],
    datas=[('m1\\m1_family_model.pkl', 'm1'), ('m1\\m1_family_vectorizer.pkl', 'm1'), ('m1\\m1_model.pkl', 'm1'), ('m1\\m1_vectorizer.pkl', 'm1')],
    hiddenimports=['sklearn', 'sklearn.base', 'sklearn.utils', 'sklearn.utils._typedefs', 'sklearn.utils.validation', 'sklearn.utils._joblib', 'sklearn.feature_extraction.text', 'sklearn.ensemble._forest', 'sklearn.tree._tree', 'sklearn.neighbors._base', 'sklearn.metrics.pairwise', 'scipy', 'scipy.sparse', 'scipy.sparse._csparsetools', 'scipy._lib._ccallback', 'scipy._cyutility', 'joblib'],
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
    name='main',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
