@echo off
chcp 65001 >nul
title Building UNFAZED - watch_downloads.exe

echo [ * ] Cleaning previous builds...
del /f /q watch_downloads.spec >nul 2>&1
rmdir /s /q dist >nul 2>&1
rmdir /s /q build >nul 2>&1
rmdir /s /q __pycache__ >nul 2>&1

echo [ * ] Starting PyInstaller build...

python -m PyInstaller ^
--noconsole ^
--onefile ^
--icon=ico.ico ^
--add-data "extractor.dll;." ^
--add-data "yara64.exe;." ^
--add-data "m1\\m1_model.pkl;m1" ^
--add-data "m1\\m1_vectorizer.pkl;m1" ^
--add-data "rules\\rules-master;rules\\rules-master" ^
--hidden-import sklearn ^
--hidden-import sklearn.ensemble._forest ^
--hidden-import sklearn.feature_extraction.text ^
--hidden-import sklearn.utils._openmp_helpers ^
--hidden-import sklearn.tree._tree ^
--hidden-import scipy ^
--hidden-import scipy._lib ^
--hidden-import scipy._lib._util ^
--hidden-import scipy.sparse ^
--hidden-import scipy.sparse._csr ^
--hidden-import scipy.sparse._lil ^
--hidden-import scipy._cython_utils ^
--hidden-import pystray ^
--hidden-import PIL.Image ^
watch_downloads.py

if not exist dist\watch_downloads.exe (
    echo [!] Build failed. Exiting...
    pause
    exit /b
)

echo.
echo [ ✔ ] Build complete! Your EXE is in the /dist folder.

echo [ * ] Launching UNFAZED Watcher in background...
start "" dist\watch_downloads.exe

echo [ * ] Build + launch complete.
pause
