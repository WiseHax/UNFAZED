from PyInstaller.utils.hooks import collect_submodules, collect_data_files

hiddenimports = collect_submodules("scipy")
datas = collect_data_files("scipy")
