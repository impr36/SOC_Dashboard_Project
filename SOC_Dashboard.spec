# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('C:\\ME\\SOC_Dashboard-main\\app\\templates', 'app/templates'), ('C:\\ME\\SOC_Dashboard-main\\app\\static', 'app/static'), ('C:\\ME\\SOC_Dashboard-main\\app\\rules', 'app/rules'), ('C:\\ME\\SOC_Dashboard-main\\app\\engines', 'app/engines'), ('C:\\ME\\SOC_Dashboard-main\\app\\collectors', 'app/collectors'), ('C:\\ME\\SOC_Dashboard-main\\app\\services', 'app/services'), ('C:\\ME\\SOC_Dashboard-main\\app\\api', 'app/api'), ('C:\\ME\\SOC_Dashboard-main\\app\\core', 'app/core'), ('C:\\ME\\SOC_Dashboard-main\\app\\alerts', 'app/alerts'), ('C:\\ME\\SOC_Dashboard-main\\requirements.txt', '.')]
binaries = []
hiddenimports = ['uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto', 'uvicorn.protocols', 'uvicorn.protocols.http', 'uvicorn.protocols.http.auto', 'uvicorn.protocols.websockets', 'uvicorn.protocols.websockets.auto', 'uvicorn.lifespan', 'uvicorn.lifespan.on', 'fastapi', 'starlette', 'jinja2', 'aiofiles', 'pydantic', 'pandas', 'sqlite3', 'psutil', 'win32api', 'win32con', 'win32evtlog', 'wmi', 'tkinter', 'tkinter.ttk', 'tkinter.messagebox', 'app.main', 'app.api.dashboard_api', 'app.api.auth_api', 'app.api.rules_api', 'app.api.settings_api', 'app.api.investigation_api', 'app.services.soc_service', 'app.services.investigation_service', 'app.collectors.collector_manager', 'app.collectors.filesystem_collector', 'app.collectors.network_collector', 'app.database.database', 'app.websocket_manager']
tmp_ret = collect_all('jinja2')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('starlette')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('fastapi')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['C:\\ME\\SOC_Dashboard-main\\launcher.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
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
    [],
    exclude_binaries=True,
    name='SOC_Dashboard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SOC_Dashboard',
)
