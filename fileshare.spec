# -*- mode: python ; coding: utf-8 -*-

import os
import sys

block_cipher = None

# 获取当前目录
src_dir = os.getcwd()
dist_dir = os.path.join(src_dir, 'dist')
build_dir = os.path.join(src_dir, 'build')

# 确保输出目录存在
os.makedirs(dist_dir, exist_ok=True)
os.makedirs(build_dir, exist_ok=True)

# 只需要打包无法自动生成的文件
datas = [
    # 静态文件目录
    (os.path.join(src_dir, 'static'), 'static'),
    # 模板文件目录
    (os.path.join(src_dir, 'templates'), 'templates'),
]

# 收集的所有hidden imports
hiddenimports = [
    'flask',
    'werkzeug',
    'json',
    'os',
    'sys',
    'datetime',
    'base64',
    'hashlib',
    'rsa',
    'zipfile',
    'shutil',
    'uuid',
    'random',
    'string',
    'psutil',
    'netifaces',
    'requests',
    'urllib3',
    'certifi',
    'charset_normalizer',
    'idna',
    'jinja2',
    'markupsafe',
    'click',
    'itsdangerous',
    'blinker',
    'python_dotenv',
    'email',
    'html',
    'http',
    'collections',
    'functools',
    'importlib',
    'inspect',
    'io',
    'itertools',
    'logging',
    're',
    'socket',
    'struct',
    'tempfile',
    'threading',
    'time',
    'traceback',
    'types',
    'unicodedata',
    'urllib',
    'xml',
    'xml.etree',
    'getopt',
    'pathlib',
]

# 主程序分析
a = Analysis(
    ['server.py'],
    pathex=[src_dir],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# 创建压缩包
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# ========== 模式1: 单文件模式 ==========
single_file_exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    exclude_binaries=False,
    name='文件共享平台v2.0-单文件',
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
    icon=None
)

# ========== 模式2: 目录模式 ==========
dir_exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name='文件共享平台v2.0',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None
)

# 目录模式 - COLLECT
coll = COLLECT(
    dir_exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='文件共享平台v2.0-目录模式',
)

# 打印构建信息
print("=" * 50)
print("PyInstaller 构建配置完成")
print("=" * 50)
print(f"源代码目录: {src_dir}")
print(f"输出目录: {dist_dir}")
print(f"构建目录: {build_dir}")
print("=" * 50)
print("只打包无法自动生成的文件:")
print("  - server.py (主程序)")
print("  - static/ (静态文件)")
print("  - templates/ (HTML模板)")
print("=" * 50)
print("可用构建模式:")
print("  1. 单文件模式 (--onefile): 文件共享平台v2.0-单文件.exe")
print("  2. 目录模式 (--onedir): 文件共享平台v2.0-目录模式/")
print("=" * 50)
