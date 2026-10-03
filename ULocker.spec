# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置。

一次可以产出两个单文件可执行程序：

* ``dist/ulocker.exe``  —— 命令行版（带控制台窗口）
* ``dist/ULocker.exe``  —— 图形界面版（无控制台窗口）

用环境变量 ``ULOCKER_BUILD_TARGETS`` 选择要构建哪些，取值是 ``cli`` / ``gui``
的逗号分隔列表，默认两个都构建。``scripts/build_exe.py`` 会帮你设置好。
"""

import os
from pathlib import Path

ROOT = Path(SPECPATH).resolve()

# 这些模块是运行时动态导入的，静态分析看不到，必须显式声明
HIDDEN_IMPORTS = [
    "argon2",
    "argon2.low_level",
    "_argon2_cffi_bindings",
    "cryptography",
    "cryptography.hazmat.backends.openssl",
]

# 坚决不要打进包里的东西（体积杀手）
BASE_EXCLUDES = [
    "tkinter",
    "matplotlib",
    "numpy",
    "pandas",
    "scipy",
    "PIL",
    "IPython",
    "pytest",
    "setuptools",
    "pip",
]

GUI_EXCLUDES = BASE_EXCLUDES
CLI_EXCLUDES = BASE_EXCLUDES + [
    "PyQt6",
    "PyQt5",
    "PySide2",
    "PySide6",
]

COMMON_KWARGS = dict(
    pathex=[str(ROOT)],
    hiddenimports=HIDDEN_IMPORTS,
    noarchive=False,
    optimize=1,
)


def _build(entry_name, name, excludes, console):
    analysis = Analysis(
        [str(ROOT / "scripts" / entry_name)],
        excludes=excludes,
        **COMMON_KWARGS,
    )
    return EXE(
        PYZ(analysis.pure),
        analysis.scripts,
        analysis.binaries,
        analysis.datas,
        [],
        name=name,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,          # UPX 压缩容易被杀软误报，这里主动关掉
        console=console,
        disable_windowed_traceback=not console,
    )


_targets = {
    part.strip().lower()
    for part in os.environ.get("ULOCKER_BUILD_TARGETS", "cli,gui").split(",")
    if part.strip()
}
_unknown = _targets - {"cli", "gui", ""}
if _unknown:
    raise SystemExit(
        f"ULOCKER_BUILD_TARGETS 里有无法识别的目标：{sorted(_unknown)}（只支持 cli / gui）"
    )

if "cli" in _targets:
    cli_exe = _build("_entry_cli.py", "ulocker", CLI_EXCLUDES, console=True)

if "gui" in _targets:
    gui_exe = _build("_entry_gui.py", "ULocker", GUI_EXCLUDES, console=False)

if not _targets:
    raise SystemExit("ULOCKER_BUILD_TARGETS 至少要包含 cli 或 gui")
