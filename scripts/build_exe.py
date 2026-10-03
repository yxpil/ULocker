#!/usr/bin/env python
"""把 ULocker 打包成单文件可执行程序。

用法::

    python scripts/build_exe.py                # 命令行版 + 图形界面版
    python scripts/build_exe.py --cli-only     # 只要命令行版（体积小很多）
    python scripts/build_exe.py --gui-only     # 只要图形界面版
    python scripts/build_exe.py --no-clean     # 保留上次的构建缓存（快，但可能有残留）

产物在 ``dist/`` 下。构建配置在仓库根目录的 ``ULocker.spec``。
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "ULocker.spec"
DIST = ROOT / "dist"


def check_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        sys.exit(
            "缺少 PyInstaller，请先安装：\n"
            "    pip install pyinstaller\n"
            "（想打包图形界面版还需要 PyQt6：pip install PyQt6）"
        )


def has_pyqt() -> bool:
    try:
        import PyQt6  # noqa: F401
    except ImportError:
        return False
    return True


def report() -> int:
    if not DIST.is_dir():
        print("dist/ 里没有东西，构建可能失败了。")
        return 1

    outputs = sorted(p for p in DIST.iterdir() if p.is_file())
    if not outputs:
        print("dist/ 里没有产出任何文件（PyInstaller 报错了吗？）")
        return 1

    print("\n构建产物：")
    for path in outputs:
        print(f"  {path.name:<18} {path.stat().st_size / 1024 / 1024:6.1f} MB   {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="把 ULocker 打包成单文件可执行程序",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--cli-only", action="store_true", help="只构建命令行版")
    group.add_argument("--gui-only", action="store_true", help="只构建图形界面版")
    parser.add_argument("--no-clean", action="store_true", help="不传 --clean，复用构建缓存")
    parser.add_argument("--keep-build", action="store_true", help="构建后不删 build/ 目录")
    args = parser.parse_args(argv)

    check_pyinstaller()

    if args.cli_only:
        targets = "cli"
    elif args.gui_only:
        targets = "gui"
    else:
        targets = "cli,gui"

    if "gui" in targets and not has_pyqt():
        print("! 没有检测到 PyQt6，图形界面版会被跳过。")
        print("  需要的话先执行：pip install PyQt6")
        if targets == "gui":
            return 2
        targets = "cli"

    if not SPEC.is_file():
        print(f"找不到打包配置：{SPEC}", file=sys.stderr)
        return 2

    env = dict(os.environ)
    env["ULOCKER_BUILD_TARGETS"] = targets
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")

    command = [sys.executable, "-m", "PyInstaller", "--noconfirm"]
    if not args.no_clean:
        command.append("--clean")
    command.append(str(SPEC))

    print(f"构建目标：{targets}")
    print("执行：" + " ".join(command) + "\n")
    result = subprocess.run(command, cwd=str(ROOT), env=env, check=False)
    if result.returncode != 0:
        print(f"\nPyInstaller 退出码 {result.returncode}，构建失败。", file=sys.stderr)
        return result.returncode

    if not args.keep_build:
        shutil.rmtree(ROOT / "build", ignore_errors=True)

    return report()


if __name__ == "__main__":
    raise SystemExit(main())
