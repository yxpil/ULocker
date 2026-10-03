"""命令行版可执行文件的入口。

PyInstaller 需要一个真实的脚本文件作为起点，直接拿 ``ulocker/__main__.py``
会因为包上下文丢失导致相对导入失败，所以这里做一个显式的薄入口。
"""

from __future__ import annotations

import sys

from ulocker.cli import main

if __name__ == "__main__":
    sys.exit(main())
