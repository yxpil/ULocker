"""通用小工具：体积格式化、安全擦除、路径规范化等。"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from .crypto import random_bytes
from .errors import PathSafetyError, ShredError, ULockerError

# Windows 上的保留设备名，作为条目名会被系统特殊对待，必须拒绝。
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")


def human_size(num: float) -> str:
    """把字节数格式化成人类可读的字符串。"""
    value = float(num)
    for unit in _UNITS:
        if abs(value) < 1024.0 or unit == _UNITS[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{value:.2f} {_UNITS[-1]}"


def round_up(value: int, step: int) -> int:
    """把 ``value`` 向上对齐到 ``step`` 的整数倍。"""
    if step <= 1:
        return max(0, value)
    return ((value + step - 1) // step) * step


def is_windows() -> bool:
    return sys.platform.startswith("win")


# --------------------------------------------------------------------------- #
# 条目名安全
# --------------------------------------------------------------------------- #


def safe_relative_name(name: str) -> str:
    """规范化并校验容器内的条目名。

    拒绝绝对路径、目录穿越、驱动器号、NUL 字节以及 Windows 保留设备名，
    返回以 ``/`` 分隔的安全相对路径。这是解包时的核心安全防线——一个恶意
    构造的 ``../../../../Windows/System32/x.dll`` 条目不应该能写到容器之外。
    """
    if not isinstance(name, str) or not name.strip():
        raise PathSafetyError(f"非法条目名：{name!r}")

    unified = name.replace("\\", "/").strip()
    if "\x00" in unified:
        raise PathSafetyError("条目名包含 NUL 字节")

    # 绝对路径 / 驱动器号 / UNC
    if unified.startswith("/") or unified.startswith("//"):
        raise PathSafetyError(f"拒绝绝对路径：{name!r}")
    if len(unified) >= 2 and unified[1] == ":" and unified[0].isalpha():
        raise PathSafetyError(f"拒绝带驱动器号的路径：{name!r}")

    parts: List[str] = []
    for segment in unified.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            raise PathSafetyError(f"拒绝目录穿越：{name!r}")
        if segment.endswith((" ", ".")) and is_windows():
            # Windows 会静默去掉结尾的空格和点，可能导致写入到意料之外的名字
            raise PathSafetyError(f"条目名以空格或点结尾：{name!r}")
        stem = segment.split(".")[0].upper()
        if is_windows() and stem in _WINDOWS_RESERVED:
            raise PathSafetyError(f"条目名使用了系统保留字：{name!r}")
        parts.append(segment)

    if not parts:
        raise PathSafetyError(f"非法条目名：{name!r}")
    return "/".join(parts)


def resolve_inside(base: Path, relative: str) -> Path:
    """把安全的相对名拼到 ``base`` 下，并再次确认结果没有跑出 ``base``。"""
    safe = safe_relative_name(relative)
    target = (base / safe).resolve()
    root = base.resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:  # pragma: no cover - safe_relative_name 已拦截
        raise PathSafetyError(f"目标路径越出解包目录：{relative!r}") from exc
    return target


def unique_path(path: Path) -> Path:
    """当目标已存在时，生成 ``name (2).ext`` 这样的不冲突路径。"""
    if not path.exists():
        return path
    stem, suffix, parent = path.stem, path.suffix, path.parent
    for i in range(2, 10000):
        candidate = parent / f"{stem} ({i}){suffix}"
        if not candidate.exists():
            return candidate
    raise ULockerError(f"无法为 {path.name} 生成不冲突的文件名")


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def free_space(path: Path) -> int:
    """返回 ``path`` 所在卷的剩余字节数。"""
    probe = path
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    try:
        return shutil.disk_usage(str(probe)).free
    except OSError:
        return 0


# --------------------------------------------------------------------------- #
# 安全擦除
# --------------------------------------------------------------------------- #


def shred_file(
    path: os.PathLike | str,
    passes: int = 1,
    progress: Optional[Callable[[int, int, str], None]] = None,
) -> int:
    """覆写并删除文件，返回覆写的字节数。

    .. warning::
       在 SSD / U 盘这类带磨损均衡的闪存介质上，覆写**无法保证**物理块被真正
       覆盖（闪存控制器会把写入重定向到新块）。本函数只能防御文件系统层面的
       恢复工具。真正的安全擦除需要厂商工具或全盘加密。
    """
    target = Path(path)
    if not target.exists():
        raise ShredError(f"文件不存在：{target}")
    if target.is_dir():
        raise ShredError(f"暂不支持擦除目录：{target}")

    size = target.stat().st_size
    passes = max(1, int(passes))
    block = 1 << 20
    written = 0

    try:
        with target.open("r+b", buffering=0) as fh:
            for p in range(passes):
                fh.seek(0)
                left = size
                while left > 0:
                    n = min(block, left)
                    fh.write(random_bytes(n))
                    left -= n
                    written += n
                    if progress:
                        progress(written, size * passes, f"{target.name} 第 {p + 1}/{passes} 遍")
                fh.flush()
                os.fsync(fh.fileno())
        # 改名再删，避免按原名残留目录项
        scrambled = target.with_name(f"{target.name}.{os.urandom(4).hex()}.tmp")
        try:
            os.replace(target, scrambled)
            target = scrambled
        except OSError:
            pass
        target.unlink(missing_ok=True)
    except OSError as exc:
        raise ShredError(f"擦除失败：{target}（{exc}）") from exc

    return written


# --------------------------------------------------------------------------- #
# 杂项
# --------------------------------------------------------------------------- #


def looks_like_vault(path: os.PathLike | str) -> bool:
    """通过魔数快速判断一个文件是否是 ULocker 容器。"""
    from .crypto import MAGIC

    try:
        with Path(path).open("rb") as fh:
            return fh.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def format_table(rows: Sequence[Sequence[str]], headers: Sequence[str]) -> str:
    """把二维数据渲染成等宽文本表格（中文字符按两格宽计算）。"""
    widths = [display_width(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], display_width(cell))

    def render(cells: Sequence[str]) -> str:
        padded = []
        for cell, width in zip(cells, widths):
            padded.append(cell + " " * max(0, width - display_width(cell)))
        return "  ".join(padded).rstrip()

    lines = [render(list(headers)), "  ".join("-" * w for w in widths)]
    lines.extend(render(list(row)) for row in rows)
    return "\n".join(lines)


def display_width(text: str) -> int:
    """近似计算终端显示宽度（CJK 字符算 2 格）。"""
    import unicodedata

    width = 0
    for ch in text:
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def parse_serial_filter(text: Optional[str]) -> Optional[str]:
    """规范化用户手写的卷序列号。"""
    if not text:
        return None
    cleaned = "".join(ch for ch in str(text).upper() if ch.isalnum())
    return cleaned or None
