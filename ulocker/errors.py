"""ULocker 异常类型。

所有异常都继承 :class:`ULockerError`，调用方只需要捕获这一个基类即可。
"""

from __future__ import annotations


class ULockerError(Exception):
    """ULocker 所有异常的基类。"""


class FormatError(ULockerError):
    """容器文件格式不合法：魔数不匹配、版本不支持、头部被截断或损坏。"""


class WrongPasswordError(ULockerError):
    """密码错误，或容器头部 / 索引已被篡改（AEAD 校验不通过）。"""


class IntegrityError(ULockerError):
    """数据区校验失败：某个分块被篡改或损坏。"""


class DriveMismatchError(ULockerError):
    """容器已绑定到某个特定 U 盘，当前盘不是它。"""


class PathSafetyError(ULockerError):
    """条目名不安全（绝对路径、目录穿越、Windows 保留设备名等）。"""


class ShredError(ULockerError):
    """安全擦除源文件失败。"""
