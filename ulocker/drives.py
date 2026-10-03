"""U 盘（可移动卷）识别。

Windows 下直接通过 ctypes 调用 ``kernel32``，**不依赖 pywin32 / psutil**；
macOS 用 ``diskutil``，Linux 用 ``lsblk``，都失败时退回扫描常见挂载点。

绑定 U 盘的判据是**卷序列号**（volume serial number）：它是格式化时生成的
32 位值，比盘符稳定、比卷标唯一。注意它会在重新格式化后改变。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .util import human_size, is_windows, parse_serial_filter

VAULT_EXT = ".ulocker"

KIND_REMOVABLE = "removable"
KIND_FIXED = "fixed"
KIND_NETWORK = "network"
KIND_OPTICAL = "optical"
KIND_RAMDISK = "ramdisk"
KIND_UNKNOWN = "unknown"

_KIND_TEXT = {
    KIND_REMOVABLE: "可移动磁盘",
    KIND_FIXED: "本地磁盘",
    KIND_NETWORK: "网络驱动器",
    KIND_OPTICAL: "光驱",
    KIND_RAMDISK: "内存盘",
    KIND_UNKNOWN: "未知",
}


@dataclass
class DriveInfo:
    """一个卷的静态信息快照。"""

    root: str
    label: str = ""
    serial: str = ""
    filesystem: str = ""
    kind: str = KIND_UNKNOWN
    total: int = 0
    free: int = 0

    # ------------------------------------------------------------------ #
    @property
    def is_removable(self) -> bool:
        return self.kind == KIND_REMOVABLE

    @property
    def kind_text(self) -> str:
        return _KIND_TEXT.get(self.kind, self.kind)

    @property
    def bind_id(self) -> str:
        """绑定用的标识：优先卷序列号，没有则退回卷标。"""
        return normalise_serial(self.serial) or (self.label or "").strip().upper()

    @property
    def has_serial(self) -> bool:
        return bool(normalise_serial(self.serial))

    def describe(self) -> str:
        bits = [f"{self.root}", self.kind_text]
        if self.label:
            bits.append(self.label)
        if self.serial:
            bits.append(f"SN:{normalise_serial(self.serial)}")
        if self.filesystem:
            bits.append(self.filesystem)
        if self.total:
            bits.append(f"{human_size(self.total)} 可用 {human_size(self.free)}")
        return " · ".join(b for b in bits if b)

    def to_json(self) -> Dict[str, Any]:
        data = asdict(self)
        data["bind_id"] = self.bind_id
        return data


def normalise_serial(value: Optional[str]) -> str:
    """把卷序列号规范成 ``8 位大写十六进制``（不足则保持原样）。"""
    if not value:
        return ""
    cleaned = re.sub(r"[^0-9A-Za-z]", "", str(value)).upper()
    if not cleaned:
        return ""
    if re.fullmatch(r"[0-9A-F]{1,8}", cleaned):
        return cleaned.zfill(8)
    return cleaned


# --------------------------------------------------------------------------- #
# Windows 实现
# --------------------------------------------------------------------------- #


def _list_windows() -> List[DriveInfo]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    get_drive_type = kernel32.GetDriveTypeW
    get_drive_type.argtypes = [wintypes.LPCWSTR]
    get_drive_type.restype = wintypes.UINT

    get_volume_info = kernel32.GetVolumeInformationW
    get_volume_info.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    get_volume_info.restype = wintypes.BOOL

    get_free = kernel32.GetDiskFreeSpaceExW
    get_free.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ulonglong),
    ]
    get_free.restype = wintypes.BOOL

    get_strings = kernel32.GetLogicalDriveStringsW
    get_strings.argtypes = [wintypes.DWORD, wintypes.LPWSTR]
    get_strings.restype = wintypes.DWORD

    buf = ctypes.create_unicode_buffer(512)
    length = get_strings(len(buf), buf)
    if not length:
        return []
    roots = [item for item in buf[:length].split("\x00") if item]

    kind_map = {
        2: KIND_REMOVABLE,
        3: KIND_FIXED,
        4: KIND_NETWORK,
        5: KIND_OPTICAL,
        6: KIND_RAMDISK,
    }

    drives: List[DriveInfo] = []
    for root in roots:
        info = DriveInfo(root=root, kind=kind_map.get(get_drive_type(root), KIND_UNKNOWN))

        label = ctypes.create_unicode_buffer(261)
        fsname = ctypes.create_unicode_buffer(261)
        serial = wintypes.DWORD(0)
        max_component = wintypes.DWORD(0)
        fs_flags = wintypes.DWORD(0)
        ok = get_volume_info(
            root,
            label,
            261,
            ctypes.byref(serial),
            ctypes.byref(max_component),
            ctypes.byref(fs_flags),
            fsname,
            261,
        )
        if ok:
            info.label = label.value
            info.filesystem = fsname.value
            info.serial = f"{serial.value:08X}"

        free_user = ctypes.c_ulonglong(0)
        total = ctypes.c_ulonglong(0)
        total_free = ctypes.c_ulonglong(0)
        if get_free(root, ctypes.byref(free_user), ctypes.byref(total), ctypes.byref(total_free)):
            info.total = int(total.value)
            info.free = int(total_free.value)

        drives.append(info)

    return drives


# --------------------------------------------------------------------------- #
# POSIX 实现
# --------------------------------------------------------------------------- #


def _run(cmd: List[str]) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def _list_linux() -> List[DriveInfo]:
    raw = _run(
        [
            "lsblk",
            "-J",
            "-o",
            "NAME,LABEL,SERIAL,MOUNTPOINT,FSTYPE,SIZE,RM,TRAN,TYPE",
        ]
    )
    drives: List[DriveInfo] = []
    if raw:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {}

        for node in payload.get("blockdevices", []):
            drives.extend(_walk_lsblk(node))

    if drives:
        return drives
    return _scan_mountpoints()


def _walk_lsblk(node: Dict[str, Any]) -> List[DriveInfo]:
    out: List[DriveInfo] = []
    mount = node.get("mountpoint")
    if mount:
        removable = bool(node.get("rm"))
        transport = (node.get("tran") or "").lower()
        if removable or transport == "usb":
            kind = KIND_REMOVABLE
        elif transport in ("", None):
            kind = KIND_FIXED
        else:
            kind = KIND_FIXED
        info = DriveInfo(
            root=mount,
            label=(node.get("label") or "").strip(),
            serial=(node.get("serial") or "").strip(),
            filesystem=(node.get("fstype") or "").strip(),
            kind=kind,
        )
        usage = shutil.disk_usage(mount) if os.path.exists(mount) else None
        if usage:
            info.total, info.free = usage.total, usage.free
        out.append(info)

    for child in node.get("children") or []:
        out.extend(_walk_lsblk(child))
    return out


def _list_macos() -> List[DriveInfo]:
    raw = _run(["diskutil", "list", "-plist", "external", "physical"])
    names: List[str] = re.findall(r"<string>(disk\d+)</string>", raw)
    drives: List[DriveInfo] = []
    seen: set[str] = set()

    for name in dict.fromkeys(names):
        plist = _run(["diskutil", "info", "-plist", name])
        if not plist:
            continue
        mount = re.search(r"<key>MountPoint</key>\s*<string>(.*?)</string>", plist)
        label = re.search(r"<key>VolumeName</key>\s*<string>(.*?)</string>", plist)
        serial = re.search(r"<key>IOPlatformUUID</key>\s*<string>(.*?)</string>", plist)
        fsname = re.search(r"<key>FilesystemType</key>\s*<string>(.*?)</string>", plist)
        if not mount:
            continue
        root = mount.group(1)
        if root in seen:
            continue
        seen.add(root)
        info = DriveInfo(
            root=root,
            label=(label.group(1) if label else "").strip(),
            serial=normalise_serial(serial.group(1).replace("-", "")[-8:]) if serial else "",
            filesystem=(fsname.group(1) if fsname else "").strip(),
            kind=KIND_REMOVABLE,
        )
        usage = shutil.disk_usage(root) if os.path.exists(root) else None
        if usage:
            info.total, info.free = usage.total, usage.free
        drives.append(info)
    return drives


def _scan_mountpoints() -> List[DriveInfo]:
    """兜底：扫描 /Volumes、/media、/run/media、/mnt 下的可访问目录。"""
    bases = [Path("/Volumes"), Path("/media"), Path("/run/media"), Path("/mnt")]
    drives: List[DriveInfo] = []
    seen: set[str] = set()
    for base in bases:
        if not base.is_dir():
            continue
        try:
            children = sorted(base.iterdir())
        except OSError:
            continue
        for child in children:
            candidates = [child]
            if child.is_dir() and not child.is_symlink():
                try:
                    candidates.extend(sorted(g for g in child.iterdir() if g.is_dir()))
                except OSError:
                    pass
            for cand in candidates:
                key = str(cand)
                if key in seen or not os.access(key, os.R_OK):
                    continue
                seen.add(key)
                info = DriveInfo(root=key, label=cand.name, kind=KIND_REMOVABLE)
                usage = shutil.disk_usage(key)
                info.total, info.free = usage.total, usage.free
                drives.append(info)
    return drives


# --------------------------------------------------------------------------- #
# 对外接口
# --------------------------------------------------------------------------- #


def list_drives(include_fixed: bool = True) -> List[DriveInfo]:
    """列出当前系统上的卷。

    :param include_fixed: 是否把本地硬盘也列出来（默认列出，便于查看容器位置）。
    """
    if is_windows():
        drives = _list_windows()
    elif sys.platform == "darwin":
        drives = _list_macos()
    elif sys.platform.startswith("linux"):
        drives = _list_linux()
    else:  # pragma: no cover - 其它平台
        drives = _scan_mountpoints()

    if not include_fixed:
        drives = [d for d in drives if d.is_removable]
    drives.sort(key=lambda d: (not d.is_removable, d.root))
    return drives


def list_removable_drives() -> List[DriveInfo]:
    """只列出可移动磁盘（U 盘 / 移动硬盘）。"""
    return [d for d in list_drives(include_fixed=True) if d.is_removable]


def get_drive_info(root: os.PathLike | str) -> Optional[DriveInfo]:
    """按挂载点查找卷信息。"""
    target = str(root)
    want = os.path.abspath(target).rstrip("\\/")
    for drive in list_drives(include_fixed=True):
        cur = os.path.abspath(drive.root).rstrip("\\/")
        if cur.lower() == want.lower():
            return drive
    # 退一步：去掉盘符中的冒号再比一次（"E:" vs "E:\\"）
    for drive in list_drives(include_fixed=True):
        if os.path.abspath(drive.root).rstrip("\\/").rstrip(":").lower() == want.rstrip(":").lower():
            return drive
    return None


def drive_of(path: os.PathLike | str) -> Optional[DriveInfo]:
    """判断某个文件/目录位于哪个卷上，并把该卷的信息返回。"""
    drive, _ = os.path.splitdrive(os.path.abspath(str(path)))
    if drive:
        if not drive.endswith("\\"):
            drive += "\\"
        info = get_drive_info(drive)
        if info:
            return info
        return DriveInfo(root=drive, kind=KIND_UNKNOWN)
    return get_drive_info("/")


def mount_root(path: os.PathLike | str) -> Path:
    """返回 ``path`` 所在卷的根目录（用于在 U 盘里找容器）。"""
    drive, _ = os.path.splitdrive(os.path.abspath(str(path)))
    if drive:
        root = drive + os.sep
        return Path(root)
    p = Path(path).resolve()
    for base in (Path("/Volumes"), Path("/media"), Path("/run/media"), Path("/mnt")):
        try:
            rel = p.relative_to(base)
        except ValueError:
            continue
        if rel.parts:
            return base / rel.parts[0]
        return base
    return p.anchor and Path(p.anchor) or p


def find_vaults(
    where: os.PathLike | str,
    *,
    max_depth: int = 2,
    recursive: bool = True,
) -> List[Path]:
    """在给定位置（通常是某个 U 盘）里找出所有 ``.ulocker`` 容器。"""
    base = Path(where)
    found: List[Path] = []
    if base.is_file():
        return [base] if base.name.lower().endswith(VAULT_EXT) else []

    if not recursive:
        try:
            candidates = sorted(base.glob(f"*{VAULT_EXT}"))
        except OSError:
            candidates = []
        return [p for p in candidates if p.is_file()]

    base_depth = len(base.parts)
    for root, dirs, files in os.walk(base, onerror=lambda _e: None):
        # 跳过明显的系统/回收站目录，避免无谓的遍历
        dirs[:] = [
            d
            for d in dirs
            if not d.startswith(".")
            and d.lower() not in {"$recycle.bin", "system volume information", "node_modules"}
        ]
        if len(Path(root).parts) - base_depth >= max_depth:
            dirs[:] = []
        for name in files:
            if name.lower().endswith(VAULT_EXT):
                found.append(Path(root) / name)
    return sorted(found)


def match_drive(bound: Optional[Dict[str, Any]], current: Optional[DriveInfo]) -> bool:
    """判断当前卷是否就是容器绑定的那个。"""
    if not bound:
        return True
    want = parse_serial_filter(bound.get("serial")) or normalise_serial(bound.get("serial"))
    if not want:
        # 没有序列号可比，退回比卷标
        want_label = (bound.get("label") or "").strip().upper()
        if not want_label or current is None:
            return True
        return (current.label or "").strip().upper() == want_label
    if current is None:
        return False
    return normalise_serial(current.serial) == want
