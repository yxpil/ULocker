"""``.ulocker`` 容器格式的读写实现。

容器物理布局::

    +--------------------------------------------------------------+
    | 0                                                          0 |
    | 魔数 "ULOCKERV"            8B                                |
    | 格式版本                    1B                                |
    | KDF 编号                    1B                                |
    | 标志位                      2B   bit0=绑定U盘  bit1=索引压缩   |
    | KDF 参数长度                2B                                |
    | KDF 参数（JSON，含盐）      L B                               |
    | 数据区起始偏移              8B   ← 头部预留区大小              |
    | 索引 nonce                 12B                               |
    | 索引密文长度                4B                                |
    | 索引密文                    M B   AES-256-GCM                 |
    | 零填充                      至 数据区起始偏移                 |
    +--------------------------------------------------------------+
    | 数据区分块记录（每块一条）                                    |
    |   [nonce 12B][密文长度 4B][AES-256-GCM 密文]                  |
    +--------------------------------------------------------------+

头部里从第 0 字节到索引密文之前的全部内容都会作为 AEAD 的附加认证数据
（AAD），所以魔数、版本、KDF 参数、预留偏移全部被密码学保护，改一个字节
就会导致解不出来。

数据区采用「逐块独立 nonce + 文件级 chunk_id 作为 AAD」的方案：
每块的 AAD 是 ``chunk_id || 块序号``，因此攻击者既不能把某块挪到别的文件，
也不能调换同一文件内块的顺序。
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
import time
import zlib
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import crypto as C
from .crypto import (
    CHUNK_SIZE,
    FLAG_DRIVE_BOUND,
    FLAG_ZLIB,
    GCM_TAG_LEN,
    NONCE_LEN,
    RECORD_HEADER_LEN,
)
from .drives import (
    DriveInfo,
    VAULT_EXT,
    drive_of,
    match_drive,
    normalise_serial,
)
from .errors import (
    DriveMismatchError,
    FormatError,
    IntegrityError,
    ShredError,
    ULockerError,
    WrongPasswordError,
)
from .util import (
    ensure_parent,
    free_space,
    human_size,
    is_windows,
    resolve_inside,
    round_up,
    safe_relative_name,
    shred_file,
    unique_path,
)

ProgressFn = Callable[[int, int, str], None]

#: 头部预留区至少留这么多余量，方便后续原地追加条目而不用搬动数据区。
MIN_RESERVE_SLACK = 64 * 1024
#: 预留区按 4 KiB 对齐。
RESERVE_ALIGN = 4096
#: 预留区估算最多重试几次。
RESERVE_ATTEMPTS = 4

_HEADER_FIXED = struct.Struct(">8sBBHH")  # magic, version, kdf_id, flags, kdf_len
_U64 = struct.Struct(">Q")
_U32 = struct.Struct(">I")
_REC_LEN = struct.Struct(">I")

_INDEX_FORMAT = 1


# --------------------------------------------------------------------------- #
# 内部异常
# --------------------------------------------------------------------------- #


class _ReserveTooSmall(ULockerError):
    """预估的头部预留区不够用，需要放大后重试（内部使用）。"""


class _Cancelled(ULockerError):
    """用户中途取消。"""


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #


@dataclass
class Entry:
    """容器中的一个条目（文件或目录）。"""

    name: str  # 容器内相对路径，POSIX 分隔
    size: int  # 明文大小
    offset: int  # 首块记录相对数据区起点的字节偏移
    chunk_id: str  # 该文件独有的 16 字节标识（十六进制），作为分块 AAD
    sha256: str  # 明文 SHA-256
    mtime: float = 0.0
    mode: int = 0o644
    is_dir: bool = False

    def to_json(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "size": self.size,
            "offset": self.offset,
            "chunk": self.chunk_id,
            "sha256": self.sha256,
            "mtime": self.mtime,
            "mode": self.mode,
            "dir": self.is_dir,
        }

    @classmethod
    def from_json(cls, raw: Dict[str, Any]) -> "Entry":
        try:
            return cls(
                name=str(raw["name"]),
                size=int(raw["size"]),
                offset=int(raw["offset"]),
                chunk_id=str(raw["chunk"]),
                sha256=str(raw["sha256"]),
                mtime=float(raw.get("mtime") or 0.0),
                mode=int(raw.get("mode") or 0o644),
                is_dir=bool(raw.get("dir")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise FormatError(f"索引条目损坏：{raw!r}") from exc


@dataclass
class VaultInfo:
    """容器的公共元信息（不含任何密钥）。"""

    path: Optional[str]
    name: str
    created: str
    updated: str
    kdf_id: int
    kdf_name: str
    kdf_params: Dict[str, Any]
    drive_bound: bool
    bound_drive: Optional[Dict[str, Any]]
    entry_count: int
    total_size: int
    encrypted_size: int
    header_size: int
    chunk_size: int
    warnings: List[str] = field(default_factory=list)

    def to_json(self) -> Dict[str, Any]:
        data = asdict(self)
        data["kdf_params"] = {
            k: v for k, v in self.kdf_params.items() if k != "salt"
        } | {"salt": "<已省略>"}
        return data

    def describe(self) -> str:
        lines = [
            f"容器名称   : {self.name}",
            f"容器路径   : {self.path or '(未保存)'}",
            f"密钥派生   : {self.kdf_name}",
            f"条目数量   : {self.entry_count}",
            f"明文总量   : {human_size(self.total_size)}",
            f"加密文件   : {human_size(self.encrypted_size)}",
            f"分块大小   : {human_size(self.chunk_size)}",
            f"创建时间   : {self.created}",
            f"最近更新   : {self.updated}",
        ]
        if self.bound_drive:
            drive = self.bound_drive
            label = drive.get("label") or "(无卷标)"
            lines.append(
                f"U 盘绑定   : 已绑定 {label} / SN:{normalise_serial(drive.get('serial'))}"
            )
        else:
            lines.append("U 盘绑定   : 未绑定（任意设备均可打开）")
        for warn in self.warnings:
            lines.append(f"提示       : {warn}")
        return "\n".join(lines)


@dataclass
class VerifyReport:
    """完整性校验结果。"""

    entries: int = 0
    bytes: int = 0
    failed: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failed


@dataclass
class SourceFile:
    """待加密的源文件。"""

    path: Path
    name: str
    size: int
    mtime: float
    mode: int


class _Progress:
    """把可选的进度回调包一层，避免到处写 ``if progress``。"""

    __slots__ = ("_fn",)

    def __init__(self, fn: Optional[ProgressFn]) -> None:
        self._fn = fn

    def __call__(self, done: int, total: int, label: str) -> None:
        if self._fn is None:
            return
        try:
            self._fn(int(done), int(total), str(label))
        except Exception:  # pragma: no cover - 进度回调不应影响主流程
            pass


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _require_password(password: str) -> Optional[str]:
    """校验口令并返回一条提示（若有）。"""
    if not isinstance(password, str) or not password:
        raise ULockerError("口令不能为空")
    if len(password) < C.PASSWORD_MIN_LEN:
        return f"口令长度不足 {C.PASSWORD_MIN_LEN} 位，建议使用更长的口令"
    return None


# --------------------------------------------------------------------------- #
# 头部读写
# --------------------------------------------------------------------------- #


@dataclass
class _Header:
    version: int
    kdf_id: int
    flags: int
    kdf_params: Dict[str, Any]
    data_offset: int
    idx_nonce: bytes
    idx_len: int
    aad: bytes
    ct: bytes

    @property
    def size(self) -> int:
        return len(self.aad) + len(self.ct)

    @property
    def drive_bound(self) -> bool:
        return bool(self.flags & FLAG_DRIVE_BOUND)


def _serialise_index(index: Dict[str, Any], compress: bool) -> Tuple[bytes, int]:
    raw = _json_bytes(index)
    if compress:
        packed = zlib.compress(raw, 6)
        if len(packed) < len(raw):
            return packed, FLAG_ZLIB
    return raw, 0


def _build_header(
    data_offset: int,
    kdf_id: int,
    kdf_params: Dict[str, Any],
    index_key: bytes,
    index: Dict[str, Any],
    extra_flags: int = 0,
    compress: bool = True,
) -> bytes:
    """组装完整头部（含索引密文）。"""
    params_bytes = _json_bytes(kdf_params)
    plain, zflag = _serialise_index(index, compress)
    flags = zflag | extra_flags

    fixed = _HEADER_FIXED.pack(
        C.MAGIC, C.FORMAT_VERSION, kdf_id, flags, len(params_bytes)
    )
    nonce = C.random_bytes(NONCE_LEN)
    ct_len = len(plain) + GCM_TAG_LEN
    tail = _U32.pack(ct_len)
    aad = fixed + params_bytes + _U64.pack(data_offset) + nonce + tail
    ct = C.aead_encrypt(index_key, nonce, plain, aad)
    assert len(ct) == ct_len, "GCM 密文长度异常"
    return aad + ct


def _read_header(fh) -> _Header:
    fh.seek(0)
    fixed = fh.read(_HEADER_FIXED.size)
    if len(fixed) < _HEADER_FIXED.size:
        raise FormatError("文件太小，不是有效的 ULocker 容器")
    magic, version, kdf_id, flags, kdf_len = _HEADER_FIXED.unpack(fixed)
    if magic != C.MAGIC:
        raise FormatError("魔数不匹配，这不是一个 ULocker 容器文件")
    if version != C.FORMAT_VERSION:
        raise FormatError(f"不支持的容器版本：{version}（本程序支持 {C.FORMAT_VERSION}）")

    params_bytes = fh.read(kdf_len)
    if len(params_bytes) != kdf_len:
        raise FormatError("头部被截断：KDF 参数不完整")
    try:
        kdf_params = json.loads(params_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormatError("头部被截断：KDF 参数已损坏") from exc
    if not isinstance(kdf_params, dict):
        raise FormatError("头部被截断：KDF 参数格式错误")

    packed = fh.read(_U64.size)
    if len(packed) != _U64.size:
        raise FormatError("头部被截断：缺少数据区偏移")
    (data_offset,) = _U64.unpack(packed)

    nonce = fh.read(NONCE_LEN)
    tail = fh.read(_U32.size)
    if len(nonce) != NONCE_LEN or len(tail) != _U32.size:
        raise FormatError("头部被截断：索引信息不完整")
    (idx_len,) = _U32.unpack(tail)
    if idx_len <= GCM_TAG_LEN or idx_len > (1 << 30):
        raise FormatError(f"头部异常：索引长度不合法（{idx_len}）")

    ct = fh.read(idx_len)
    if len(ct) != idx_len:
        raise FormatError("头部被截断：索引密文不完整")

    aad = fixed + params_bytes + packed + nonce + tail
    header = _Header(
        version=version,
        kdf_id=kdf_id,
        flags=flags,
        kdf_params=kdf_params,
        data_offset=data_offset,
        idx_nonce=nonce,
        idx_len=idx_len,
        aad=aad,
        ct=ct,
    )
    if header.data_offset < header.size:
        raise FormatError("头部异常：数据区偏移落在头部之内")
    return header


def _decrypt_index(header: _Header, index_key: bytes) -> Dict[str, Any]:
    plain = C.aead_decrypt(
        index_key,
        header.idx_nonce,
        header.ct,
        header.aad,
        err=WrongPasswordError,
        msg="口令错误，或容器头部已被篡改",
    )
    if header.flags & FLAG_ZLIB:
        try:
            plain = zlib.decompress(plain)
        except zlib.error as exc:
            raise FormatError("索引解压失败，容器可能已损坏") from exc
    try:
        index = json.loads(plain.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormatError("索引解析失败，容器可能已损坏") from exc
    if not isinstance(index, dict) or index.get("ulocker") != _INDEX_FORMAT:
        raise FormatError("索引格式不受支持")
    return index


# --------------------------------------------------------------------------- #
# 分块读写
# --------------------------------------------------------------------------- #


def _write_chunk(fh, data_key: bytes, chunk_id: bytes, seq: int, plain: bytes) -> None:
    nonce = C.random_bytes(NONCE_LEN)
    aad = chunk_id + _U64.pack(seq)
    ct = C.aead_encrypt(data_key, nonce, plain, aad)
    fh.write(nonce)
    fh.write(_REC_LEN.pack(len(ct)))
    fh.write(ct)


def _read_chunk(
    fh,
    data_key: bytes,
    chunk_id: bytes,
    seq: int,
    entry_name: str,
    chunk_size: int,
) -> bytes:
    head = fh.read(RECORD_HEADER_LEN)
    if len(head) != RECORD_HEADER_LEN:
        raise IntegrityError(f"数据区被截断：{entry_name} 第 {seq} 块缺失")
    nonce = head[:NONCE_LEN]
    (length,) = _REC_LEN.unpack(head[NONCE_LEN:])
    if length <= GCM_TAG_LEN or length > chunk_size + GCM_TAG_LEN:
        raise IntegrityError(f"分块长度异常：{entry_name} 第 {seq} 块（{length} 字节）")
    ct = fh.read(length)
    if len(ct) != length:
        raise IntegrityError(f"数据区被截断：{entry_name} 第 {seq} 块不完整")
    aad = chunk_id + _U64.pack(seq)
    return C.aead_decrypt(
        data_key,
        nonce,
        ct,
        aad,
        err=IntegrityError,
        msg=f"数据校验失败：{entry_name} 第 {seq} 块已被篡改或损坏",
    )


def _iter_records(fh, data_offset: int, entry: Entry, chunk_size: int):
    """按块遍历某个条目的原始记录，产出 ``(nonce, 密文字节)``，不解密。"""
    fh.seek(data_offset + entry.offset)
    remaining = entry.size
    while remaining > 0:
        head = fh.read(RECORD_HEADER_LEN)
        if len(head) != RECORD_HEADER_LEN:
            raise IntegrityError(f"数据区被截断：{entry.name}")
        nonce = head[:NONCE_LEN]
        (length,) = _REC_LEN.unpack(head[NONCE_LEN:])
        if length <= GCM_TAG_LEN or length > chunk_size + GCM_TAG_LEN:
            raise IntegrityError(f"分块长度异常：{entry.name}")
        payload = fh.read(length)
        if len(payload) != length:
            raise IntegrityError(f"数据区被截断：{entry.name}")
        remaining -= length - GCM_TAG_LEN
        yield nonce, payload


def _entry_wire_size(fh, data_offset: int, entry: Entry, chunk_size: int) -> int:
    """条目在数据区占用的总字节数（含记录头）。"""
    total = 0
    for nonce, payload in _iter_records(fh, data_offset, entry, chunk_size):
        total += len(nonce) + _REC_LEN.size + len(payload)
    return total


# --------------------------------------------------------------------------- #
# 源文件收集
# --------------------------------------------------------------------------- #


def _collect_sources(
    sources: Sequence[os.PathLike | str],
    *,
    follow_symlinks: bool = False,
) -> List[SourceFile]:
    """把用户给的路径展开成待加密文件清单（目录会被递归展开）。"""
    collected: List[SourceFile] = []

    for raw in sources:
        path = Path(raw).expanduser()
        if path.is_dir():
            base_name = path.name or path.drive.rstrip(":\\/") or "root"
            for root, dirs, files in os.walk(path, followlinks=follow_symlinks):
                if not follow_symlinks:
                    dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
                dirs.sort()
                for filename in sorted(files):
                    full = Path(root) / filename
                    if not follow_symlinks and full.is_symlink():
                        continue
                    rel = (Path(base_name) / full.relative_to(path)).as_posix()
                    collected.append(_make_source(full, rel))
        elif path.is_file():
            collected.append(_make_source(path, path.name))
        else:
            raise ULockerError(f"路径不存在：{path}")

    seen: Dict[str, Path] = {}
    for item in collected:
        key = item.name.lower() if is_windows() else item.name
        if key in seen:
            raise ULockerError(
                f"存在重名条目：{item.name}（来自 {seen[key]} 与 {item.path}）"
            )
        seen[key] = item.path

    collected.sort(key=lambda s: s.name)
    return collected


def _make_source(path: Path, name: str) -> SourceFile:
    safe = safe_relative_name(name)
    try:
        info = path.stat()
    except OSError as exc:
        raise ULockerError(f"无法读取源文件：{path}（{exc}）") from exc
    return SourceFile(
        path=path,
        name=safe,
        size=info.st_size,
        mtime=info.st_mtime,
        mode=stat.S_IMODE(info.st_mode),
    )


def _cipher_overhead(files: Sequence[SourceFile], chunk_size: int) -> int:
    """加密后数据区的额外开销（每块 16B 记录头 + 16B GCM 标签）。"""
    total = 0
    for item in files:
        chunks = (item.size + chunk_size - 1) // chunk_size if item.size else 0
        total += chunks * (RECORD_HEADER_LEN + GCM_TAG_LEN)
    return total


# --------------------------------------------------------------------------- #
# 索引构造
# --------------------------------------------------------------------------- #


def _make_index(
    name: str,
    created: str,
    updated: str,
    chunk_size: int,
    data_key: bytes,
    drive: Optional[Dict[str, Any]],
    entries: Sequence[Entry],
    kdf_id: int = C.DEFAULT_KDF_ID,
    weak_password: bool = False,
) -> Dict[str, Any]:
    return {
        "ulocker": _INDEX_FORMAT,
        "name": name,
        "created": created,
        "updated": updated,
        "chunk_size": int(chunk_size),
        "kdf": {"id": int(kdf_id), "name": C.KDF_NAMES.get(kdf_id, str(kdf_id))},
        "data_key": C.b64e(data_key),
        # 口令强度只是个提醒标记，不含任何密钥信息
        "weak_password": bool(weak_password),
        "drive": drive,
        "entries": [e.to_json() for e in entries],
    }


def _index_entries(index: Dict[str, Any]) -> List[Entry]:
    raw = index.get("entries")
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise FormatError("索引条目格式错误")
    return [Entry.from_json(item) for item in raw]


def _index_data_key(index: Dict[str, Any]) -> bytes:
    raw = index.get("data_key")
    if not isinstance(raw, str):
        raise FormatError("索引中缺少数据密钥")
    key = C.b64d(raw)
    if len(key) != C.KEY_LEN:
        raise FormatError("索引中的数据密钥长度不正确")
    return key


def _index_chunk_size(index: Dict[str, Any]) -> int:
    value = index.get("chunk_size") or CHUNK_SIZE
    try:
        value = int(value)
    except (TypeError, ValueError) as exc:
        raise FormatError("索引中的分块大小不合法") from exc
    if value < 512 or value > (64 << 20):
        raise FormatError(f"索引中的分块大小超出合理范围：{value}")
    return value


def _plan_reservation(skeleton: Dict[str, Any], kdf_params: Dict[str, Any]) -> int:
    """根据索引骨架估算头部预留区大小（含压缩后的真实长度）。"""
    index_size, _flag = _serialise_index(skeleton, True)
    fixed = (
        _HEADER_FIXED.size
        + len(_json_bytes(kdf_params))
        + _U64.size
        + NONCE_LEN
        + _U32.size
    )
    header_len = fixed + len(index_size)
    slack = max(MIN_RESERVE_SLACK, header_len)
    return round_up(header_len + slack, RESERVE_ALIGN)


def _drive_record(info: DriveInfo) -> Dict[str, Any]:
    return {
        "serial": normalise_serial(info.serial),
        "label": info.label,
        "filesystem": info.filesystem,
        "kind": info.kind,
        "root": info.root,
    }


def _normalise_binding(
    bind_drive: Any,
    target: Path,
) -> Optional[Dict[str, Any]]:
    """把 ``bind_drive`` 的各种写法统一成索引里的 dict（或 None）。"""
    if bind_drive is None or bind_drive is False:
        return None
    if bind_drive is True:
        info = drive_of(target)
        if info is None:
            raise ULockerError("无法识别目标所在磁盘，无法完成 U 盘绑定")
        if not info.has_serial:
            raise ULockerError(
                f"磁盘 {info.root} 没有可用的卷序列号，无法绑定；"
                "可以改用 --bind-serial 手动指定"
            )
        return _drive_record(info)
    if isinstance(bind_drive, DriveInfo):
        return _drive_record(bind_drive)
    if isinstance(bind_drive, dict):
        return dict(bind_drive)
    if isinstance(bind_drive, (str, os.PathLike)):
        text = str(bind_drive)
        info = drive_of(text) if os.path.exists(text) else None
        if info is None:
            info = _find_info_by_serial_or_root(text)
        if info is not None:
            return _drive_record(info)
        return {"serial": normalise_serial(text), "label": "", "filesystem": "", "kind": "", "root": ""}
    raise ULockerError(f"无法理解的绑定目标：{bind_drive!r}")


def _find_info_by_serial_or_root(text: str) -> Optional[DriveInfo]:
    from .drives import list_drives

    want_serial = normalise_serial(text)
    want_root = text.rstrip("\\/").upper()
    for info in list_drives(include_fixed=True):
        if want_serial and normalise_serial(info.serial) == want_serial:
            return info
        if info.root.rstrip("\\/").upper() == want_root:
            return info
    return None


# --------------------------------------------------------------------------- #
# 数据区写入
# --------------------------------------------------------------------------- #


def _store_file(
    fh,
    base: int,
    data_key: bytes,
    source: SourceFile,
    chunk_size: int,
    progress: _Progress,
    done: int,
    total: int,
) -> Tuple[Entry, int]:
    chunk_id = C.random_bytes(16)
    offset = fh.tell() - base
    digest = hashlib.sha256()
    seq = 0

    with source.path.open("rb") as src:
        while True:
            buf = src.read(chunk_size)
            if not buf:
                break
            digest.update(buf)
            _write_chunk(fh, data_key, chunk_id, seq, buf)
            seq += 1
            done += len(buf)
            progress(done, total, source.name)

    entry = Entry(
        name=source.name,
        size=source.size,
        offset=offset,
        chunk_id=chunk_id.hex(),
        sha256=digest.hexdigest(),
        mtime=source.mtime,
        mode=source.mode,
    )
    return entry, done


def _store_files(
    fh,
    base: int,
    data_key: bytes,
    sources: Sequence[SourceFile],
    chunk_size: int,
    progress: _Progress,
    total: int,
    done: int = 0,
) -> Tuple[List[Entry], int]:
    # 新建时文件是空的，追加时文件已有内容：两种情况都从数据区末尾接着写。
    fh.seek(0, os.SEEK_END)
    if fh.tell() < base:
        fh.seek(base)
    entries: List[Entry] = []
    for source in sources:
        entry, done = _store_file(
            fh, base, data_key, source, chunk_size, progress, done, total
        )
        entries.append(entry)
    return entries, done


# --------------------------------------------------------------------------- #
# 创建容器
# --------------------------------------------------------------------------- #


def create_vault(
    path: os.PathLike | str,
    password: str,
    sources: Sequence[os.PathLike | str] = (),
    *,
    kdf_id: Optional[int] = None,
    kdf_overrides: Optional[Dict[str, Any]] = None,
    vault_name: Optional[str] = None,
    bind_drive: Any = None,
    progress: Optional[ProgressFn] = None,
    overwrite: bool = False,
    shred_source: bool = False,
    shred_passes: int = 1,
    follow_symlinks: bool = False,
    chunk_size: int = CHUNK_SIZE,
) -> VaultInfo:
    """创建一个新的 :file:`.ulocker` 容器。

    :param sources: 要加密的文件/目录（目录会被递归展开）。可以为空。
    :param bind_drive: ``None`` 不绑定；``True`` 绑定到 ``path`` 所在磁盘；
        也可以直接传 :class:`~ulocker.drives.DriveInfo`、卷序列号字符串。
    :param shred_source: 加密完成后是否安全擦除源文件（默认保留）。
    """
    warnings: List[str] = []
    target = Path(path).expanduser()
    if target.suffix.lower() != VAULT_EXT:
        target = target.with_name(target.name + VAULT_EXT)
    if target.is_dir():
        raise ULockerError(f"目标是一个目录：{target}")
    if target.exists() and not overwrite:
        raise ULockerError(f"目标已存在：{target}（如需覆盖请显式允许）")

    warn = _require_password(password)
    weak_password = warn is not None
    if warn:
        warnings.append(warn)

    progress_cb = _Progress(progress)
    sources_list = _collect_sources(sources, follow_symlinks=follow_symlinks)
    total = sum(item.size for item in sources_list)

    if chunk_size < 512 or chunk_size > (64 << 20):
        raise ULockerError("分块大小必须在 512 B 到 64 MiB 之间")

    kdf_id = kdf_id or C.pick_default_kdf()
    if kdf_id == C.KDF_ARGON2ID and not C.has_argon2():
        warnings.append("当前环境缺少 argon2-cffi，已自动改用 scrypt 派生密钥")
        kdf_id = C.KDF_SCRYPT

    kdf_params = C.new_kdf_params(kdf_id, kdf_overrides)
    kek = C.derive_kek(password, C.kdf_salt(kdf_params), kdf_id, kdf_params)
    index_key = C.derive_index_key(kek)
    data_key = C.new_data_key()

    drive = _normalise_binding(bind_drive, target)
    name = vault_name or target.stem
    created = _now()

    skeleton = _make_index(
        name, created, created, chunk_size, data_key, drive, [], kdf_id, weak_password
    )
    skeleton["entries"] = [
        {
            "name": item.name,
            "size": item.size,
            "offset": 0,
            "chunk": "00" * 16,
            "sha256": "00" * 32,
            "mtime": item.mtime,
            "mode": item.mode,
        }
        for item in sources_list
    ]
    reserved = _plan_reservation(skeleton, kdf_params)

    # 空间预检：预留区 + 密文数据区
    need = reserved + total + _cipher_overhead(sources_list, chunk_size)
    existing = target.stat().st_size if target.exists() else 0
    available = free_space(target.parent) + existing
    if available and need > available:
        raise ULockerError(
            f"目标磁盘空间不足：需要约 {human_size(need)}，可用 {human_size(available)}"
        )

    tmp = target.with_name(target.name + ".tmp")
    tmp.unlink(missing_ok=True)

    try:
        for attempt in range(RESERVE_ATTEMPTS):
            try:
                with tmp.open("wb") as fh:
                    fh.seek(reserved)
                    entries, done = _store_files(
                        fh, reserved, data_key, sources_list, chunk_size, progress_cb, total
                    )
                    index = _make_index(
                        name,
                        created,
                        _now(),
                        chunk_size,
                        data_key,
                        drive,
                        entries,
                        kdf_id,
                        weak_password,
                    )
                    header = _build_header(
                        reserved,
                        kdf_id,
                        kdf_params,
                        index_key,
                        index,
                        extra_flags=FLAG_DRIVE_BOUND if drive else 0,
                    )
                    if len(header) > reserved:
                        raise _ReserveTooSmall(
                            f"预留区不足：需要 {len(header)}，现有 {reserved}"
                        )
                    fh.seek(0)
                    fh.write(header)
                    pad = reserved - len(header)
                    if pad:
                        fh.write(b"\x00" * pad)
                    fh.flush()
                    os.fsync(fh.fileno())
                break
            except _ReserveTooSmall:
                # 索引比预估的大（比如条目名特别长），放大预留区重来
                reserved = round_up(reserved * 2 + MIN_RESERVE_SLACK, RESERVE_ALIGN)
                tmp.unlink(missing_ok=True)
                progress_cb(0, total, "重新计算头部预留区…")
        else:  # pragma: no cover - 正常情况下不会走到
            raise ULockerError("无法为头部预留足够的空间，请减少单次加密的文件数量")

        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    # 回读校验：确保刚写出来的容器确实能用口令打开
    # （此处跳过 U 盘绑定校验——容器完全可能是在这台机器上为另一块 U 盘准备的）
    vault = open_vault(target, password, ignore_drive_binding=True)
    try:
        info = vault.info
        info.warnings = warnings + info.warnings
    finally:
        vault.close()

    if shred_source and sources_list:
        for item in sources_list:
            try:
                shred_file(item.path, passes=shred_passes)
            except ShredError as exc:
                warnings.append(str(exc))
        _prune_empty_dirs(sources)

    return info


def _prune_empty_dirs(sources: Sequence[os.PathLike | str]) -> None:
    """擦除源文件后，顺手删掉变空的目录（仅限用户显式给的目录）。"""
    for raw in sources:
        path = Path(raw).expanduser()
        if not path.is_dir():
            continue
        for root, dirs, files in os.walk(path, topdown=False):
            try:
                if not any(Path(root).iterdir()):
                    os.rmdir(root)
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# 打开容器
# --------------------------------------------------------------------------- #


def open_vault(
    path: os.PathLike | str,
    password: str,
    *,
    ignore_drive_binding: bool = False,
) -> "Vault":
    """用口令打开容器，返回 :class:`Vault`。"""
    target = Path(path).expanduser()
    if not target.is_file():
        raise ULockerError(f"容器不存在：{target}")

    # 优先以可读写方式打开；只读介质（写保护的 U 盘、只读挂载）回退成只读模式，
    # 此时仍然能查看和解包，但修改类操作会被明确拒绝。
    read_only = False
    try:
        fh = target.open("rb+")
    except OSError:
        fh = target.open("rb")
        read_only = True

    try:
        header = _read_header(fh)
        kek = C.derive_kek(
            password, C.kdf_salt(header.kdf_params), header.kdf_id, header.kdf_params
        )
        index_key = C.derive_index_key(kek)
        index = _decrypt_index(header, index_key)
    except BaseException:
        fh.close()
        raise

    warnings: List[str] = []
    if read_only:
        warnings.append("容器以只读方式打开：可以查看和解包，但无法追加或修改")
    if index.get("weak_password"):
        warnings.append(
            f"该容器使用短于 {C.PASSWORD_MIN_LEN} 位的口令，建议尽快更换（ulocker passwd）"
        )
    bound = index.get("drive")
    if bound and not ignore_drive_binding:
        current = drive_of(target)
        if current is None:
            warnings.append("无法读取当前磁盘信息，已跳过 U 盘绑定校验")
        elif not match_drive(bound, current):
            fh.close()
            want = normalise_serial(bound.get("serial")) or bound.get("label") or "?"
            got = normalise_serial(current.serial) or current.label or "?"
            raise DriveMismatchError(
                f"该容器已绑定到另一块 U 盘（期望 SN:{want}，当前 SN:{got}，"
                f"位置 {current.root}）。如需强制打开，请使用 --ignore-drive-binding"
            )

    return Vault(
        path=target,
        fh=fh,
        header=header,
        index=index,
        index_key=index_key,
        warnings=warnings,
        read_only=read_only,
    )


def peek_vault(path: os.PathLike | str) -> Dict[str, Any]:
    """只读容器头部（不需要口令），返回格式与绑定信息。"""
    target = Path(path).expanduser()
    if not target.is_file():
        raise ULockerError(f"容器不存在：{target}")
    with target.open("rb") as fh:
        header = _read_header(fh)
    return {
        "path": str(target),
        "version": header.version,
        "kdf_id": header.kdf_id,
        "kdf_name": C.KDF_NAMES.get(header.kdf_id, str(header.kdf_id)),
        "drive_bound": header.drive_bound,
        "data_offset": header.data_offset,
        "header_size": header.size,
        "file_size": target.stat().st_size,
    }


# --------------------------------------------------------------------------- #
# Vault
# --------------------------------------------------------------------------- #


class Vault:
    """一个已解锁的容器。

    建议用 ``with`` 语句或显式调用 :meth:`close` 释放文件句柄。
    """

    def __init__(
        self,
        path: Path,
        fh,
        header: _Header,
        index: Dict[str, Any],
        index_key: bytes,
        warnings: Optional[List[str]] = None,
        read_only: bool = False,
    ) -> None:
        self.path = path
        self._fh = fh
        self._header = header
        self._index = index
        self._index_key = index_key
        self._warnings = list(warnings or [])
        self._read_only = bool(read_only)
        self._data_key = _index_data_key(index)
        self._chunk_size = _index_chunk_size(index)

    # -------------------------------------------------------------- 生命周期

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None

    @property
    def closed(self) -> bool:
        return self._fh is None

    def _require_open(self) -> None:
        if self._fh is None:
            raise ULockerError("容器已关闭")

    def _require_writable(self) -> None:
        self._require_open()
        if self._read_only:
            raise ULockerError(
                f"容器以只读方式打开（{self.path} 不可写），无法追加或修改内容"
            )

    @property
    def read_only(self) -> bool:
        """容器是否以只读方式打开（只读介质上仍然可以查看与解包）。"""
        return self._read_only

    # -------------------------------------------------------------- 元信息

    @property
    def data_offset(self) -> int:
        return self._header.data_offset

    @property
    def chunk_size(self) -> int:
        return self._chunk_size

    @property
    def name(self) -> str:
        return str(self._index.get("name") or self.path.stem)

    @property
    def bound_drive(self) -> Optional[Dict[str, Any]]:
        drive = self._index.get("drive")
        return dict(drive) if isinstance(drive, dict) else None

    @property
    def drive_bound(self) -> bool:
        return bool(self._index.get("drive"))

    @property
    def warnings(self) -> List[str]:
        return list(self._warnings)

    def entries(self) -> List[Entry]:
        return sorted(_index_entries(self._index), key=lambda e: e.name)

    def find(self, name: str) -> Entry:
        wanted = name.replace("\\", "/").strip("/")
        for entry in self.entries():
            if entry.name == wanted or Path(entry.name).name == wanted:
                return entry
        raise ULockerError(f"容器中不存在条目：{name}")

    def rename_entry(self, old: str, new: str) -> Entry:
        """给容器内的条目改名。

        只改索引、不动数据区，所以无论容器多大都是瞬间完成。
        """
        safe = safe_relative_name(new)

        entries = _index_entries(self._index)
        wanted = old.replace("\\", "/").strip("/")
        target: Optional[Entry] = None
        for entry in entries:
            if entry.name == wanted:
                target = entry
                break
        if target is None:
            raise ULockerError(f"容器中不存在条目：{old}")
        for entry in entries:
            if entry is not target and entry.name == safe:
                raise ULockerError(f"新名字已被占用：{safe}")

        target.name = safe
        index = dict(self._index)
        index["entries"] = [e.to_json() for e in entries]
        index["updated"] = _now()
        self._commit(index, self._index_key, self._header.kdf_id, self._header.kdf_params)
        return target

    @property
    def info(self) -> VaultInfo:
        entries = _index_entries(self._index)
        try:
            stored = self.path.stat().st_size
        except OSError:
            stored = 0
        return VaultInfo(
            path=str(self.path),
            name=self.name,
            created=str(self._index.get("created") or ""),
            updated=str(self._index.get("updated") or ""),
            kdf_id=self._header.kdf_id,
            kdf_name=C.KDF_NAMES.get(self._header.kdf_id, str(self._header.kdf_id)),
            kdf_params=dict(self._header.kdf_params),
            drive_bound=bool(self._index.get("drive")),
            bound_drive=self.bound_drive,
            entry_count=len(entries),
            total_size=sum(e.size for e in entries),
            encrypted_size=stored,
            header_size=self._header.size,
            chunk_size=self._chunk_size,
            warnings=self.warnings,
        )

    # -------------------------------------------------------------- 解包

    def extract(
        self,
        names: Optional[Sequence[str]] = None,
        dest: os.PathLike | str = ".",
        *,
        progress: Optional[ProgressFn] = None,
        overwrite: bool = False,
        restore_mtime: bool = True,
        verify: bool = True,
    ) -> List[Path]:
        """把条目解密到 ``dest`` 目录，返回写出的文件路径列表。"""
        self._require_open()
        progress_cb = _Progress(progress)

        all_entries = self.entries()
        if names is None:
            selected = all_entries
        else:
            wanted = [n.replace("\\", "/").strip("/") for n in names]
            selected = []
            missing: List[str] = []
            for one in wanted:
                hit = [
                    e
                    for e in all_entries
                    if e.name == one or Path(e.name).name == one
                ]
                if not hit:
                    missing.append(one)
                else:
                    selected.extend(hit)
            if missing:
                raise ULockerError("容器中不存在：" + "、".join(missing))

        dest_root = Path(dest).expanduser()
        if dest_root.exists() and not dest_root.is_dir():
            raise ULockerError(f"解包目标必须是目录：{dest_root}")
        dest_root.mkdir(parents=True, exist_ok=True)

        total = sum(e.size for e in selected) or 1
        done = 0
        written: List[Path] = []

        for entry in selected:
            target = resolve_inside(dest_root, entry.name)
            if target.exists():
                if not overwrite:
                    target = unique_path(target)
                elif target.is_dir():
                    raise ULockerError(f"目标是一个目录：{target}")
            _extract_entry(
                self._fh,
                self.data_offset,
                self._data_key,
                entry,
                target,
                self._chunk_size,
                progress_cb,
                done,
                total,
                restore_mtime=restore_mtime,
                verify=verify,
            )
            done += entry.size
            written.append(target)

        progress_cb(total, total, "解包完成")
        return written

    def read_bytes(self, name: str, limit: Optional[int] = None) -> bytes:
        """把单个条目读进内存（适合预览小文件）。"""
        self._require_open()
        entry = self.find(name)
        size = entry.size if limit is None else min(entry.size, int(limit))
        buf = bytearray()
        chunk_id = bytes.fromhex(entry.chunk_id)
        self._fh.seek(self.data_offset + entry.offset)
        seq = 0
        while len(buf) < size:
            data = _read_chunk(
                self._fh, self._data_key, chunk_id, seq, entry.name, self._chunk_size
            )
            buf.extend(data)
            seq += 1
        return bytes(buf[:size])

    # -------------------------------------------------------------- 追加

    def add_paths(
        self,
        sources: Sequence[os.PathLike | str],
        *,
        progress: Optional[ProgressFn] = None,
        follow_symlinks: bool = False,
        shred_source: bool = False,
        shred_passes: int = 1,
    ) -> List[Entry]:
        """向容器追加文件/目录。数据区只做追加，头部原地重写。"""
        self._require_writable()
        progress_cb = _Progress(progress)
        files = _collect_sources(sources, follow_symlinks=follow_symlinks)
        if not files:
            return []

        existing = {e.name.lower() if is_windows() else e.name for e in self.entries()}
        for item in files:
            key = item.name.lower() if is_windows() else item.name
            if key in existing:
                raise ULockerError(f"容器中已存在同名条目：{item.name}")

        old_size = os.path.getsize(self.path)
        total = sum(item.size for item in files)
        added: List[Entry] = []

        try:
            new_entries, _ = _store_files(
                self._fh,
                self.data_offset,
                self._data_key,
                files,
                self._chunk_size,
                progress_cb,
                total,
            )
            added = new_entries
            index = dict(self._index)
            index["entries"] = [
                e.to_json() for e in (_index_entries(self._index) + new_entries)
            ]
            index["updated"] = _now()
            self._commit(index, self._index_key, self._header.kdf_id, self._header.kdf_params)
        except BaseException:
            # 回滚：把追加在末尾的半成品字节砍掉，索引保持不变
            try:
                if self._fh is not None:
                    self._fh.truncate(old_size)
                    self._fh.flush()
            except OSError:
                pass
            raise

        if shred_source:
            for item in files:
                try:
                    shred_file(item.path, passes=shred_passes)
                except ShredError as exc:
                    self._warnings.append(str(exc))

        return added

    # -------------------------------------------------------------- 删除

    def delete_entries(
        self,
        names: Sequence[str],
        *,
        progress: Optional[ProgressFn] = None,
    ) -> List[str]:
        """从容器中删除条目并回收它们占用的空间（会重写数据区）。"""
        self._require_writable()
        progress_cb = _Progress(progress)
        doomed = [e.name for e in (self.find(n) for n in names)]
        doomed_set = set(doomed)
        keep = [e for e in self.entries() if e.name not in doomed_set]
        if not keep and not doomed_set:
            return []

        self._compact(keep, doomed, progress_cb)
        return doomed

    def _compact(
        self,
        keep: List[Entry],
        doomed: List[str],
        progress_cb: _Progress,
    ) -> None:
        data_key = self._data_key
        chunk_size = self._chunk_size
        name = self.name
        created = str(self._index.get("created") or _now())
        drive = self.bound_drive

        skeleton = _make_index(
            name,
            created,
            _now(),
            chunk_size,
            data_key,
            drive,
            keep,
            self._header.kdf_id,
            bool(self._index.get("weak_password")),
        )
        reserved = _plan_reservation(skeleton, self._header.kdf_params)

        total = sum(e.size for e in keep) or 1
        done = 0
        tmp = self.path.with_name(self.path.name + ".compact.tmp")
        tmp.unlink(missing_ok=True)

        try:
            with tmp.open("wb") as out:
                for attempt in range(RESERVE_ATTEMPTS):
                    out.seek(0)
                    out.truncate()
                    out.seek(reserved)
                    new_entries: List[Entry] = []
                    done = 0
                    for entry in keep:
                        new_offset = out.tell() - reserved
                        for nonce, payload in _iter_records(
                            self._fh, self.data_offset, entry, chunk_size
                        ):
                            out.write(nonce)
                            out.write(_REC_LEN.pack(len(payload)))
                            out.write(payload)
                        plain_len = entry.size
                        done += plain_len
                        progress_cb(done, total, entry.name)
                        new_entries.append(replace(entry, offset=new_offset))

                    index = _make_index(
                        name,
                        created,
                        _now(),
                        chunk_size,
                        data_key,
                        drive,
                        new_entries,
                        self._header.kdf_id,
                        bool(self._index.get("weak_password")),
                    )
                    header = _build_header(
                        reserved,
                        self._header.kdf_id,
                        self._header.kdf_params,
                        self._index_key,
                        index,
                        extra_flags=FLAG_DRIVE_BOUND if drive else 0,
                    )
                    if len(header) <= reserved:
                        break
                    reserved = round_up(reserved * 2 + MIN_RESERVE_SLACK, RESERVE_ALIGN)
                else:  # pragma: no cover
                    raise ULockerError("无法为头部预留足够的空间")

                out.seek(0)
                out.write(header)
                pad = reserved - len(header)
                if pad:
                    out.write(b"\x00" * pad)
                out.flush()
                os.fsync(out.fileno())

            self._replace_file(tmp)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

        progress_cb(total, total, "整理完成")

    # -------------------------------------------------------------- 改密码

    def change_password(
        self,
        new_password: str,
        *,
        kdf_id: Optional[int] = None,
        kdf_overrides: Optional[Dict[str, Any]] = None,
        progress: Optional[ProgressFn] = None,
    ) -> None:
        """只重新包裹数据密钥，数据区一个字节都不用动。"""
        self._require_writable()
        warn = _require_password(new_password)
        if warn:
            self._warnings.append(warn)

        kdf_id = kdf_id or self._header.kdf_id or C.pick_default_kdf()
        kdf_params = C.new_kdf_params(kdf_id, kdf_overrides)
        kek = C.derive_kek(
            new_password, C.kdf_salt(kdf_params), kdf_id, kdf_params
        )
        index_key = C.derive_index_key(kek)

        index = dict(self._index)
        index["updated"] = _now()
        index["kdf"] = {"id": int(kdf_id), "name": C.KDF_NAMES.get(kdf_id, str(kdf_id))}
        index["weak_password"] = len(new_password) < C.PASSWORD_MIN_LEN

        _Progress(progress)(0, 1, "重新包裹数据密钥…")
        self._commit(index, index_key, kdf_id, kdf_params)
        _Progress(progress)(1, 1, "密码已更新")

    # -------------------------------------------------------------- 校验

    def verify(self, *, progress: Optional[ProgressFn] = None) -> VerifyReport:
        """逐块解密并核对 SHA-256，确认容器没有损坏。"""
        self._require_open()
        progress_cb = _Progress(progress)
        entries = self.entries()
        report = VerifyReport(entries=len(entries))
        total = sum(e.size for e in entries) or 1
        done = 0

        for entry in entries:
            chunk_id = bytes.fromhex(entry.chunk_id)
            digest = hashlib.sha256()
            try:
                self._fh.seek(self.data_offset + entry.offset)
                remaining = entry.size
                seq = 0
                while remaining > 0:
                    data = _read_chunk(
                        self._fh,
                        self._data_key,
                        chunk_id,
                        seq,
                        entry.name,
                        self._chunk_size,
                    )
                    if len(data) > remaining:
                        raise IntegrityError(f"分块长度超出预期：{entry.name}")
                    digest.update(data)
                    remaining -= len(data)
                    seq += 1
                    done += len(data)
                    progress_cb(done, total, entry.name)
                if digest.hexdigest() != entry.sha256:
                    report.failed.append(f"{entry.name}（SHA-256 不一致）")
                else:
                    report.bytes += entry.size
            except IntegrityError as exc:
                report.failed.append(f"{entry.name}（{exc}）")

        progress_cb(total, total, "校验完成")
        return report

    # -------------------------------------------------------------- 头部提交

    def _commit(
        self,
        index: Dict[str, Any],
        index_key: bytes,
        kdf_id: int,
        kdf_params: Dict[str, Any],
    ) -> None:
        """把新索引写回容器；预留区够就原地写，不够就整体搬迁数据区。"""
        self._require_writable()
        extra = FLAG_DRIVE_BOUND if index.get("drive") else 0
        header = _build_header(
            self._header.data_offset, kdf_id, kdf_params, index_key, index, extra
        )

        if len(header) <= self._header.data_offset:
            self._fh.seek(0)
            self._fh.write(header)
            pad = self._header.data_offset - len(header)
            if pad:
                self._fh.write(b"\x00" * pad)
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._index_key = index_key
            self._refresh_header()
            return

        self._relocate(index, index_key, kdf_id, kdf_params, extra)

    def _relocate(
        self,
        index: Dict[str, Any],
        index_key: bytes,
        kdf_id: int,
        kdf_params: Dict[str, Any],
        extra: int,
    ) -> None:
        """索引变大到装不下时，把整块数据区原样搬到新偏移处。

        数据区的分块偏移都是**相对数据区起点**的，所以搬迁后偏移全部依旧有效，
        不需要做任何解密/重新加密。
        """
        base_header = _build_header(0, kdf_id, kdf_params, index_key, index, extra)
        reserved = round_up(
            len(base_header) + max(MIN_RESERVE_SLACK, len(base_header)), RESERVE_ALIGN
        )
        header = _build_header(reserved, kdf_id, kdf_params, index_key, index, extra)

        old_offset = self._header.data_offset
        old_eof = os.path.getsize(self.path)
        data_len = max(0, old_eof - old_offset)

        tmp = self.path.with_name(self.path.name + ".relocate.tmp")
        tmp.unlink(missing_ok=True)
        try:
            with tmp.open("wb") as out:
                out.seek(reserved)
                self._fh.seek(old_offset)
                remaining = data_len
                while remaining > 0:
                    buf = self._fh.read(min(1 << 22, remaining))
                    if not buf:
                        break
                    out.write(buf)
                    remaining -= len(buf)
                out.seek(0)
                out.write(header)
                pad = reserved - len(header)
                if pad:
                    out.write(b"\x00" * pad)
                out.flush()
                os.fsync(out.fileno())
            # 立即切换索引密钥，_replace_file() 会用它重新解析头部
            self._index_key = index_key
            self._replace_file(tmp)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

    def _replace_file(self, tmp: Path) -> None:
        """用 ``tmp`` 顶替当前容器文件，并重新打开句柄。"""
        self.close()
        os.replace(tmp, self.path)
        self._fh = self.path.open("rb+")
        self._refresh_header()

    def _refresh_header(self) -> None:
        """从磁盘重新解析头部，保证内存状态与文件一致。"""
        header = _read_header(self._fh)
        self._header = header
        self._index = _decrypt_index(header, self._index_key)
        self._data_key = _index_data_key(self._index)
        self._chunk_size = _index_chunk_size(self._index)

    # -------------------------------------------------------------- 杂项

    def export_key_receipt(self) -> Dict[str, Any]:
        """导出不含密钥的凭据文件内容（用于给用户留档 / 做恢复提示）。"""
        info = self.info
        return {
            "ulocker": _INDEX_FORMAT,
            "vault": info.name,
            "created": info.created,
            "kdf": info.kdf_name,
            "drive_bound": info.drive_bound,
            "bound_drive": info.bound_drive,
            "entries": info.entry_count,
            "note": "本文件不包含任何密钥。忘记口令后无法恢复数据。",
        }

    def __repr__(self) -> str:  # pragma: no cover
        state = "closed" if self.closed else f"{len(_index_entries(self._index))} entries"
        return f"<Vault {self.path.name} {state}>"


# --------------------------------------------------------------------------- #
# 解包单条目
# --------------------------------------------------------------------------- #


def _extract_entry(
    fh,
    data_offset: int,
    data_key: bytes,
    entry: Entry,
    target: Path,
    chunk_size: int,
    progress: _Progress,
    done: int,
    total: int,
    *,
    restore_mtime: bool = True,
    verify: bool = True,
) -> None:
    ensure_parent(target)
    part = target.with_name(target.name + ".ulocker-part")
    chunk_id = bytes.fromhex(entry.chunk_id)
    digest = hashlib.sha256()
    seq = 0
    remaining = entry.size

    try:
        fh.seek(data_offset + entry.offset)
        with part.open("wb") as out:
            while remaining > 0:
                data = _read_chunk(fh, data_key, chunk_id, seq, entry.name, chunk_size)
                if len(data) > remaining:
                    raise IntegrityError(f"分块长度超出预期：{entry.name}")
                if verify:
                    digest.update(data)
                out.write(data)
                remaining -= len(data)
                seq += 1
                progress(done + entry.size - remaining, total, entry.name)
            out.flush()
            os.fsync(out.fileno())

        if verify:
            actual = digest.hexdigest()
            if actual != entry.sha256:
                raise IntegrityError(
                    f"SHA-256 校验失败：{entry.name}（期望 {entry.sha256[:16]}…，"
                    f"实际 {actual[:16]}…）"
                )

        os.replace(part, target)
    except BaseException:
        part.unlink(missing_ok=True)
        raise

    if restore_mtime and entry.mtime:
        try:
            os.utime(target, (time.time(), entry.mtime))
        except OSError:
            pass

    # 时间戳之后无法再可靠地恢复权限（Windows 上意义不大），失败就忽略
    try:
        if not is_windows():
            os.chmod(target, entry.mode & 0o777 or 0o644)
    except OSError:
        pass


def extract_vault(
    path: os.PathLike | str,
    password: str,
    dest: os.PathLike | str = ".",
    *,
    names: Optional[Sequence[str]] = None,
    progress: Optional[ProgressFn] = None,
    overwrite: bool = False,
    ignore_drive_binding: bool = False,
) -> List[Path]:
    """一步打开并解包（便捷函数）。"""
    vault = open_vault(path, password, ignore_drive_binding=ignore_drive_binding)
    try:
        return vault.extract(names, dest, progress=progress, overwrite=overwrite)
    finally:
        vault.close()
