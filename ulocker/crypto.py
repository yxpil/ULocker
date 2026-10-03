"""ULocker 加密原语：口令派生、密钥分层与 AES-256-GCM 封装。

密钥层次（信封加密 envelope encryption）::

    口令 ──Argon2id / scrypt──► KEK(32B) ──HKDF-SHA256──► index_key(32B)
    index_key 解密容器索引 ──► 取出随机的 data_key(32B)
    data_key 以 AES-256-GCM 逐块加解密真实数据

之所以要让 ``data_key`` 与口令解耦，好处有两个：

1. **改密码是秒级的**。只需要用新 KEK 重新加密索引，数据区一个字节都不用动；
   否则一个 32 GB 的 U 盘改密码就得整盘重写一遍。
2. **没有后门**。``data_key`` 只存在于被加密的索引里，而索引由口令派生出的
   ``index_key`` 保护。忘记口令 = 数据在密码学上无法恢复。
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from typing import Any, Dict, Optional, Type

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import IntegrityError, ULockerError

# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #

MAGIC = b"ULOCKERV"
FORMAT_VERSION = 1

KDF_ARGON2ID = 1
KDF_SCRYPT = 2

KDF_NAMES: Dict[int, str] = {KDF_ARGON2ID: "argon2id", KDF_SCRYPT: "scrypt"}
KDF_IDS: Dict[str, int] = {v: k for k, v in KDF_NAMES.items()}

FLAG_DRIVE_BOUND = 0x0001  # 容器绑定到某个特定 U 盘
FLAG_ZLIB = 0x0002  # 索引经过 zlib 压缩

KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
GCM_TAG_LEN = 16

RECORD_HEADER_LEN = NONCE_LEN + 4  # [nonce 12B][密文长度 4B]
CHUNK_SIZE = 1 << 20  # 默认 1 MiB 明文分块
MAX_CHUNK_CT = CHUNK_SIZE + GCM_TAG_LEN

#: 容器默认使用 Argon2id；没有安装 argon2-cffi 时可退回 scrypt。
DEFAULT_KDF_ID = KDF_ARGON2ID

#: Argon2id 默认参数（64 MiB / 3 轮 / 4 线程，约几十毫秒量级）。
DEFAULT_ARGON2ID: Dict[str, int] = {
    "time_cost": 3,
    "memory_cost": 64 * 1024,  # KiB
    "parallelism": 4,
}

#: scrypt 默认参数（约 32 MiB 内存）。
DEFAULT_SCRYPT: Dict[str, int] = {
    "n": 1 << 15,
    "r": 8,
    "p": 1,
}

#: 口令长度下限（仅用于提醒，加密层不强制）。
PASSWORD_MIN_LEN = 8

_INFO_INDEX = b"ulocker/v1/index"


# --------------------------------------------------------------------------- #
# 随机数 / 密钥
# --------------------------------------------------------------------------- #


def random_bytes(n: int) -> bytes:
    """返回 ``n`` 字节密码学安全的随机数据。"""
    return secrets.token_bytes(n)


def new_data_key() -> bytes:
    """生成一个全新的随机数据密钥（AES-256）。"""
    return secrets.token_bytes(KEY_LEN)


# --------------------------------------------------------------------------- #
# 口令派生
# --------------------------------------------------------------------------- #


def derive_kek(
    password: str,
    salt: bytes,
    kdf_id: int,
    params: Optional[Dict[str, Any]] = None,
) -> bytes:
    """用口令派生 32 字节 KEK。

    :param password: 用户口令（UTF-8 编码后参与派生）。
    :param salt: 从容器头部读出的盐值。
    :param kdf_id: :data:`KDF_ARGON2ID` 或 :data:`KDF_SCRYPT`。
    :param params: 该 KDF 的参数（不含 salt 亦可）。
    """
    if not isinstance(password, str):
        raise ULockerError("口令必须是字符串")
    if len(salt) < 8:
        raise ULockerError("盐值长度不足，容器头部可能已损坏")
    secret = password.encode("utf-8")
    params = dict(params or {})

    if kdf_id == KDF_ARGON2ID:
        return _argon2id(secret, salt, params)
    if kdf_id == KDF_SCRYPT:
        return _scrypt(secret, salt, params)
    raise ULockerError(f"不支持的 KDF 编号：{kdf_id}")


def _argon2id(secret: bytes, salt: bytes, params: Dict[str, Any]) -> bytes:
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError as exc:  # pragma: no cover - 取决于运行环境
        raise ULockerError(
            "该容器使用 Argon2id 派生密钥，请先安装依赖：pip install argon2-cffi"
        ) from exc

    return hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=int(params.get("time_cost", DEFAULT_ARGON2ID["time_cost"])),
        memory_cost=int(params.get("memory_cost", DEFAULT_ARGON2ID["memory_cost"])),
        parallelism=int(params.get("parallelism", DEFAULT_ARGON2ID["parallelism"])),
        hash_len=KEY_LEN,
        type=Type.ID,
        version=19,
    )


def _scrypt(secret: bytes, salt: bytes, params: Dict[str, Any]) -> bytes:
    n = int(params.get("n", DEFAULT_SCRYPT["n"]))
    r = int(params.get("r", DEFAULT_SCRYPT["r"]))
    p = int(params.get("p", DEFAULT_SCRYPT["p"]))
    if n < 2 or (n & (n - 1)):
        raise ULockerError("scrypt 的 n 必须是大于 1 的 2 的幂")
    if r < 1 or p < 1:
        raise ULockerError("scrypt 的 r / p 必须为正整数")
    # OpenSSL 默认 maxmem 仅 32 MiB，参数稍大就会直接报错，这里显式放宽。
    maxmem = max(128 * n * r * 2, 64 * 1024 * 1024)
    return hashlib.scrypt(secret, salt=salt, n=n, r=r, p=p, dklen=KEY_LEN, maxmem=maxmem)


def new_kdf_params(
    kdf_id: int,
    overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """构造一份带随机盐的 KDF 参数，可直接序列化进容器头部。"""
    if kdf_id == KDF_ARGON2ID:
        params: Dict[str, Any] = dict(DEFAULT_ARGON2ID)
    elif kdf_id == KDF_SCRYPT:
        params = dict(DEFAULT_SCRYPT)
    else:
        raise ULockerError(f"不支持的 KDF 编号：{kdf_id}")

    for key, value in (overrides or {}).items():
        if value is not None:
            params[key] = value

    params["salt"] = base64.b64encode(random_bytes(SALT_LEN)).decode("ascii")
    return params


def kdf_salt(params: Dict[str, Any]) -> bytes:
    """从 KDF 参数中取出盐值。"""
    raw = params.get("salt")
    if not isinstance(raw, str):
        raise ULockerError("容器头部缺少盐值")
    try:
        return base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise ULockerError("容器头部的盐值已损坏") from exc


def derive_index_key(kek: bytes) -> bytes:
    """由 KEK 派生出索引加密密钥（HKDF 域分离）。"""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=None,
        info=_INFO_INDEX,
    ).derive(kek)


# --------------------------------------------------------------------------- #
# AEAD 封装
# --------------------------------------------------------------------------- #


def aead_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> bytes:
    """AES-256-GCM 加密，返回含认证标签的密文。"""
    return AESGCM(key).encrypt(nonce, plaintext, aad or None)


def aead_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes = b"",
    *,
    err: Type[ULockerError] = IntegrityError,
    msg: str = "数据校验失败：内容已被篡改或损坏",
) -> bytes:
    """AES-256-GCM 解密；认证失败时抛出 ``err``。"""
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad or None)
    except InvalidTag as exc:
        raise err(msg) from exc


# --------------------------------------------------------------------------- #
# 小工具
# --------------------------------------------------------------------------- #


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:
        raise ULockerError("Base64 数据已损坏") from exc


def zero(bytearray_like: Any) -> None:
    """尽力清零内存中的密钥副本（CPython 下的尽力而为）。"""
    try:
        for i in range(len(bytearray_like)):
            bytearray_like[i] = 0
    except Exception:  # pragma: no cover
        pass


def wipe_bytes(data: Optional[bytearray]) -> None:
    if isinstance(data, bytearray):
        zero(data)


def has_argon2() -> bool:
    """检测当前环境是否可用 Argon2id。"""
    try:
        import argon2.low_level  # noqa: F401
    except ImportError:
        return False
    return True


def resolve_kdf(name: str) -> int:
    """把 ``argon2id`` / ``scrypt`` 之类的名字解析成编号。"""
    key = (name or "").strip().lower()
    if key in KDF_IDS:
        return KDF_IDS[key]
    if key.isdigit() and int(key) in KDF_NAMES:
        return int(key)
    raise ULockerError(f"未知的 KDF：{name!r}（可选：argon2id、scrypt）")


def pick_default_kdf() -> int:
    """优先 Argon2id，缺依赖时退回 scrypt。"""
    return KDF_ARGON2ID if has_argon2() else KDF_SCRYPT


def cpu_parallelism() -> int:
    try:
        return max(1, min(8, os.cpu_count() or 4))
    except Exception:  # pragma: no cover
        return 4
