"""ULocker —— U 盘加密软件。

以「信封加密 + 分块 AEAD」的方式，把文件装进一个 ``.ulocker`` 容器文件里：

* 容器可以放在 U 盘上，文件名、目录结构、内容全部加密；
* Argon2id（或 scrypt）从口令派生出 KEK，KEK 只用来包裹随机的数据密钥；
* 数据区用 AES-256-GCM 按块流式处理，多大文件都不吃内存；
* 可以把容器绑定到指定 U 盘的卷序列号，换一块盘就打不开。

快速上手::

    from ulocker import create_vault, open_vault

    create_vault("E:/secret.ulocker", "my passphrase", ["D:/projects"])
    with open_vault("E:/secret.ulocker", "my passphrase") as vault:
        vault.extract(dest="D:/restore")
"""

from .crypto import (
    CHUNK_SIZE,
    DEFAULT_ARGON2ID,
    DEFAULT_KDF_ID,
    DEFAULT_SCRYPT,
    FORMAT_VERSION,
    KDF_ARGON2ID,
    KDF_NAMES,
    KDF_SCRYPT,
    MAGIC,
    PASSWORD_MIN_LEN,
    has_argon2,
)
from .drives import (
    DriveInfo,
    find_vaults,
    get_drive_info,
    list_drives,
    list_removable_drives,
)
from .errors import (
    DriveMismatchError,
    FormatError,
    IntegrityError,
    PathSafetyError,
    ShredError,
    ULockerError,
    WrongPasswordError,
)
from .util import human_size, looks_like_vault, shred_file
from .vault import (
    Entry,
    Vault,
    VaultInfo,
    VerifyReport,
    create_vault,
    extract_vault,
    open_vault,
    peek_vault,
)

__version__ = "1.0.0"
__all__ = [
    "__version__",
    # 高层 API
    "create_vault",
    "open_vault",
    "extract_vault",
    "peek_vault",
    "Vault",
    "VaultInfo",
    "VerifyReport",
    "Entry",
    # 磁盘
    "DriveInfo",
    "list_drives",
    "list_removable_drives",
    "get_drive_info",
    "find_vaults",
    # 工具
    "shred_file",
    "human_size",
    "looks_like_vault",
    # 常量
    "MAGIC",
    "FORMAT_VERSION",
    "CHUNK_SIZE",
    "PASSWORD_MIN_LEN",
    "KDF_ARGON2ID",
    "KDF_SCRYPT",
    "KDF_NAMES",
    "DEFAULT_KDF_ID",
    "DEFAULT_ARGON2ID",
    "DEFAULT_SCRYPT",
    "has_argon2",
    # 异常
    "ULockerError",
    "FormatError",
    "WrongPasswordError",
    "IntegrityError",
    "DriveMismatchError",
    "PathSafetyError",
    "ShredError",
]
