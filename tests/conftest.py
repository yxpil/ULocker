"""pytest 公共配置与夹具。

测试里把 KDF 参数调到最小（Argon2id 16 KiB / 1 轮），这样上百次加解密
也只花几百毫秒；真实使用时用的是 crypto 模块里的默认强参数。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# 让测试可以直接 import ulocker（无需先 pip install -e .）
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ulocker import crypto as C  # noqa: E402

#: 测试用的极速 Argon2id 参数
FAST_ARGON2 = {"time_cost": 1, "memory_cost": 16, "parallelism": 1}
#: 测试用的极速 scrypt 参数
FAST_SCRYPT = {"n": 16, "r": 8, "p": 1}

PASSWORD = "correct horse battery staple"
OTHER_PASSWORD = "a completely different passphrase"


@pytest.fixture
def fast_argon2() -> dict:
    return dict(FAST_ARGON2)


@pytest.fixture
def fast_scrypt() -> dict:
    return dict(FAST_SCRYPT)


@pytest.fixture
def password() -> str:
    return PASSWORD


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    path = tmp_path / "work"
    path.mkdir()
    return path


@pytest.fixture
def sample_tree(workdir: Path) -> Path:
    """一棵包含中文名、空文件、嵌套目录的样本目录树。"""
    root = workdir / "资料"
    (root / "子目录" / "更深一层").mkdir(parents=True)
    (root / "readme.txt").write_text("hello ULocker\n", encoding="utf-8")
    (root / "子目录" / "数据.bin").write_bytes(bytes(range(256)) * 40)
    (root / "子目录" / "更深一层" / "空文件.dat").write_bytes(b"")
    (root / "子目录" / "更深一层" / "中文名称文件.txt").write_text(
        "内容里有中文和一些符号：!@#$%^&*()\n", encoding="utf-8"
    )
    return root


def make_vault(tmp_path: Path, sources=(), *, password: str = PASSWORD, **kwargs):
    """创建一个测试容器的便捷封装。"""
    from ulocker import create_vault

    target = tmp_path / "vault.ulocker"
    params = dict(kdf_id=C.KDF_ARGON2ID, kdf_overrides=FAST_ARGON2)
    params.update(kwargs)
    return target, create_vault(target, password, sources, **params)
