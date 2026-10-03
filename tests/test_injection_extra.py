"""注入/篡改攻击测试（在既有安全测试基础上补充边界向量）。

两类：

1. **路径穿越注入**：``safe_relative_name`` / ``resolve_inside`` 对 NUL 字节、
   Windows 保留设备名（CON/NUL/COM1…）、尾部空格/点、UNC 路径、混用反斜杠的
   ``..`` 穿越等输入必须拒绝，而不是原样放行。
2. **分块密码层攻击**：数据区每块的 AAD 是 ``chunk_id || 块序号``。
   - 块重排攻击：把第 2 块密文挪到第 1 块位置，解密应因 seq 不匹配而失败；
   - 跨文件移植攻击：把另一个文件的密文块贴到本文件块位置，应因 chunk_id
     不匹配而失败；
   - 任意翻转一个密文字节，``verify()`` 应报告该条目损坏。
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

from conftest import PASSWORD, make_vault
from ulocker import open_vault
from ulocker.errors import IntegrityError, PathSafetyError
from ulocker.util import resolve_inside, safe_relative_name
from ulocker.vault import extract_vault

RECORD_HEADER_LEN = 16  # 12B nonce + 4B 大端密文长度


def _read_record(fh, pos: int):
    fh.seek(pos)
    head = fh.read(RECORD_HEADER_LEN)
    nonce = head[:12]
    (length,) = struct.unpack(">I", head[12:16])
    return nonce, length, fh.read(length)


class TestPathInjection:
    @pytest.mark.parametrize(
        "bad",
        [
            "a\x00b.txt",
            "CON", "NUL", "COM1", "COM9", "LPT1", "LPT9", "PRN", "AUX",
            "sub/CON", "NUL.txt", "a/COM1.dat", "x/LPT9/y",
            "../x", "a/../../b", "..\\..\\evil",
            "//server/share/x.txt",
            "/abs/path",
            "C:\\Windows\\x.dll", "c:/Windows/x.dll",
        ],
    )
    def test_name_rejected(self, bad: str) -> None:
        with pytest.raises(PathSafetyError):
            safe_relative_name(bad)

    @pytest.mark.skipif(not sys.platform.startswith("win"), reason="Windows 专属规则")
    @pytest.mark.parametrize("bad", ["file.", "a/b."])
    def test_trailing_dot_rejected_on_windows(self, bad: str) -> None:
        with pytest.raises(PathSafetyError):
            safe_relative_name(bad)

    def test_trailing_space_is_stripped_not_rejected(self) -> None:
        # strip() 先把首尾空白吃掉，尾部空格最终归一化为普通文件名（不构成穿越）
        assert safe_relative_name("file ") == "file"
        assert safe_relative_name("  a/b  ") == "a/b"

    def test_resolve_inside_rejects_nul(self, tmp_path: Path) -> None:
        with pytest.raises(PathSafetyError):
            resolve_inside(tmp_path, "a\x00.txt")

    def test_resolve_inside_rejects_unc(self, tmp_path: Path) -> None:
        with pytest.raises(PathSafetyError):
            resolve_inside(tmp_path, "//server/share/evil.txt")

    def test_normal_name_survives_roundtrip(self, tmp_path: Path) -> None:
        # 对照：正常相对路径必须放行，不能误杀
        assert safe_relative_name("子目录/图片 (2).png") == "子目录/图片 (2).png"
        target = resolve_inside(tmp_path, "a/b/c.txt")
        assert target.is_relative_to(tmp_path.resolve())


class TestChunkLevelAttacks:
    def _create(self, tmp_path: Path, n_files: int, chunk_size: int):
        src = tmp_path / "src"
        src.mkdir()
        for i in range(n_files):
            # 1024 B 内容，chunk_size=512 时正好 2 块
            (src / f"f{i}.bin").write_bytes(bytes((j * 7 + i) % 256 for j in range(1024)))
        target, _ = make_vault(tmp_path, [src], chunk_size=chunk_size)
        return target

    def test_reorder_blocks_detected(self, tmp_path: Path) -> None:
        target = self._create(tmp_path, n_files=1, chunk_size=512)
        v = open_vault(target, PASSWORD)
        entry = v.find("f0.bin")
        data_offset = v.data_offset
        v.close()

        with open(target, "r+b") as fh:
            pos = data_offset + entry.offset
            _, l0, _ = _read_record(fh, pos)
            n1, l1, c1 = _read_record(fh, pos + RECORD_HEADER_LEN + l0)
            # 把 seq=1 的整块记录（nonce+长度+密文）写到 seq=0 的位置
            fh.seek(pos)
            fh.write(n1 + struct.pack(">I", l1) + c1)

        out = tmp_path / "out"
        with pytest.raises(IntegrityError):
            extract_vault(target, PASSWORD, out)

    def test_cross_file_chunk_transplant_detected(self, tmp_path: Path) -> None:
        target = self._create(tmp_path, n_files=2, chunk_size=512)
        v = open_vault(target, PASSWORD)
        ea = v.find("f0.bin")
        eb = v.find("f1.bin")
        data_offset = v.data_offset
        v.close()

        with open(target, "r+b") as fh:
            nb, lb, cb = _read_record(fh, data_offset + eb.offset)
            fh.seek(data_offset + ea.offset)
            fh.write(nb + struct.pack(">I", lb) + cb)

        out = tmp_path / "out"
        with pytest.raises(IntegrityError):
            extract_vault(target, PASSWORD, out)

    def test_flipped_byte_detected_by_verify(self, tmp_path: Path) -> None:
        target = self._create(tmp_path, n_files=1, chunk_size=512)
        v = open_vault(target, PASSWORD)
        entry = v.find("f0.bin")
        data_offset = v.data_offset
        v.close()

        with open(target, "r+b") as fh:
            pos = data_offset + entry.offset + RECORD_HEADER_LEN
            fh.seek(pos)
            head = fh.read(1)
            fh.seek(pos)
            fh.write(bytes([head[0] ^ 0xFF]))

        v = open_vault(target, PASSWORD)
        report = v.verify()
        v.close()
        assert not report.ok
        assert report.failed
