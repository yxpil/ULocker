"""容器读写、完整性、绑定与口令变更的整体测试。"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ulocker import crypto as C
from ulocker.drives import drive_of
from ulocker.errors import (
    DriveMismatchError,
    FormatError,
    IntegrityError,
    PathSafetyError,
    ULockerError,
    WrongPasswordError,
)
from ulocker.util import safe_relative_name
from ulocker.vault import (
    create_vault,
    open_vault,
    peek_vault,
)

from conftest import FAST_ARGON2, FAST_SCRYPT, OTHER_PASSWORD, PASSWORD


def new_vault(tmp_path: Path, sources=(), *, password: str = PASSWORD, **kwargs) -> Path:
    target = tmp_path / "locked.ulocker"
    options = {"kdf_id": C.KDF_ARGON2ID, "kdf_overrides": dict(FAST_ARGON2)}
    options.update(kwargs)
    create_vault(target, password, sources, **options)
    return target


def flip_byte(path: Path, offset: int) -> None:
    with path.open("r+b") as fh:
        fh.seek(offset)
        byte = fh.read(1)
        fh.seek(offset)
        fh.write(bytes([byte[0] ^ 0x02]))


# --------------------------------------------------------------------------- #
# 基本往返
# --------------------------------------------------------------------------- #


class TestRoundTrip:
    def test_single_file(self, tmp_path: Path) -> None:
        src = tmp_path / "note.txt"
        src.write_text("机密内容 secret\n", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])

        dest = tmp_path / "out"
        with open_vault(vault_path, PASSWORD) as vault:
            assert [e.name for e in vault.entries()] == ["note.txt"]
            vault.extract(dest=dest)

        assert (dest / "note.txt").read_text(encoding="utf-8") == "机密内容 secret\n"

    def test_directory_tree_with_unicode(self, tmp_path: Path, sample_tree: Path) -> None:
        vault_path = new_vault(tmp_path, [sample_tree])
        dest = tmp_path / "out"

        with open_vault(vault_path, PASSWORD) as vault:
            names = {e.name for e in vault.entries()}
            vault.extract(dest=dest)

        assert "资料/readme.txt" in names
        assert "资料/子目录/更深一层/空文件.dat" in names
        assert (dest / "资料" / "子目录" / "数据.bin").read_bytes() == bytes(range(256)) * 40
        assert (dest / "资料" / "子目录" / "更深一层" / "空文件.dat").read_bytes() == b""
        assert "中文" in (dest / "资料" / "子目录" / "更深一层" / "中文名称文件.txt").read_text(
            encoding="utf-8"
        )

    def test_scrypt_vault(self, tmp_path: Path) -> None:
        src = tmp_path / "a.txt"
        src.write_text("scrypt path", encoding="utf-8")
        vault_path = new_vault(
            tmp_path, [src], kdf_id=C.KDF_SCRYPT, kdf_overrides=dict(FAST_SCRYPT)
        )
        with open_vault(vault_path, PASSWORD) as vault:
            assert vault.read_bytes("a.txt") == b"scrypt path"

    def test_empty_vault(self, tmp_path: Path) -> None:
        vault_path = new_vault(tmp_path, [])
        with open_vault(vault_path, PASSWORD) as vault:
            assert vault.entries() == []
            assert vault.extract(dest=tmp_path / "out") == []
            assert vault.info.entry_count == 0

    def test_empty_file_roundtrip(self, tmp_path: Path) -> None:
        src = tmp_path / "empty.bin"
        src.write_bytes(b"")
        vault_path = new_vault(tmp_path, [src])
        dest = tmp_path / "out"
        with open_vault(vault_path, PASSWORD) as vault:
            vault.extract(dest=dest)
        assert (dest / "empty.bin").read_bytes() == b""

    def test_multi_chunk_streaming(self, tmp_path: Path) -> None:
        """分块边界：1024 字节一块，写 5 个半块。"""
        payload = os.urandom(1024 * 4 + 300)
        src = tmp_path / "big.bin"
        src.write_bytes(payload)

        vault_path = new_vault(tmp_path, [src], chunk_size=1024)
        dest = tmp_path / "out"
        with open_vault(vault_path, PASSWORD) as vault:
            assert vault.chunk_size == 1024
            vault.extract(dest=dest)

        assert (dest / "big.bin").read_bytes() == payload

    def test_exact_multiple_of_chunk_size(self, tmp_path: Path) -> None:
        payload = os.urandom(1024 * 3)
        src = tmp_path / "exact.bin"
        src.write_bytes(payload)
        vault_path = new_vault(tmp_path, [src], chunk_size=1024)
        dest = tmp_path / "out"
        with open_vault(vault_path, PASSWORD) as vault:
            vault.extract(dest=dest)
        assert (dest / "exact.bin").read_bytes() == payload

    def test_mtime_preserved(self, tmp_path: Path) -> None:
        src = tmp_path / "old.txt"
        src.write_text("x", encoding="utf-8")
        stamp = 1_500_000_000
        os.utime(src, (stamp, stamp))

        vault_path = new_vault(tmp_path, [src])
        dest = tmp_path / "out"
        with open_vault(vault_path, PASSWORD) as vault:
            vault.extract(dest=dest)
        assert abs((dest / "old.txt").stat().st_mtime - stamp) < 2

    def test_empty_password_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ULockerError):
            create_vault(tmp_path / "v.ulocker", "", [])

    def test_ciphertext_leaks_nothing_obvious(self, tmp_path: Path) -> None:
        """容器里不应出现明文文件名或内容。"""
        src = tmp_path / "password_list_机密.txt"
        src.write_text("SUPER_SECRET_MARKER_12345", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])
        blob = vault_path.read_bytes()
        assert b"SUPER_SECRET_MARKER_12345" not in blob
        assert "password_list".encode("utf-8") not in blob
        assert "机密".encode("utf-8") not in blob


# --------------------------------------------------------------------------- #
# 健壮性
# --------------------------------------------------------------------------- #


class TestFailureModes:
    def test_wrong_password(self, tmp_path: Path) -> None:
        src = tmp_path / "a.txt"
        src.write_text("data", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])
        with pytest.raises(WrongPasswordError):
            open_vault(vault_path, OTHER_PASSWORD)

    def test_not_a_vault(self, tmp_path: Path) -> None:
        bogus = tmp_path / "fake.ulocker"
        bogus.write_bytes(b"this is definitely not a ulocker container" * 4)
        with pytest.raises(FormatError):
            open_vault(bogus, PASSWORD)

    def test_truncated_header(self, tmp_path: Path) -> None:
        src = tmp_path / "a.txt"
        src.write_text("data", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])
        data = vault_path.read_bytes()[:20]
        vault_path.write_bytes(data)
        with pytest.raises(FormatError):
            open_vault(vault_path, PASSWORD)

    def test_index_ciphertext_tamper_detected(self, tmp_path: Path) -> None:
        src = tmp_path / "a.txt"
        src.write_text("data", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])
        # 头部最后一个字节属于索引密文
        flip_byte(vault_path, peek_vault(vault_path)["header_size"] - 1)
        with pytest.raises(WrongPasswordError):
            open_vault(vault_path, PASSWORD)

    def test_header_flag_tamper_detected(self, tmp_path: Path) -> None:
        """标志位在 AAD 之内，改一个 bit 就应该解不开。"""
        src = tmp_path / "a.txt"
        src.write_text("data", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])
        flip_byte(vault_path, 11)  # 标志位低字节
        with pytest.raises((WrongPasswordError, FormatError)):
            open_vault(vault_path, PASSWORD)

    def test_data_tamper_detected_on_extract(self, tmp_path: Path) -> None:
        src = tmp_path / "a.txt"
        src.write_text("important payload that must stay intact", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])
        data_offset = peek_vault(vault_path)["data_offset"]
        flip_byte(vault_path, data_offset + 20)  # 落在第一块密文里

        with open_vault(vault_path, PASSWORD) as vault:
            with pytest.raises(IntegrityError):
                vault.extract(dest=tmp_path / "out")
        # 失败时不应该留下半成品
        leftovers = list((tmp_path / "out").rglob("*.ulocker-part"))
        assert leftovers == []

    def test_verify_reports_corruption(self, tmp_path: Path) -> None:
        src = tmp_path / "a.txt"
        src.write_text("payload", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])
        data_offset = peek_vault(vault_path)["data_offset"]
        flip_byte(vault_path, data_offset + 18)

        with open_vault(vault_path, PASSWORD) as vault:
            report = vault.verify()
        assert not report.ok
        assert report.failed

    def test_duplicate_source_names_rejected(self, tmp_path: Path) -> None:
        first = tmp_path / "one"
        second = tmp_path / "two"
        first.mkdir()
        second.mkdir()
        (first / "same.txt").write_text("1", encoding="utf-8")
        (second / "same.txt").write_text("2", encoding="utf-8")
        # 两个目录会展开成 one/same.txt 与 two/same.txt，不重名；直接传两个同名文件才冲突
        (tmp_path / "x.txt").write_text("a", encoding="utf-8")
        dup = tmp_path / "nested" / "x.txt"
        dup.parent.mkdir()
        dup.write_text("b", encoding="utf-8")
        with pytest.raises(ULockerError):
            new_vault(tmp_path, [tmp_path / "x.txt", dup])

    def test_missing_source(self, tmp_path: Path) -> None:
        with pytest.raises(ULockerError):
            new_vault(tmp_path, [tmp_path / "does-not-exist"])

    def test_existing_target_requires_force(self, tmp_path: Path) -> None:
        target = tmp_path / "v.ulocker"
        create_vault(target, PASSWORD, [], kdf_overrides=dict(FAST_ARGON2))
        with pytest.raises(ULockerError):
            create_vault(target, PASSWORD, [], kdf_overrides=dict(FAST_ARGON2))
        create_vault(
            target, PASSWORD, [], kdf_overrides=dict(FAST_ARGON2), overwrite=True
        )

    def test_index_has_no_readable_salt_leak(self, tmp_path: Path) -> None:
        """盐值是公开的，但数据密钥绝不能出现在明文里。"""
        vault_path = new_vault(tmp_path, [])
        blob = vault_path.read_bytes()
        with open_vault(vault_path, PASSWORD) as vault:
            data_key = vault._data_key  # noqa: SLF001 - 白盒校验
        assert data_key not in blob
        assert C.b64e(data_key).encode("ascii") not in blob


# --------------------------------------------------------------------------- #
# 路径安全
# --------------------------------------------------------------------------- #


class TestPathSafety:
    def test_safe_names_accepted(self) -> None:
        assert safe_relative_name("a/b/c.txt") == "a/b/c.txt"
        assert safe_relative_name("子目录/文件.dat") == "子目录/文件.dat"
        assert safe_relative_name("a\\b\\c.txt") == "a/b/c.txt"
        assert safe_relative_name("./a//b.txt") == "a/b.txt"

    @pytest.mark.parametrize(
        "bad",
        [
            "../escape.txt",
            "a/../../escape.txt",
            "/absolute/path.txt",
            "C:/windows/system32/evil.dll",
            "",
            "   ",
            "a/b\x00c.txt",
        ],
    )
    def test_unsafe_names_rejected(self, bad: str) -> None:
        with pytest.raises(PathSafetyError):
            safe_relative_name(bad)

    def test_extract_refuses_poisoned_entry_name(self, tmp_path: Path) -> None:
        """即使索引被改坏，解包也不能写到目标目录之外。"""
        src = tmp_path / "a.txt"
        src.write_text("payload", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])

        with open_vault(vault_path, PASSWORD) as vault:
            vault._index["entries"][0]["name"] = "../../../pwned.txt"  # noqa: SLF001
            vault._commit(  # noqa: SLF001 - 故意绕过校验，模拟被篡改的索引
                vault._index,
                vault._index_key,
                vault._header.kdf_id,
                vault._header.kdf_params,
            )

        dest = tmp_path / "out"
        dest.mkdir()
        with open_vault(vault_path, PASSWORD) as vault:
            with pytest.raises(PathSafetyError):
                vault.extract(dest=dest)
        assert not (tmp_path / "pwned.txt").exists()
        assert not (tmp_path.parent / "pwned.txt").exists()


# --------------------------------------------------------------------------- #
# 追加 / 删除 / 改名
# --------------------------------------------------------------------------- #


class TestMutation:
    def test_add_paths(self, tmp_path: Path) -> None:
        first = tmp_path / "one.txt"
        first.write_text("first", encoding="utf-8")
        vault_path = new_vault(tmp_path, [first])

        second = tmp_path / "two.txt"
        second.write_text("second content", encoding="utf-8")
        third = tmp_path / "third.bin"
        third.write_bytes(b"\x00\x01\x02" * 100)

        with open_vault(vault_path, PASSWORD) as vault:
            added = vault.add_paths([second, third])
            assert {e.name for e in added} == {"two.txt", "third.bin"}

        dest = tmp_path / "out"
        with open_vault(vault_path, PASSWORD) as vault:
            assert len(vault.entries()) == 3
            vault.extract(dest=dest)
        assert (dest / "one.txt").read_text(encoding="utf-8") == "first"
        assert (dest / "two.txt").read_text(encoding="utf-8") == "second content"
        assert (dest / "third.bin").read_bytes() == b"\x00\x01\x02" * 100

    def test_add_duplicate_rejected(self, tmp_path: Path) -> None:
        src = tmp_path / "dup.txt"
        src.write_text("x", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])
        with open_vault(vault_path, PASSWORD) as vault:
            with pytest.raises(ULockerError):
                vault.add_paths([src])

    def test_add_rolls_back_on_failure(self, tmp_path: Path) -> None:
        src = tmp_path / "a.txt"
        src.write_text("keep me", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])
        size_before = vault_path.stat().st_size

        with open_vault(vault_path, PASSWORD) as vault:
            with pytest.raises(ULockerError):
                vault.add_paths([tmp_path / "ghost"])

        assert vault_path.stat().st_size == size_before
        dest = tmp_path / "out"
        with open_vault(vault_path, PASSWORD) as vault:
            vault.extract(dest=dest)
        assert (dest / "a.txt").read_text(encoding="utf-8") == "keep me"

    def test_add_many_entries_grows_index(self, tmp_path: Path) -> None:
        """反复追加迫使索引增长，最终触发头部搬迁而数据仍然可读。"""
        vault_path = new_vault(tmp_path, [])
        for batch in range(6):
            files = []
            for i in range(12):
                f = tmp_path / f"batch{batch}_{i}.txt"
                f.write_text(f"payload {batch}-{i}", encoding="utf-8")
                files.append(f)
            with open_vault(vault_path, PASSWORD) as vault:
                vault.add_paths(files)

        dest = tmp_path / "out"
        with open_vault(vault_path, PASSWORD) as vault:
            assert len(vault.entries()) == 72
            assert vault.verify().ok
            vault.extract(dest=dest)
        assert (dest / "batch5_11.txt").read_text(encoding="utf-8") == "payload 5-11"

    def test_delete_and_compact(self, tmp_path: Path) -> None:
        for name in ("keep1.txt", "remove.txt", "keep2.txt"):
            (tmp_path / name).write_text(name, encoding="utf-8")

        sources = [tmp_path / "keep1.txt", tmp_path / "remove.txt", tmp_path / "keep2.txt"]
        vault_path = new_vault(tmp_path, sources)
        size_before = vault_path.stat().st_size

        with open_vault(vault_path, PASSWORD) as vault:
            removed = vault.delete_entries(["remove.txt"])
            assert removed == ["remove.txt"]

        with open_vault(vault_path, PASSWORD) as vault:
            assert {e.name for e in vault.entries()} == {"keep1.txt", "keep2.txt"}
            assert vault.verify().ok
            dest = tmp_path / "out"
            vault.extract(dest=dest)

        assert (dest / "keep1.txt").read_text(encoding="utf-8") == "keep1.txt"
        assert (dest / "keep2.txt").read_text(encoding="utf-8") == "keep2.txt"
        assert not (dest / "remove.txt").exists()
        assert vault_path.stat().st_size <= size_before

    def test_delete_unknown_entry(self, tmp_path: Path) -> None:
        vault_path = new_vault(tmp_path, [])
        with open_vault(vault_path, PASSWORD) as vault:
            with pytest.raises(ULockerError):
                vault.delete_entries(["nothing-here.txt"])

    def test_rename_entry(self, tmp_path: Path) -> None:
        src = tmp_path / "before.txt"
        src.write_text("body", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])

        with open_vault(vault_path, PASSWORD) as vault:
            vault.rename_entry("before.txt", "归档/after.txt")

        dest = tmp_path / "out"
        with open_vault(vault_path, PASSWORD) as vault:
            assert [e.name for e in vault.entries()] == ["归档/after.txt"]
            vault.extract(dest=dest)
        assert (dest / "归档" / "after.txt").read_text(encoding="utf-8") == "body"

    def test_rename_rejects_unsafe_and_taken(self, tmp_path: Path) -> None:
        (tmp_path / "a.txt").write_text("a", encoding="utf-8")
        (tmp_path / "b.txt").write_text("b", encoding="utf-8")
        vault_path = new_vault(tmp_path, [tmp_path / "a.txt", tmp_path / "b.txt"])
        with open_vault(vault_path, PASSWORD) as vault:
            with pytest.raises(PathSafetyError):
                vault.rename_entry("a.txt", "../escape")
            with pytest.raises(ULockerError):
                vault.rename_entry("a.txt", "b.txt")


# --------------------------------------------------------------------------- #
# 口令变更
# --------------------------------------------------------------------------- #


class TestPasswordChange:
    def test_change_password_same_kdf_is_in_place(self, tmp_path: Path) -> None:
        payload = os.urandom(3000)
        src = tmp_path / "data.bin"
        src.write_bytes(payload)
        vault_path = new_vault(tmp_path, [src])
        size_before = vault_path.stat().st_size

        with open_vault(vault_path, PASSWORD) as vault:
            vault.change_password(OTHER_PASSWORD)

        # 数据区没有重写：文件大小完全不变
        assert vault_path.stat().st_size == size_before

        with pytest.raises(WrongPasswordError):
            open_vault(vault_path, PASSWORD)

        dest = tmp_path / "out"
        with open_vault(vault_path, OTHER_PASSWORD) as vault:
            vault.extract(dest=dest)
        assert (dest / "data.bin").read_bytes() == payload

    def test_change_password_and_switch_kdf(self, tmp_path: Path) -> None:
        src = tmp_path / "note.txt"
        src.write_text("switch kdf", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])

        with open_vault(vault_path, PASSWORD) as vault:
            vault.change_password(OTHER_PASSWORD, kdf_id=C.KDF_SCRYPT, kdf_overrides=dict(FAST_SCRYPT))

        with open_vault(vault_path, OTHER_PASSWORD) as vault:
            assert vault.info.kdf_name == "scrypt"
            assert vault.read_bytes("note.txt") == b"switch kdf"

    def test_short_password_just_warns(self, tmp_path: Path) -> None:
        src = tmp_path / "a.txt"
        src.write_text("x", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src], password="short")
        with open_vault(vault_path, "short") as vault:
            assert any("口令" in w for w in vault.warnings)


# --------------------------------------------------------------------------- #
# U 盘绑定
# --------------------------------------------------------------------------- #


class TestDriveBinding:
    def test_bound_to_foreign_serial_refuses(self, tmp_path: Path) -> None:
        src = tmp_path / "a.txt"
        src.write_text("data", encoding="utf-8")
        vault_path = new_vault(
            tmp_path,
            [src],
            bind_drive={
                "serial": "DEADBEEF",
                "label": "FAKE KEY",
                "filesystem": "exFAT",
                "kind": "removable",
                "root": "Z:\\",
            },
        )

        current = drive_of(vault_path)
        if current is None:  # pragma: no cover - 取决于平台
            pytest.skip("当前平台无法枚举磁盘信息")

        with pytest.raises(DriveMismatchError):
            open_vault(vault_path, PASSWORD)

        # 显式忽略绑定时应该还能打开
        with open_vault(vault_path, PASSWORD, ignore_drive_binding=True) as vault:
            assert vault.read_bytes("a.txt") == b"data"
            assert vault.drive_bound

    def test_peek_reports_binding_without_password(self, tmp_path: Path) -> None:
        vault_path = new_vault(
            tmp_path,
            [],
            bind_drive={"serial": "11223344", "label": "USB", "filesystem": "exFAT"},
        )
        meta = peek_vault(vault_path)
        assert meta["drive_bound"] is True
        assert meta["kdf_name"] == "argon2id"
        assert meta["data_offset"] % 4096 == 0

    def test_unbound_vault_opens_anywhere(self, tmp_path: Path) -> None:
        vault_path = new_vault(tmp_path, [])
        with open_vault(vault_path, PASSWORD) as vault:
            assert vault.drive_bound is False
        assert peek_vault(vault_path)["drive_bound"] is False

    def test_bind_to_current_drive_roundtrip(self, tmp_path: Path) -> None:
        current = drive_of(tmp_path)
        if current is None or not current.has_serial:  # pragma: no cover
            pytest.skip("当前磁盘没有可用的卷序列号")

        src = tmp_path / "a.txt"
        src.write_text("bound here", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src], bind_drive=True)

        with open_vault(vault_path, PASSWORD) as vault:
            assert vault.drive_bound
            assert vault.bound_drive["serial"] == current.serial
            assert vault.read_bytes("a.txt") == b"bound here"


# --------------------------------------------------------------------------- #
# 信息与辅助能力
# --------------------------------------------------------------------------- #


class TestInfo:
    def test_info_fields(self, tmp_path: Path) -> None:
        src = tmp_path / "a.txt"
        src.write_text("1234567890", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])

        with open_vault(vault_path, PASSWORD) as vault:
            info = vault.info
            assert info.entry_count == 1
            assert info.total_size == 10
            assert info.kdf_name == "argon2id"
            assert info.encrypted_size == vault_path.stat().st_size
            assert info.chunk_size == C.CHUNK_SIZE
            assert "密钥派生" in info.describe()

    def test_info_json_hides_salt(self, tmp_path: Path) -> None:
        vault_path = new_vault(tmp_path, [])
        with open_vault(vault_path, PASSWORD) as vault:
            payload = vault.info.to_json()
        assert payload["kdf_params"]["salt"] == "<已省略>"

    def test_read_bytes_with_limit(self, tmp_path: Path) -> None:
        src = tmp_path / "a.bin"
        src.write_bytes(bytes(range(256)) * 8)
        vault_path = new_vault(tmp_path, [src])
        with open_vault(vault_path, PASSWORD) as vault:
            assert vault.read_bytes("a.bin", limit=10) == bytes(range(10))

    def test_export_key_receipt_has_no_secrets(self, tmp_path: Path) -> None:
        src = tmp_path / "a.txt"
        src.write_text("x", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])
        with open_vault(vault_path, PASSWORD) as vault:
            receipt = vault.export_key_receipt()
            key_hex = vault._data_key.hex()  # noqa: SLF001
        assert "data_key" not in receipt
        assert key_hex not in str(receipt)

    def test_find_matches_basename(self, tmp_path: Path) -> None:
        src = tmp_path / "deep.txt"
        src.write_text("x", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])
        with open_vault(vault_path, PASSWORD) as vault:
            assert vault.find("deep.txt").name == "deep.txt"
            with pytest.raises(ULockerError):
                vault.find("nope.txt")

    def test_extension_appended(self, tmp_path: Path) -> None:
        info = create_vault(
            tmp_path / "noext", PASSWORD, [], kdf_overrides=dict(FAST_ARGON2)
        )
        assert info.path and info.path.endswith(".ulocker")
        assert Path(info.path).exists()

    def test_closed_vault_refuses_operations(self, tmp_path: Path) -> None:
        vault_path = new_vault(tmp_path, [])
        vault = open_vault(vault_path, PASSWORD)
        vault.close()
        assert vault.closed
        with pytest.raises(ULockerError):
            vault.extract(dest=tmp_path / "out")


class TestShredSource:
    def test_shred_source_removes_plaintext(self, tmp_path: Path) -> None:
        src = tmp_path / "sensitive.txt"
        src.write_text("burn after reading", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src], shred_source=True)
        assert not src.exists()

        dest = tmp_path / "out"
        with open_vault(vault_path, PASSWORD) as vault:
            vault.extract(dest=dest)
        assert (dest / "sensitive.txt").read_text(encoding="utf-8") == "burn after reading"


class TestExtractBehaviour:
    def test_extract_selected_names_only(self, tmp_path: Path) -> None:
        (tmp_path / "a.txt").write_text("A", encoding="utf-8")
        (tmp_path / "b.txt").write_text("B", encoding="utf-8")
        vault_path = new_vault(tmp_path, [tmp_path / "a.txt", tmp_path / "b.txt"])
        dest = tmp_path / "out"
        with open_vault(vault_path, PASSWORD) as vault:
            written = vault.extract(["a.txt"], dest)
        assert [p.name for p in written] == ["a.txt"]
        assert not (dest / "b.txt").exists()

    def test_extract_unknown_name(self, tmp_path: Path) -> None:
        vault_path = new_vault(tmp_path, [])
        with open_vault(vault_path, PASSWORD) as vault:
            with pytest.raises(ULockerError):
                vault.extract(["ghost.txt"], tmp_path / "out")

    def test_existing_file_not_overwritten_by_default(self, tmp_path: Path) -> None:
        src = tmp_path / "a.txt"
        src.write_text("new", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])

        dest = tmp_path / "out"
        dest.mkdir()
        (dest / "a.txt").write_text("original", encoding="utf-8")

        with open_vault(vault_path, PASSWORD) as vault:
            written = vault.extract(dest=dest)

        assert (dest / "a.txt").read_text(encoding="utf-8") == "original"
        assert written[0].name == "a (2).txt"
        assert (dest / "a (2).txt").read_text(encoding="utf-8") == "new"

    def test_overwrite_flag(self, tmp_path: Path) -> None:
        src = tmp_path / "a.txt"
        src.write_text("new", encoding="utf-8")
        vault_path = new_vault(tmp_path, [src])
        dest = tmp_path / "out"
        dest.mkdir()
        (dest / "a.txt").write_text("original", encoding="utf-8")

        with open_vault(vault_path, PASSWORD) as vault:
            vault.extract(dest=dest, overwrite=True)
        assert (dest / "a.txt").read_text(encoding="utf-8") == "new"
