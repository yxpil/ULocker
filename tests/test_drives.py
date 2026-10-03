"""磁盘识别与容器搜索的测试。

这些测试不假设机器上一定有 U 盘：涉及真实磁盘的断言会在信息不可用时跳过。
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ulocker.drives import (
    KIND_FIXED,
    KIND_REMOVABLE,
    DriveInfo,
    drive_of,
    find_vaults,
    get_drive_info,
    list_drives,
    list_removable_drives,
    match_drive,
    mount_root,
    normalise_serial,
)
from ulocker.vault import create_vault

from conftest import FAST_ARGON2, PASSWORD


class TestNormaliseSerial:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("1a2b3c4d", "1A2B3C4D"),
            ("1A2B3C4D", "1A2B3C4D"),
            ("  abcd  ", "0000ABCD"),
            ("ABCD-1234", "ABCD1234"),
            ("", ""),
            (None, ""),
            ("ZZZZ", "ZZZZ"),
        ],
    )
    def test_values(self, raw, expected) -> None:
        assert normalise_serial(raw) == expected


class TestDriveInfo:
    def test_describe_and_json(self) -> None:
        info = DriveInfo(
            root="E:\\",
            label="KINGSTON",
            serial="1A2B3C4D",
            filesystem="exFAT",
            kind=KIND_REMOVABLE,
            total=32_000_000_000,
            free=8_000_000_000,
        )
        text = info.describe()
        assert "E:\\" in text
        assert "KINGSTON" in text
        assert "1A2B3C4D" in text
        payload = info.to_json()
        assert payload["bind_id"] == "1A2B3C4D"
        assert payload["kind"] == KIND_REMOVABLE

    def test_is_removable(self) -> None:
        assert DriveInfo(root="E:\\", kind=KIND_REMOVABLE).is_removable
        assert not DriveInfo(root="C:\\", kind=KIND_FIXED).is_removable

    def test_bind_id_falls_back_to_label(self) -> None:
        info = DriveInfo(root="/media/usb", label="MYSTICK")
        assert info.bind_id == "MYSTICK"
        assert not info.has_serial


class TestMatchDrive:
    def test_no_binding_always_matches(self) -> None:
        assert match_drive(None, None)
        assert match_drive({}, DriveInfo(root="E:\\"))

    def test_serial_match(self) -> None:
        bound = {"serial": "1a2b3c4d"}
        assert match_drive(bound, DriveInfo(root="E:\\", serial="1A2B3C4D"))
        assert not match_drive(bound, DriveInfo(root="F:\\", serial="FFFFFFFF"))

    def test_missing_current_drive(self) -> None:
        assert not match_drive({"serial": "1A2B3C4D"}, None)

    def test_label_fallback_when_no_serial(self) -> None:
        bound = {"serial": "", "label": "MYSTICK"}
        assert match_drive(bound, DriveInfo(root="/media/x", label="MYSTICK"))
        assert not match_drive(bound, DriveInfo(root="/media/x", label="OTHER"))


class TestEnumeration:
    def test_list_drives_returns_objects(self) -> None:
        drives = list_drives(include_fixed=True)
        assert isinstance(drives, list)
        for info in drives:
            assert isinstance(info, DriveInfo)
            assert info.root
            assert info.kind

    def test_removable_subset(self) -> None:
        all_drives = list_drives(include_fixed=True)
        removable = list_removable_drives()
        assert len(removable) <= len(all_drives)
        assert all(d.is_removable for d in removable)

    def test_fixed_only_filter(self) -> None:
        result = list_drives(include_fixed=False)
        assert all(d.is_removable for d in result)

    def test_drive_of_current_path(self, tmp_path: Path) -> None:
        info = drive_of(tmp_path)
        if info is None:  # pragma: no cover
            pytest.skip("当前平台无法枚举磁盘")
        assert info.root
        again = get_drive_info(info.root)
        assert again is not None
        assert again.root.rstrip("\\/").lower() == info.root.rstrip("\\/").lower()

    def test_mount_root_of_tmp(self, tmp_path: Path) -> None:
        root = mount_root(tmp_path)
        assert root.exists()

    def test_get_drive_info_unknown(self) -> None:
        assert get_drive_info("Q:\\definitely-not-a-drive\\") is None


class TestFindVaults:
    def test_find_in_directory(self, tmp_path: Path) -> None:
        nested = tmp_path / "backup"
        nested.mkdir()
        first = nested / "a.ulocker"
        second = tmp_path / "b.ulocker"
        for target in (first, second):
            create_vault(target, PASSWORD, [], kdf_overrides=dict(FAST_ARGON2))

        found = find_vaults(tmp_path)
        assert set(found) == {first, second}

    def test_find_respects_depth(self, tmp_path: Path) -> None:
        deep = tmp_path / "l1" / "l2" / "l3"
        deep.mkdir(parents=True)
        create_vault(
            deep / "deep.ulocker", PASSWORD, [], kdf_overrides=dict(FAST_ARGON2)
        )
        assert find_vaults(tmp_path, max_depth=1) == []
        assert len(find_vaults(tmp_path, max_depth=4)) == 1

    def test_find_non_recursive(self, tmp_path: Path) -> None:
        nested = tmp_path / "sub"
        nested.mkdir()
        create_vault(
            nested / "hidden.ulocker", PASSWORD, [], kdf_overrides=dict(FAST_ARGON2)
        )
        top = tmp_path / "top.ulocker"
        create_vault(top, PASSWORD, [], kdf_overrides=dict(FAST_ARGON2))

        assert find_vaults(tmp_path, recursive=False) == [top]

    def test_find_accepts_file_path(self, tmp_path: Path) -> None:
        target = tmp_path / "one.ulocker"
        create_vault(target, PASSWORD, [], kdf_overrides=dict(FAST_ARGON2))
        assert find_vaults(target) == [target]
        plain = tmp_path / "plain.txt"
        plain.write_text("x", encoding="utf-8")
        assert find_vaults(plain) == []

    def test_find_on_empty_directory(self, tmp_path: Path) -> None:
        assert find_vaults(tmp_path) == []

    def test_find_skips_recycle_bin(self, tmp_path: Path) -> None:
        recycle = tmp_path / "$RECYCLE.BIN"
        recycle.mkdir()
        create_vault(
            recycle / "junk.ulocker", PASSWORD, [], kdf_overrides=dict(FAST_ARGON2)
        )
        assert find_vaults(tmp_path) == []

    @pytest.mark.skipif(os.name != "nt", reason="仅 Windows 有回收站目录名")
    def test_windows_case_insensitive_extension(self, tmp_path: Path) -> None:
        target = tmp_path / "UPPER.ULOCKER"
        create_vault(target, PASSWORD, [], kdf_overrides=dict(FAST_ARGON2))
        assert find_vaults(tmp_path) == [target]
