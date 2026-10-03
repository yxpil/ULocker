"""工具函数的测试。"""

from __future__ import annotations

from pathlib import Path

import pytest

from ulocker.errors import PathSafetyError, ShredError
from ulocker.util import (
    display_width,
    format_table,
    human_size,
    looks_like_vault,
    parse_serial_filter,
    resolve_inside,
    round_up,
    safe_relative_name,
    shred_file,
    unique_path,
)


class TestHumanSize:
    @pytest.mark.parametrize(
        "value,expected",
        [
            (0, "0 B"),
            (1, "1 B"),
            (1023, "1023 B"),
            (1024, "1.00 KiB"),
            (1536, "1.50 KiB"),
            (1024**2, "1.00 MiB"),
            (1024**3, "1.00 GiB"),
            (1024**4, "1.00 TiB"),
        ],
    )
    def test_values(self, value: int, expected: str) -> None:
        assert human_size(value) == expected


class TestRoundUp:
    def test_alignment(self) -> None:
        assert round_up(0, 4096) == 0
        assert round_up(1, 4096) == 4096
        assert round_up(4096, 4096) == 4096
        assert round_up(4097, 4096) == 8192

    def test_step_of_one(self) -> None:
        assert round_up(7, 1) == 7


class TestDisplayWidth:
    def test_ascii_and_cjk(self) -> None:
        assert display_width("abc") == 3
        assert display_width("中文") == 4
        assert display_width("a中") == 3


class TestFormatTable:
    def test_renders_headers_and_rows(self) -> None:
        text = format_table([["a", "1"], ["中", "2"]], ["名称", "值"])
        lines = text.splitlines()
        assert len(lines) == 4
        assert "名称" in lines[0]
        assert "a" in lines[2]
        assert "中" in lines[3]

    def test_empty_rows(self) -> None:
        assert format_table([], ["a"]) == "a\n-"


class TestSafeNames:
    def test_normalises_separators(self) -> None:
        assert safe_relative_name("a\\b\\c") == "a/b/c"
        assert safe_relative_name("./a/./b") == "a/b"

    @pytest.mark.parametrize("bad", ["..", "../x", "a/../b", "/abs", "C:\\x", "  ", ""])
    def test_rejects(self, bad: str) -> None:
        with pytest.raises(PathSafetyError):
            safe_relative_name(bad)


class TestResolveInside:
    def test_stays_within_base(self, tmp_path: Path) -> None:
        target = resolve_inside(tmp_path, "a/b.txt")
        assert target == (tmp_path / "a" / "b.txt").resolve()

    def test_blocks_escape(self, tmp_path: Path) -> None:
        with pytest.raises(PathSafetyError):
            resolve_inside(tmp_path, "../outside.txt")


class TestUniquePath:
    def test_returns_same_when_absent(self, tmp_path: Path) -> None:
        target = tmp_path / "a.txt"
        assert unique_path(target) == target

    def test_appends_counter(self, tmp_path: Path) -> None:
        target = tmp_path / "a.txt"
        target.write_text("x", encoding="utf-8")
        assert unique_path(target) == tmp_path / "a (2).txt"
        (tmp_path / "a (2).txt").write_text("y", encoding="utf-8")
        assert unique_path(target) == tmp_path / "a (3).txt"

    def test_handles_extension(self, tmp_path: Path) -> None:
        target = tmp_path / "archive.tar.gz"
        target.write_text("x", encoding="utf-8")
        assert unique_path(target).name == "archive.tar (2).gz"


class TestShred:
    def test_shred_removes_file(self, tmp_path: Path) -> None:
        target = tmp_path / "secret.txt"
        target.write_text("do not keep this", encoding="utf-8")
        written = shred_file(target)
        assert written == len("do not keep this")
        assert not target.exists()
        assert list(tmp_path.iterdir()) == []

    def test_shred_reports_progress(self, tmp_path: Path) -> None:
        target = tmp_path / "big.bin"
        target.write_bytes(b"x" * 100)
        seen: list[tuple[int, int, str]] = []
        shred_file(target, passes=2, progress=lambda d, t, l: seen.append((d, t, l)))
        assert seen
        assert seen[-1][0] == 200

    def test_shred_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ShredError):
            shred_file(tmp_path / "ghost.txt")

    def test_shred_directory_refused(self, tmp_path: Path) -> None:
        folder = tmp_path / "dir"
        folder.mkdir()
        with pytest.raises(ShredError):
            shred_file(folder)


class TestLooksLikeVault:
    def test_detects_magic(self, tmp_path: Path) -> None:
        from ulocker.vault import create_vault

        from conftest import FAST_ARGON2, PASSWORD

        target = tmp_path / "v.ulocker"
        create_vault(target, PASSWORD, [], kdf_overrides=dict(FAST_ARGON2))
        assert looks_like_vault(target)

        other = tmp_path / "other.bin"
        other.write_bytes(b"not a vault at all")
        assert not looks_like_vault(other)

    def test_missing_file(self, tmp_path: Path) -> None:
        assert not looks_like_vault(tmp_path / "nope.bin")


class TestSerialFilter:
    def test_parses(self) -> None:
        assert parse_serial_filter("1a2b-3c4d") == "1A2B3C4D"
        assert parse_serial_filter(None) is None
        assert parse_serial_filter("   ") is None
