"""进度回调（钩子）机制测试。

ULocker 没有插件系统，但 ``create_vault`` / ``Vault.extract`` /
``Vault.verify`` / ``Vault.add_paths`` 都接受一个可选的 ``progress`` 回调::

    progress(done: int, total: int, label: str)

``ulocker.vault._Progress`` 是这个回调的包装层，它把回调本身的异常吞掉，
保证一个"坏掉的钩子"不会让正在进行的加解密/解包操作整体失败。本文件验证：

1. 正常回调能按顺序收到 (done, total, label)，且 done 单调、最终等于总量；
2. 抛异常的回调被隔离——create / extract / verify 全部照常完成，数据完好；
3. 回调中途抛错不影响后续操作；``progress=None`` 时也能正常工作。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import FAST_ARGON2, PASSWORD, make_vault
from ulocker import create_vault, open_vault
from ulocker.vault import extract_vault


def _make_sources(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    big = root / "big.bin"
    big.write_bytes(bytes((i % 251) for i in range(4096)))
    small = root / "small.txt"
    small.write_text("hello progress hook\n", encoding="utf-8")
    return root


class TestProgressCallbackDelivery:
    def test_events_received_in_order(self, tmp_path: Path) -> None:
        src = _make_sources(tmp_path / "src")
        seen: list[tuple[int, int, str]] = []
        target, _ = make_vault(
            tmp_path,
            [src],
            progress=lambda d, t, l: seen.append((int(d), int(t), str(l))),
        )
        # 至少收到若干进度事件；总量等于两个源文件大小之和
        assert seen, "正常回调应至少收到一次进度事件"
        done_seq = [d for d, _, _ in seen]
        assert done_seq == sorted(done_seq), "done 必须单调递增"
        total = sum(t for _, t, _ in seen[:1])
        assert total > 0
        assert seen[-1][0] >= total

    def test_no_callback_is_fine(self, tmp_path: Path) -> None:
        # progress 缺省（None）：_Progress 包装层直接返回，不应抛任何异常
        src = _make_sources(tmp_path / "src")
        target, info = make_vault(tmp_path, [src])
        assert info.entry_count == 2

    def test_extract_forwards_progress(self, tmp_path: Path) -> None:
        src = _make_sources(tmp_path / "src")
        target, _ = make_vault(tmp_path, [src])
        seen: list[tuple[int, int, str]] = []
        out = tmp_path / "out"
        extract_vault(
            target, PASSWORD, out,
            progress=lambda d, t, l: seen.append((int(d), int(t), str(l))),
        )
        assert seen, "解包应转发进度事件"
        assert seen[-1][0] == seen[-1][1], "最后一条进度事件应 done==total"


class TestCallbackFailureIsolation:
    """钩子测试核心：一个抛异常的回调不能拖垮主流程。"""

    def test_raising_callback_does_not_break_create(self, tmp_path: Path) -> None:
        src = _make_sources(tmp_path / "src")

        def boom(d: int, t: int, l: str) -> None:
            raise RuntimeError("progress hook exploded")

        # 即使每次回调都抛错，create_vault 仍应完整写完容器
        target, info = make_vault(tmp_path, [src], progress=boom)
        assert info.entry_count == 2
        # 容器可用：解包回来内容一致（目录源的条目名带 src/ 前缀）
        out = tmp_path / "out"
        written = extract_vault(target, PASSWORD, out)
        assert sorted(p.name for p in written) == ["big.bin", "small.txt"]
        assert (out / "src" / "big.bin").read_bytes() == (src / "big.bin").read_bytes()

    def test_raising_callback_does_not_break_extract(self, tmp_path: Path) -> None:
        src = _make_sources(tmp_path / "src")
        target, _ = make_vault(tmp_path, [src])

        calls = {"n": 0}

        def flaky(d: int, t: int, l: str) -> None:
            calls["n"] += 1
            if calls["n"] >= 2:
                raise ValueError("hook failed on 2nd event")

        out = tmp_path / "out"
        written = extract_vault(target, PASSWORD, out, progress=flaky)
        assert len(written) == 2
        assert calls["n"] >= 2

    def test_raising_callback_does_not_break_verify(self, tmp_path: Path) -> None:
        src = _make_sources(tmp_path / "src")
        target, _ = make_vault(tmp_path, [src])

        with open_vault(target, PASSWORD) as vault:
            report = vault.verify(progress=lambda d, t, l: 1 / 0)
        assert report.ok, "校验应在回调抛错的情况下依然完成且通过"
        assert report.entries == 2

    def test_raising_callback_does_not_break_add(self, tmp_path: Path) -> None:
        target, _ = make_vault(tmp_path, [])
        extra = tmp_path / "extra"
        extra.mkdir()
        (extra / "new.bin").write_bytes(b"added data")

        with open_vault(target, PASSWORD) as vault:
            vault.add_paths([extra], progress=lambda d, t, l: (_ for _ in ()).throw(OSError("hook")))
            entries = vault.entries()
        assert [e.name for e in entries] == ["extra/new.bin"]
