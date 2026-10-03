"""图形界面冒烟测试。

用 Qt 的 ``offscreen`` 平台插件跑，不需要真实显示器，CI 里也能过。
没装 PyQt6 时整个模块会被跳过。
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="需要 PyQt6 才能测试图形界面")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from ulocker import crypto as C  # noqa: E402
from ulocker import gui  # noqa: E402
from ulocker.drives import KIND_REMOVABLE, DriveInfo  # noqa: E402
from ulocker.gui import MainWindow, Worker, _accepts_progress  # noqa: E402
from ulocker.vault import create_vault, open_vault  # noqa: E402

from conftest import FAST_ARGON2, PASSWORD  # noqa: E402


@pytest.fixture(scope="module")
def qt_app():
    application = QApplication.instance() or QApplication([])
    yield application


@pytest.fixture
def fake_drive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> DriveInfo:
    """把 GUI 看到的“磁盘”指向 tmp_path，避免测试去扫真实硬盘。"""
    info = DriveInfo(
        root=str(tmp_path),
        label="测试盘",
        serial="1A2B3C4D",
        filesystem="exFAT",
        kind=KIND_REMOVABLE,
        total=64 * 1024 * 1024,
        free=32 * 1024 * 1024,
    )
    monkeypatch.setattr(gui, "list_drives", lambda **kwargs: [info])
    return info


@pytest.fixture
def window(qt_app, fake_drive: DriveInfo):
    win = MainWindow()
    yield win
    win.close_vault(quiet=True)
    win.close()


def make_vault(tmp_path: Path, *, name: str = "v.ulocker", body: str = "hello") -> Path:
    src = tmp_path / "note.txt"
    src.write_text(body, encoding="utf-8")
    target = tmp_path / name
    create_vault(target, PASSWORD, [src], kdf_overrides=dict(FAST_ARGON2))
    return target


class TestProgressDetection:
    def test_functions_without_progress(self) -> None:
        assert not _accepts_progress(open_vault)
        assert not _accepts_progress(lambda root: root)

    def test_functions_with_progress(self, tmp_path: Path) -> None:
        vault_path = make_vault(tmp_path)
        with open_vault(vault_path, PASSWORD) as vault:
            assert _accepts_progress(vault.verify)
            assert _accepts_progress(vault.extract)
            assert _accepts_progress(vault.add_paths)

    def test_var_keyword_accepted(self) -> None:
        assert _accepts_progress(lambda **kwargs: kwargs)


class TestWindow:
    def test_initial_state(self, window: MainWindow) -> None:
        assert window.table.columnCount() == 4
        assert window.table.rowCount() == 0
        assert not window.act_extract.isEnabled()
        assert not window.act_close.isEnabled()
        assert "加密" in window.vault_label.text() or window.vault_label.text() == "未打开容器"

    def test_drive_is_selected_and_described(self, window: MainWindow, fake_drive: DriveInfo) -> None:
        assert window.drive is not None
        assert window.drive.root == fake_drive.root
        assert "1A2B3C4D" in window.drive_label.text()

    def test_attach_and_close_vault(self, window: MainWindow, tmp_path: Path) -> None:
        vault_path = make_vault(tmp_path)
        vault = open_vault(vault_path, PASSWORD)
        window._attach_vault(vault)

        assert window.vault is not None
        assert window.table.rowCount() == 1
        assert window.table.item(0, 0).text() == "note.txt"
        assert window.act_extract.isEnabled()
        assert "1 个条目" in window.badge.text()

        window.close_vault(quiet=True)
        assert window.vault is None
        assert window.table.rowCount() == 0
        assert not window.act_extract.isEnabled()

    def test_close_vault_releases_file_handle(self, window: MainWindow, tmp_path: Path) -> None:
        vault_path = make_vault(tmp_path)
        window._attach_vault(open_vault(vault_path, PASSWORD))
        held = window.vault
        window.close_vault(quiet=True)
        assert held is not None and held.closed

    def test_vault_list_shows_containers_in_root(
        self, window: MainWindow, tmp_path: Path
    ) -> None:
        make_vault(tmp_path)
        window.refresh_vaults()
        assert window.vault_list.count() == 1
        item = window.vault_list.item(0)
        assert item.text().startswith("v.ulocker")

    def test_log_accumulates(self, window: MainWindow) -> None:
        window.note("第一条")
        window.note("第二条")
        text = window.log.toPlainText()
        assert "第一条" in text and "第二条" in text


class TestWorker:
    def test_success_signal(self, tmp_path: Path) -> None:
        vault_path = make_vault(tmp_path)
        results: list[object] = []
        failures: list[str] = []

        worker = Worker(open_vault, vault_path, PASSWORD)
        worker.succeeded.connect(results.append)
        worker.failed.connect(failures.append)
        worker.run()  # 直接同步执行，不需要事件循环

        assert failures == []
        assert len(results) == 1
        results[0].close()

    def test_failure_signal(self) -> None:
        failures: list[str] = []

        def boom() -> None:
            raise ValueError("故意炸一下")

        worker = Worker(boom)
        worker.failed.connect(failures.append)
        worker.run()

        assert len(failures) == 1
        assert "故意炸一下" in failures[0]

    def test_progress_is_forwarded(self, tmp_path: Path) -> None:
        vault_path = make_vault(tmp_path)
        events: list[tuple[int, int, str]] = []
        succeeded: list[object] = []

        vault = open_vault(vault_path, PASSWORD)
        worker = Worker(vault.verify)
        worker.progressed.connect(lambda d, t, l: events.append((d, t, l)))
        worker.succeeded.connect(succeeded.append)
        worker.run()
        vault.close()

        assert succeeded
        assert events  # 至少收到一次进度
        assert events[-1][0] == events[-1][1]

    def test_missing_vault_reports_clean_error(self, tmp_path: Path) -> None:
        failures: list[str] = []
        worker = Worker(open_vault, tmp_path / "nope.ulocker", PASSWORD)
        worker.failed.connect(failures.append)
        worker.run()
        assert failures
        assert "不存在" in failures[0]
