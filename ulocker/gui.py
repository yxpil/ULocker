"""ULocker 图形界面（PyQt6）。

界面分三块：左边选 U 盘和容器，右边看容器里的条目，底部是进度与日志。
所有耗时操作都跑在后台线程里，主界面不会卡住。
"""

from __future__ import annotations

import inspect
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import __version__
from . import crypto as C
from .drives import VAULT_EXT, DriveInfo, find_vaults, list_drives
from .errors import ULockerError
from .util import human_size
from .vault import Entry, Vault, create_vault, open_vault, peek_vault

try:  # pragma: no cover - 取决于运行环境
    from PyQt6.QtCore import Qt, QThread, pyqtSignal
    from PyQt6.QtGui import QFont
    from PyQt6.QtWidgets import (
        QAbstractItemView,
        QApplication,
        QCheckBox,
        QComboBox,
        QDialog,
        QDialogButtonBox,
        QFileDialog,
        QFormLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QInputDialog,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMessageBox,
        QPlainTextEdit,
        QProgressBar,
        QPushButton,
        QSplitter,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )

    HAS_QT = True
except ImportError:  # pragma: no cover
    HAS_QT = False


STYLE = """
QWidget { background: #1b1d21; color: #e6e6e6; font-size: 13px; }
QMainWindow, QDialog { background: #1b1d21; }
QGroupBox {
    border: 1px solid #33373d; border-radius: 8px;
    margin-top: 14px; padding: 10px 10px 8px 10px; font-weight: 600;
}
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: #9aa4b2; }
QPushButton {
    background: #2b2f36; border: 1px solid #3a3f47; border-radius: 6px;
    padding: 6px 14px; min-height: 22px;
}
QPushButton:hover { background: #343943; border-color: #4a515b; }
QPushButton:pressed { background: #262a30; }
QPushButton:disabled { color: #6b7280; background: #24272c; border-color: #2f333a; }
QPushButton#primary { background: #2f6fdb; border-color: #3d7ff0; color: #ffffff; font-weight: 600; }
QPushButton#primary:hover { background: #3a7eee; }
QPushButton#danger { background: #5c2b2b; border-color: #7a3a3a; }
QPushButton#danger:hover { background: #6d3434; }
QLineEdit, QComboBox, QPlainTextEdit, QListWidget, QTableWidget {
    background: #22252a; border: 1px solid #33373d; border-radius: 6px;
    selection-background-color: #2f6fdb; selection-color: #ffffff;
}
QLineEdit { padding: 5px 8px; }
QComboBox { padding: 5px 8px; }
QComboBox QAbstractItemView { background: #22252a; border: 1px solid #33373d; }
QListWidget::item { padding: 6px 8px; border-radius: 4px; }
QListWidget::item:selected { background: #2f6fdb; color: #ffffff; }
QTableWidget { gridline-color: #2c3037; }
QTableWidget::item:selected { background: #2f6fdb; color: #ffffff; }
QHeaderView::section {
    background: #262a30; color: #9aa4b2; border: none;
    border-right: 1px solid #2c3037; border-bottom: 1px solid #2c3037;
    padding: 6px 8px; font-weight: 600;
}
QProgressBar {
    background: #22252a; border: 1px solid #33373d; border-radius: 6px;
    height: 16px; text-align: center; color: #cbd5e1;
}
QProgressBar::chunk { background: #2f6fdb; border-radius: 5px; }
QCheckBox { spacing: 8px; }
QLabel#hint { color: #8b95a3; }
QLabel#title { font-size: 15px; font-weight: 600; }
QSplitter::handle { background: #262a30; }
"""


# --------------------------------------------------------------------------- #
# 后台线程
# --------------------------------------------------------------------------- #


def _accepts_progress(fn: Callable[..., Any]) -> bool:
    """判断目标函数是否能接受 ``progress=`` 关键字。

    不是所有被丢进后台的活都支持进度回调（比如 ``open_vault``），所以这里先看
    一眼签名，避免硬塞参数把好好的调用搞崩。
    """
    try:
        parameters = inspect.signature(fn).parameters
    except (TypeError, ValueError):  # pragma: no cover - 内置函数之类
        return False
    if "progress" in parameters:
        return True
    return any(p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values())


class Worker(QThread):
    """把阻塞操作丢到后台线程执行，通过信号回传结果。"""

    progressed = pyqtSignal(int, int, str)
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self._with_progress = _accepts_progress(fn)

    def run(self) -> None:  # pragma: no cover - GUI 线程
        try:
            if self._with_progress:
                result = self._fn(*self._args, progress=self._emit, **self._kwargs)
            else:
                result = self._fn(*self._args, **self._kwargs)
        except BaseException as exc:  # noqa: BLE001 - 需要把任何异常回传给界面
            detail = str(exc) or exc.__class__.__name__
            if not isinstance(exc, ULockerError):
                detail = f"{detail}\n\n{traceback.format_exc(limit=3)}"
            self.failed.emit(detail)
        else:
            self.succeeded.emit(result)

    def _emit(self, done: int, total: int, label: str) -> None:
        self.progressed.emit(int(done), int(total), str(label))


# --------------------------------------------------------------------------- #
# 对话框
# --------------------------------------------------------------------------- #


class NewVaultDialog(QDialog):
    """新建容器时的参数收集。"""

    def __init__(self, parent: QWidget | None, default_dir: Path, bind_available: bool) -> None:
        super().__init__(parent)
        self.setWindowTitle("新建加密容器")
        self.setMinimumWidth(460)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(10)

        self.name_edit = QLineEdit("我的加密库")
        form.addRow("容器名称", self.name_edit)

        path_row = QHBoxLayout()
        self.path_edit = QLineEdit(str(default_dir / f"我的加密库{VAULT_EXT}"))
        browse = QPushButton("浏览…")
        browse.clicked.connect(self._pick_path)
        path_row.addWidget(self.path_edit, 1)
        path_row.addWidget(browse)
        holder = QWidget()
        holder.setLayout(path_row)
        form.addRow("保存位置", holder)

        self.pwd_edit = QLineEdit()
        self.pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pwd_edit.setPlaceholderText(f"至少 {C.PASSWORD_MIN_LEN} 位，越长越安全")
        form.addRow("口令", self.pwd_edit)

        self.pwd2_edit = QLineEdit()
        self.pwd2_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pwd2_edit.setPlaceholderText("再输入一次")
        form.addRow("确认口令", self.pwd2_edit)

        self.kdf_combo = QComboBox()
        self.kdf_combo.addItem("Argon2id（推荐，抗显卡暴力破解）", C.KDF_ARGON2ID)
        self.kdf_combo.addItem("scrypt（兼容性更好）", C.KDF_SCRYPT)
        if not C.has_argon2():
            self.kdf_combo.setCurrentIndex(1)
            self.kdf_combo.setEnabled(False)
            self.kdf_combo.setToolTip("未安装 argon2-cffi，只能使用 scrypt")
        form.addRow("密钥派生", self.kdf_combo)

        self.bind_check = QCheckBox("把容器绑定到这块 U 盘（换盘打不开）")
        self.bind_check.setChecked(bind_available)
        self.bind_check.setEnabled(bind_available)
        if not bind_available:
            self.bind_check.setText("当前磁盘没有可用的卷序列号，无法绑定")
        form.addRow("U 盘绑定", self.bind_check)

        self.shred_check = QCheckBox("加密后安全擦除源文件")
        form.addRow("源文件", self.shred_check)

        layout.addLayout(form)

        hint = QLabel("提示：口令一旦忘记，数据在密码学上无法恢复。")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("开始加密")
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _pick_path(self) -> None:
        current = Path(self.path_edit.text()).parent
        chosen = QFileDialog.getSaveFileName(
            self,
            "容器保存位置",
            str(current),
            f"ULocker 容器 (*{VAULT_EXT})",
        )
        if chosen and chosen[0]:
            target = chosen[0]
            if not target.lower().endswith(VAULT_EXT):
                target += VAULT_EXT
            self.path_edit.setText(target)

    def _on_accept(self) -> None:
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, "提示", "请填写容器名称")
            return
        if len(self.pwd_edit.text()) < C.PASSWORD_MIN_LEN:
            QMessageBox.warning(self, "提示", f"口令至少 {C.PASSWORD_MIN_LEN} 位")
            return
        if self.pwd_edit.text() != self.pwd2_edit.text():
            QMessageBox.warning(self, "提示", "两次输入的口令不一致")
            return
        self.accept()

    # ---------------------------------------------------------------- 结果
    @property
    def result_data(self) -> Dict[str, Any]:
        return {
            "name": self.name_edit.text().strip(),
            "path": Path(self.path_edit.text().strip()),
            "password": self.pwd_edit.text(),
            "kdf_id": int(self.kdf_combo.currentData()),
            "bind": bool(self.bind_check.isChecked()),
            "shred": bool(self.shred_check.isChecked()),
        }


class ChangePasswordDialog(QDialog):
    """修改口令。"""

    def __init__(self, parent: QWidget | None) -> None:
        super().__init__(parent)
        self.setWindowTitle("修改口令")
        self.setMinimumWidth(380)
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.pwd = QLineEdit()
        self.pwd.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("新口令", self.pwd)
        self.pwd2 = QLineEdit()
        self.pwd2.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("确认新口令", self.pwd2)

        self.kdf_combo = QComboBox()
        self.kdf_combo.addItem("保持原设置", None)
        self.kdf_combo.addItem("改成 Argon2id", C.KDF_ARGON2ID)
        self.kdf_combo.addItem("改成 scrypt", C.KDF_SCRYPT)
        form.addRow("密钥派生", self.kdf_combo)

        layout.addLayout(form)
        note = QLabel("修改口令只会重新包裹数据密钥，数据区不会重写，秒级完成。")
        note.setObjectName("hint")
        note.setWordWrap(True)
        layout.addWidget(note)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_accept(self) -> None:
        if len(self.pwd.text()) < C.PASSWORD_MIN_LEN:
            QMessageBox.warning(self, "提示", f"口令至少 {C.PASSWORD_MIN_LEN} 位")
            return
        if self.pwd.text() != self.pwd2.text():
            QMessageBox.warning(self, "提示", "两次输入的口令不一致")
            return
        self.accept()

    @property
    def password(self) -> str:
        return self.pwd.text()

    @property
    def kdf_id(self) -> Optional[int]:
        return self.kdf_combo.currentData()


# --------------------------------------------------------------------------- #
# 主窗口
# --------------------------------------------------------------------------- #


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"ULocker · U 盘加密  v{__version__}")
        self.resize(1080, 680)
        self.setAcceptDrops(True)

        self.vault: Optional[Vault] = None
        self.drive: Optional[DriveInfo] = None
        self.worker: Optional[Worker] = None

        self._build_ui()
        self.refresh_drives()

    # ------------------------------------------------------------ 界面搭建

    def _build_ui(self) -> None:
        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(14, 12, 14, 12)
        root.setSpacing(10)

        title = QLabel("ULocker · U 盘加密")
        title.setObjectName("title")
        root.addWidget(title)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_left())
        splitter.addWidget(self._build_right())
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([330, 750])
        root.addWidget(splitter, 1)

        self.setCentralWidget(central)
        self._build_status()

    def _build_left(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(10)

        group = QGroupBox("磁盘")
        gl = QVBoxLayout(group)
        row = QHBoxLayout()
        self.drive_combo = QComboBox()
        self.drive_combo.currentIndexChanged.connect(self._on_drive_changed)
        refresh = QPushButton("刷新")
        refresh.clicked.connect(self.refresh_drives)
        row.addWidget(self.drive_combo, 1)
        row.addWidget(refresh)
        gl.addLayout(row)
        self.drive_label = QLabel("")
        self.drive_label.setObjectName("hint")
        self.drive_label.setWordWrap(True)
        gl.addWidget(self.drive_label)
        layout.addWidget(group)

        group2 = QGroupBox("容器")
        gl2 = QVBoxLayout(group2)
        self.vault_list = QListWidget()
        self.vault_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.vault_list.itemDoubleClicked.connect(lambda _i: self.unlock_vault())
        gl2.addWidget(self.vault_list)

        btns = QHBoxLayout()
        new_btn = QPushButton("新建")
        new_btn.setObjectName("primary")
        new_btn.clicked.connect(self.create_vault_flow)
        open_btn = QPushButton("解锁")
        open_btn.clicked.connect(self.unlock_vault)
        find_btn = QPushButton("深度搜索")
        find_btn.setToolTip("在整个磁盘里递归查找容器（可能比较慢）")
        find_btn.clicked.connect(self.deep_search)
        btns.addWidget(new_btn)
        btns.addWidget(open_btn)
        btns.addWidget(find_btn)
        gl2.addLayout(btns)

        tip = QLabel("双击容器可直接解锁；也可以把文件拖进窗口来加密。")
        tip.setObjectName("hint")
        tip.setWordWrap(True)
        gl2.addWidget(tip)
        layout.addWidget(group2, 1)
        return panel

    def _build_right(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 0, 0, 0)
        layout.setSpacing(10)

        self.vault_label = QLabel("未打开容器")
        self.vault_label.setObjectName("title")
        layout.addWidget(self.vault_label)

        self.badge = QLabel("")
        self.badge.setObjectName("hint")
        self.badge.setWordWrap(True)
        layout.addWidget(self.badge)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["条目", "大小", "修改时间", "SHA-256"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in (1, 2, 3):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.table, 1)

        actions = QHBoxLayout()
        self.act_extract = QPushButton("解包…")
        self.act_add = QPushButton("追加文件…")
        self.act_delete = QPushButton("删除选中")
        self.act_delete.setObjectName("danger")
        self.act_password = QPushButton("改口令…")
        self.act_verify = QPushButton("校验完整性")
        self.act_close = QPushButton("锁定")
        for btn, slot in (
            (self.act_extract, self.extract_flow),
            (self.act_add, self.add_flow),
            (self.act_delete, self.delete_flow),
            (self.act_password, self.change_password_flow),
            (self.act_verify, self.verify_flow),
            (self.act_close, self.close_vault),
        ):
            btn.clicked.connect(slot)
            actions.addWidget(btn)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(500)
        self.log.setFixedHeight(110)
        self.log.setFont(QFont("Consolas", 9))
        layout.addWidget(self.log)

        self._set_actions_enabled(False)
        return panel

    def _build_status(self) -> None:
        bar = self.statusBar()
        self.progress = QProgressBar()
        self.progress.setFixedWidth(320)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setVisible(False)
        bar.addPermanentWidget(self.progress)
        bar.showMessage("就绪")

    def _set_actions_enabled(self, enabled: bool) -> None:
        for btn in (
            self.act_extract,
            self.act_add,
            self.act_delete,
            self.act_password,
            self.act_verify,
            self.act_close,
        ):
            btn.setEnabled(enabled)

    # ------------------------------------------------------------ 日志

    def note(self, text: str) -> None:
        self.log.appendPlainText(time.strftime("[%H:%M:%S] ") + text)

    def warn(self, text: str) -> None:
        self.note("⚠ " + text)

    def toast(self, title: str, text: str, kind: str = "info") -> None:
        if kind == "error":
            QMessageBox.critical(self, title, text)
        elif kind == "warn":
            QMessageBox.warning(self, title, text)
        else:
            QMessageBox.information(self, title, text)

    # ------------------------------------------------------------ 磁盘与容器

    def refresh_drives(self) -> None:
        self.drive_combo.blockSignals(True)
        self.drive_combo.clear()
        try:
            drives: List[DriveInfo] = list_drives(include_fixed=True)
        except Exception as exc:  # noqa: BLE001
            self.warn(f"枚举磁盘失败：{exc}")
            drives = []

        for info in drives:
            prefix = "U 盘" if info.is_removable else info.kind_text
            text = f"{prefix} · {info.root} {info.label}".strip()
            if info.total:
                text += f"  ({human_size(info.free)} 可用)"
            self.drive_combo.addItem(text, info)

        # 默认优先选中可移动磁盘
        for index in range(self.drive_combo.count()):
            if self.drive_combo.itemData(index).is_removable:
                self.drive_combo.setCurrentIndex(index)
                break
        self.drive_combo.blockSignals(False)
        self._on_drive_changed()

    def _on_drive_changed(self) -> None:
        info = self.drive_combo.currentData()
        self.drive = info
        if info is None:
            self.drive_label.setText("没有检测到磁盘")
            return
        detail = f"卷序列号：{info.serial or '不可用'}　文件系统：{info.filesystem or '未知'}"
        if info.total:
            detail += f"\n容量 {human_size(info.total)}，可用 {human_size(info.free)}"
        self.drive_label.setText(detail)
        self.refresh_vaults()

    def refresh_vaults(self) -> None:
        """只扫磁盘根目录——这是最常用的位置，而且不会卡住界面。"""
        self.vault_list.clear()
        if self.drive is None:
            return
        found = self._scan_vaults(self.drive.root, deep=False)
        for path in found:
            self._add_vault_item(path)
        if found:
            self.vault_list.setCurrentRow(0)
        self.note(f"{self.drive.root} 根目录下有 {len(found)} 个容器")

    def deep_search(self) -> None:
        """递归搜索整个磁盘，放到后台线程做。"""
        if self.drive is None:
            return
        root = self.drive.root
        self.run_task(
            f"搜索 {root} 下的容器",
            self._scan_vaults,
            root,
            deep=True,
            on_done=self._after_deep_search,
            status=f"正在扫描 {root} …",
        )

    @staticmethod
    def _scan_vaults(root: str, *, deep: bool = False) -> List[Path]:
        return find_vaults(root, max_depth=4 if deep else 0, recursive=deep)

    def _after_deep_search(self, found: Any) -> None:
        paths = list(found or [])
        known = {
            self.vault_list.item(row).data(Qt.ItemDataRole.UserRole)
            for row in range(self.vault_list.count())
        }
        added = 0
        for path in paths:
            if str(path) not in known:
                self._add_vault_item(path)
                added += 1
        self.note(f"深度搜索完成：共 {len(paths)} 个容器，新增 {added} 个")

    def _add_vault_item(self, path: Path) -> None:
        try:
            size = human_size(path.stat().st_size)
        except OSError:
            size = "?"
        item = QListWidgetItem(f"{path.name}\n{path.parent}　{size}")
        item.setData(Qt.ItemDataRole.UserRole, str(path))
        self.vault_list.addItem(item)

    def _selected_vault_path(self) -> Optional[Path]:
        item = self.vault_list.currentItem()
        if item is None:
            return None
        raw = item.data(Qt.ItemDataRole.UserRole)
        return Path(raw) if raw else None

    # ------------------------------------------------------------ 线程调度

    def run_task(
        self,
        label: str,
        fn: Callable[..., Any],
        *args: Any,
        on_done: Optional[Callable[[Any], None]] = None,
        status: str = "",
        **kwargs: Any,
    ) -> None:
        if self.worker is not None and self.worker.isRunning():
            self.toast("提示", "还有任务在进行中，请稍候", "warn")
            return

        self.progress.setVisible(True)
        # 先显示为“忙碌”状态，收到第一个进度回调后自动变成确定进度条
        self.progress.setRange(0, 0)
        self.progress.setValue(0)
        self.statusBar().showMessage(status or label)
        self.note(f"▶ {label}")

        worker = Worker(fn, *args, **kwargs)
        worker.progressed.connect(self._on_progress)
        worker.failed.connect(lambda msg: self._on_failed(label, msg))
        if on_done:
            worker.succeeded.connect(lambda result: self._on_success(label, result, on_done))
        else:
            worker.succeeded.connect(lambda result: self._on_success(label, result, None))
        self.worker = worker
        worker.start()

    def _on_progress(self, done: int, total: int, label: str) -> None:
        total = max(total, 1)
        if self.progress.maximum() == 0:
            self.progress.setRange(0, total)
        self.progress.setValue(min(done, total))
        self.statusBar().showMessage(
            f"{label}  {human_size(done)}/{human_size(total)}"
        )

    def _on_failed(self, label: str, message: str) -> None:
        self.progress.setVisible(False)
        self.statusBar().showMessage("失败")
        self.note(f"✗ {label} 失败：{message.splitlines()[0]}")
        self.toast("操作失败", message, "error")

    def _on_success(self, label: str, result: Any, on_done: Optional[Callable[[Any], None]]) -> None:
        self.progress.setVisible(False)
        self.statusBar().showMessage("就绪")
        self.note(f"✓ {label} 完成")
        if on_done:
            on_done(result)

    # ------------------------------------------------------------ 新建

    def create_vault_flow(self, preset_sources: Optional[Sequence[Path]] = None) -> None:
        default_dir = Path(self.drive.root) if self.drive else Path.home() / "Desktop"
        bind_available = bool(self.drive and self.drive.is_removable and self.drive.has_serial)
        dialog = NewVaultDialog(self, default_dir, bind_available)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        data = dialog.result_data

        if preset_sources is None:
            choice = QMessageBox.question(
                self,
                "选择要加密的内容",
                "是否现在选择要加密的文件或目录？\n（选「否」会创建一个空容器，以后再追加）",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            sources: List[Path] = []
            if choice == QMessageBox.StandardButton.Yes:
                sources = self._pick_sources()
                if not sources:
                    return
        else:
            sources = list(preset_sources)

        target = Path(data["path"])
        if target.exists():
            answer = QMessageBox.question(
                self,
                "容器已存在",
                f"{target.name} 已存在，要覆盖它吗？原内容将无法恢复。",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        self.run_task(
            "新建容器",
            create_vault,
            target,
            data["password"],
            [str(p) for p in sources],
            kdf_id=data["kdf_id"],
            vault_name=data["name"],
            bind_drive=True if data["bind"] else None,
            overwrite=True,
            shred_source=data["shred"],
            on_done=lambda info: self._after_create(info, data["password"]),
        )

    def _after_create(self, info: Any, password: str) -> None:
        for warn in info.warnings:
            self.warn(warn)
        self.note(
            f"容器 {info.name}：{info.entry_count} 个条目，"
            f"明文 {human_size(info.total_size)}"
        )

        # 让新建的容器出现在列表里并选中（可能在子目录，所以主动插入）
        target = str(info.path)
        known = {
            self.vault_list.item(row).data(Qt.ItemDataRole.UserRole)
            for row in range(self.vault_list.count())
        }
        if target not in known:
            self._add_vault_item(Path(target))
        for row in range(self.vault_list.count()):
            if self.vault_list.item(row).data(Qt.ItemDataRole.UserRole) == target:
                self.vault_list.setCurrentRow(row)
                break

        # 自动解锁刚建好的容器
        try:
            self._attach_vault(
                open_vault(info.path, password, ignore_drive_binding=True)
            )
        except ULockerError as exc:
            self.warn(f"自动解锁失败：{exc}")
        self.toast("完成", f"容器已创建：\n{info.path}")

    def _pick_sources(self) -> List[Path]:
        box = QMessageBox(self)
        box.setWindowTitle("选择内容")
        box.setText("要加密文件，还是整个目录？")
        file_btn = box.addButton("选择文件", QMessageBox.ButtonRole.AcceptRole)
        dir_btn = box.addButton("选择目录", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("取消", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        clicked = box.clickedButton()
        if clicked is file_btn:
            files, _ = QFileDialog.getOpenFileNames(self, "选择要加密的文件", str(Path.home()))
            return [Path(f) for f in files]
        if clicked is dir_btn:
            chosen = QFileDialog.getExistingDirectory(self, "选择要加密的目录", str(Path.home()))
            return [Path(chosen)] if chosen else []
        return []

    # ------------------------------------------------------------ 解锁 / 锁定

    def unlock_vault(self) -> None:
        path = self._selected_vault_path()
        if path is None:
            self.toast("提示", "请先在左侧选择一个容器", "warn")
            return

        try:
            meta = peek_vault(path)
        except ULockerError as exc:
            self.toast("无法读取容器", str(exc), "error")
            return

        if meta["drive_bound"]:
            self.note("该容器绑定了特定 U 盘，正在校验…")

        password, ok = QInputDialog.getText(
            self,
            "解锁容器",
            f"{path.name}\n请输入口令：",
            QInputDialog.EchoMode.Password,
        )
        if not ok or not password:
            return

        self.run_task(
            "解锁",
            open_vault,
            path,
            password,
            on_done=self._attach_vault,
        )

    def _attach_vault(self, vault: Vault) -> None:
        self.close_vault(quiet=True)
        self.vault = vault
        info = vault.info
        self.vault_label.setText(f"{info.name}  ·  {info.path}")
        badges = [
            f"{info.entry_count} 个条目",
            f"明文 {human_size(info.total_size)}",
            f"容器 {human_size(info.encrypted_size)}",
            f"密钥派生 {info.kdf_name}",
        ]
        if info.bound_drive:
            drive = info.bound_drive
            badges.append(
                f"绑定 {drive.get('label') or '(无卷标)'} / SN:{drive.get('serial')}"
            )
        self.badge.setText("　|　".join(badges))
        for warn in info.warnings:
            self.warn(warn)
        self.reload_entries()
        self._set_actions_enabled(True)
        self.note(f"已解锁 {info.name}")

    def close_vault(self, quiet: bool = False) -> None:
        if self.vault is not None:
            name = self.vault.name
            self.vault.close()
            self.vault = None
            if not quiet:
                self.note(f"已锁定 {name}")
        self.table.setRowCount(0)
        self.vault_label.setText("未打开容器")
        self.badge.setText("")
        self._set_actions_enabled(False)

    def reload_entries(self) -> None:
        entries: List[Entry] = self.vault.entries() if self.vault else []
        self.table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            name_item = QTableWidgetItem(entry.name)
            name_item.setData(Qt.ItemDataRole.UserRole, entry.name)
            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, QTableWidgetItem(human_size(entry.size)))
            when = (
                time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.mtime))
                if entry.mtime
                else "-"
            )
            self.table.setItem(row, 2, QTableWidgetItem(when))
            self.table.setItem(row, 3, QTableWidgetItem(entry.sha256[:16]))
        self.table.resizeRowsToContents()

    # ------------------------------------------------------------ 各操作

    def extract_flow(self) -> None:
        if self.vault is None:
            return
        dest = QFileDialog.getExistingDirectory(self, "解包到哪个目录", str(Path.home()))
        if not dest:
            return
        rows = sorted({index.row() for index in self.table.selectedIndexes()})
        names = [self.table.item(r, 0).text() for r in rows] if rows else None

        self.run_task(
            f"解包 {len(names) if names else '全部'} 个条目",
            self.vault.extract,
            names,
            dest,
            overwrite=True,
            on_done=self._after_extract,
        )

    def _after_extract(self, written: Any) -> None:
        paths = [Path(p) for p in written]
        self.note(f"已解包 {len(paths)} 个文件")
        if paths:
            self.toast("解包完成", f"已写出 {len(paths)} 个文件到：\n{paths[0].parent}")

    def add_flow(self, preset: Optional[Sequence[Path]] = None) -> None:
        if self.vault is None:
            return
        sources = list(preset) if preset else self._pick_sources()
        if not sources:
            return
        self.run_task(
            "追加文件",
            self.vault.add_paths,
            [str(p) for p in sources],
            on_done=self._after_add,
        )

    def _after_add(self, added: Any) -> None:
        count = len(added) if added is not None else 0
        self.reload_entries()
        self.toast("完成", f"已追加 {count} 个条目")

    def delete_flow(self) -> None:
        if self.vault is None:
            return
        rows = sorted({index.row() for index in self.table.selectedIndexes()})
        if not rows:
            self.toast("提示", "请先选中要删除的条目", "warn")
            return
        names = [self.table.item(r, 0).text() for r in rows]
        answer = QMessageBox.question(
            self,
            "确认删除",
            f"从容器中删除 {len(names)} 个条目？\n"
            "容器会被重新整理以回收空间，这一过程不可撤销。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.run_task(
            "删除条目",
            self.vault.delete_entries,
            names,
            on_done=lambda removed: self._after_delete(removed),
        )

    def _after_delete(self, removed: Any) -> None:
        self.reload_entries()
        self.toast("完成", f"已删除 {len(removed) if removed else 0} 个条目")

    def change_password_flow(self) -> None:
        if self.vault is None:
            return
        dialog = ChangePasswordDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self.run_task(
            "修改口令",
            self.vault.change_password,
            dialog.password,
            kdf_id=dialog.kdf_id,
            on_done=lambda _r: self.toast("完成", "口令已更新"),
        )

    def verify_flow(self) -> None:
        if self.vault is None:
            return
        self.run_task("校验完整性", self.vault.verify, on_done=self._after_verify)

    def _after_verify(self, report: Any) -> None:
        if report.ok:
            self.note(f"校验通过：{report.entries} 个条目 / {human_size(report.bytes)}")
            self.toast("校验通过", f"{report.entries} 个条目全部完整")
        else:
            detail = "\n".join(report.failed[:12])
            self.warn(f"校验发现 {len(report.failed)} 项异常")
            self.toast("校验失败", f"{len(report.failed)} 项异常：\n{detail}", "error")

    # ------------------------------------------------------------ 拖放

    def dragEnterEvent(self, event) -> None:  # noqa: N802 - Qt 命名
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:  # noqa: N802
        paths = [Path(url.toLocalFile()) for url in event.mimeData().urls() if url.isLocalFile()]
        paths = [p for p in paths if p.exists()]
        if not paths:
            return
        event.acceptProposedAction()
        names = "、".join(p.name for p in paths[:3])
        if self.vault is not None:
            self.add_flow(paths)
            self.note(f"拖入 {len(paths)} 个路径（{names}…）→ 追加")
        else:
            self.note(f"拖入 {len(paths)} 个路径（{names}…），当前没有打开容器")
            answer = QMessageBox.question(
                self,
                "还没有打开容器",
                f"要把这 {len(paths)} 个路径放进一个新容器吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer == QMessageBox.StandardButton.Yes:
                self.create_vault_flow(paths)

    def closeEvent(self, event) -> None:  # noqa: N802
        if self.worker is not None and self.worker.isRunning():
            answer = QMessageBox.question(
                self,
                "任务进行中",
                "还有任务没有完成，强制退出可能导致容器写入不完整。确定要退出吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        self.close_vault(quiet=True)
        event.accept()


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #


def main(argv: Optional[Sequence[str]] = None) -> int:
    if not HAS_QT:
        print(
            "启动图形界面需要 PyQt6，请先安装：\n"
            "    pip install PyQt6\n"
            "或者使用命令行：ulocker --help",
            file=sys.stderr,
        )
        return 1

    app = QApplication(list(argv) if argv else sys.argv[:1])
    app.setApplicationName("ULocker")
    app.setApplicationVersion(__version__)
    app.setStyleSheet(STYLE)

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
