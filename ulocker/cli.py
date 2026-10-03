"""ULocker 命令行界面。

设计上遵循「默认安全、显式覆盖」的原则：危险动作（覆盖已有容器、忽略 U 盘
绑定、擦除源文件）都必须显式给出选项才会执行。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence

from . import __version__
from . import crypto as C
from .drives import VAULT_EXT, drive_of, find_vaults, list_drives
from .errors import ULockerError
from .util import format_table, human_size, shred_file
from .vault import (
    create_vault,
    open_vault,
    peek_vault,
)

ENV_PASSWORD = "ULOCKER_PASSWORD"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


# --------------------------------------------------------------------------- #
# 输出
# --------------------------------------------------------------------------- #


class Console:
    """极简输出封装：支持彩色、静默与 JSON 模式。"""

    def __init__(self, *, quiet: bool = False, as_json: bool = False, color: Optional[bool] = None) -> None:
        self.quiet = quiet
        self.as_json = as_json
        if color is None:
            color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        self.color = bool(color)

    def _paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def ok(self, text: str) -> None:
        if not self.quiet and not self.as_json:
            print(self._paint("✓ ", "32") + text)

    def warn(self, text: str) -> None:
        if not self.quiet:
            print(self._paint("! ", "33") + text, file=sys.stderr)

    def note(self, text: str) -> None:
        if not self.quiet and not self.as_json:
            print("  " + text)

    def error(self, text: str) -> None:
        print(self._paint("✗ ", "31") + text, file=sys.stderr)

    def line(self, text: str = "") -> None:
        if not self.quiet and not self.as_json:
            print(text)

    def dump(self, payload: Any) -> None:
        print(json.dumps(payload, ensure_ascii=False, indent=2))


def make_progress(console: Console) -> Optional[Callable[[int, int, str], None]]:
    """生成一个单行刷新的进度条；静默 / JSON 模式下不输出。"""
    if console.quiet or console.as_json:
        return None

    state = {"last": 0.0, "drawn": False, "total": 0}

    def callback(done: int, total: int, label: str) -> None:
        now = time.monotonic()
        finished = total and done >= total
        if not finished and now - state["last"] < 0.05:
            return
        state["last"] = now
        if total != state["total"]:
            state["total"] = total
            state["drawn"] = False

        ratio = (done / total) if total else 1.0
        ratio = min(1.0, max(0.0, ratio))
        width = 26
        filled = int(width * ratio)
        bar = "█" * filled + "░" * (width - filled)
        text = (
            f"\r  [{bar}] {ratio * 100:5.1f}%  "
            f"{human_size(done)}/{human_size(total)}  {label[:36]:<36}"
        )
        sys.stderr.write(text)
        sys.stderr.flush()
        state["drawn"] = True

    return callback


def finish_progress(console: Console) -> None:
    if not console.quiet and not console.as_json:
        sys.stderr.write("\r" + " " * 96 + "\r")
        sys.stderr.flush()


# --------------------------------------------------------------------------- #
# 口令获取
# --------------------------------------------------------------------------- #


def read_password(args: argparse.Namespace, *, confirm: bool = False) -> str:
    """按 ``--password`` → 环境变量 → 交互输入 的顺序取口令。"""
    inline = getattr(args, "password", None)
    if inline:
        return inline

    from_env = os.environ.get(ENV_PASSWORD)
    if from_env:
        return from_env

    try:
        import getpass
    except ImportError:  # pragma: no cover
        raise ULockerError("当前环境无法交互输入口令，请使用 --password 或设置 ULOCKER_PASSWORD")

    if not sys.stdin.isatty():
        raise ULockerError(
            "非交互环境无法提示输入口令，请使用 --password 或设置 ULOCKER_PASSWORD 环境变量"
        )

    first = getpass.getpass("请输入口令：")
    if not first:
        raise ULockerError("口令不能为空")
    if confirm:
        again = getpass.getpass("请再次输入口令：")
        if again != first:
            raise ULockerError("两次输入的口令不一致")
    return first


# --------------------------------------------------------------------------- #
# 子命令实现
# --------------------------------------------------------------------------- #


def cmd_drives(args: argparse.Namespace, console: Console) -> int:
    drives = list_drives(include_fixed=not args.removable_only)
    if args.json:
        console.dump([d.to_json() for d in drives])
        return EXIT_OK
    if not drives:
        console.warn("没有找到任何磁盘")
        return EXIT_OK

    rows = []
    for d in drives:
        rows.append(
            [
                d.root,
                d.kind_text,
                d.label or "-",
                d.serial or "-",
                d.filesystem or "-",
                human_size(d.total) if d.total else "-",
                human_size(d.free) if d.total else "-",
            ]
        )
    console.line(format_table(rows, ["挂载点", "类型", "卷标", "卷序列号", "文件系统", "容量", "可用"]))
    return EXIT_OK


def cmd_find(args: argparse.Namespace, console: Console) -> int:
    root = args.where
    if not root and not args.json:
        removable = [d for d in list_drives(True) if d.is_removable]
        if len(removable) == 1:
            root = removable[0].root
            console.note(f"自动选中可移动磁盘 {root}")
    if not root:
        raise ULockerError("请指定要搜索的磁盘，例如：ulocker find E:\\")

    vaults = find_vaults(root, max_depth=args.depth, recursive=not args.no_recursive)
    if args.json:
        console.dump([str(p) for p in vaults])
        return EXIT_OK
    if not vaults:
        console.warn(f"{root} 下没有找到 {VAULT_EXT} 容器")
        return EXIT_OK

    rows = []
    for path in vaults:
        size = path.stat().st_size
        try:
            meta = peek_vault(path)
            kdf = meta["kdf_name"]
            bound = "已绑定" if meta["drive_bound"] else "未绑定"
            entries = "?"
        except ULockerError:
            kdf, bound, entries = "无法解析", "-", "-"
        rows.append([str(path), human_size(size), kdf, bound, entries])
    console.line(format_table(rows, ["容器文件", "大小", "密钥派生", "U 盘绑定", "条目"]))
    return EXIT_OK


def cmd_info(args: argparse.Namespace, console: Console) -> int:
    meta = peek_vault(args.vault)
    if args.json and not args.password and not os.environ.get(ENV_PASSWORD):
        console.dump(meta)
        return EXIT_OK

    if not args.password and not os.environ.get(ENV_PASSWORD):
        if args.json:
            console.dump(meta)
            return EXIT_OK
        console.line(f"容器文件   : {meta['path']}")
        console.line(f"格式版本   : {meta['version']}")
        console.line(f"密钥派生   : {meta['kdf_name']}")
        console.line(f"U 盘绑定   : {'是' if meta['drive_bound'] else '否'}")
        console.line(f"文件大小   : {human_size(meta['file_size'])}")
        console.line(f"头部大小   : {human_size(meta['header_size'])}")
        console.note("（输入口令可查看完整信息，如：ulocker info <容器> -p 你的口令）")
        return EXIT_OK

    password = read_password(args)
    with open_vault(args.vault, password, ignore_drive_binding=args.ignore_drive_binding) as vault:
        if args.json:
            console.dump(vault.info.to_json())
        else:
            console.line(vault.info.describe())
            console.line()
            _print_entries(console, vault, limit=args.limit)
    return EXIT_OK


def _print_entries(console: Console, vault, limit: int = 0) -> None:
    entries = vault.entries()
    if not entries:
        console.line("（容器为空）")
        return
    rows = []
    for index, entry in enumerate(entries):
        if limit and index >= limit:
            rows.append(["…", f"还有 {len(entries) - limit} 个条目", "", ""])
            break
        rows.append(
            [
                entry.name,
                human_size(entry.size),
                time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.mtime)) if entry.mtime else "-",
                entry.sha256[:12],
            ]
        )
    console.line(format_table(rows, ["条目", "大小", "修改时间", "SHA-256"]))


def cmd_new(args: argparse.Namespace, console: Console) -> int:
    vault_path = Path(args.vault).expanduser()
    bind: Any = None
    bind_note = "未绑定 U 盘"

    if args.bind_serial:
        bind = args.bind_serial
        bind_note = f"绑定到卷序列号 {args.bind_serial}"
    elif args.no_bind:
        bind_note = "未绑定 U 盘（已用 --no-bind 指定）"
    else:
        info = drive_of(vault_path)
        if info is not None and info.is_removable:
            bind = True
            bind_note = f"绑定到 U 盘 {info.root} {info.label or ''} SN:{info.serial}".strip()
        elif info is not None:
            bind_note = f"{info.root} 是本地磁盘，默认不做绑定（可用 --bind 强制）"

    if args.bind and not args.bind_serial:
        bind = True
        info = drive_of(vault_path)
        if info is None:
            raise ULockerError("无法识别目标磁盘，无法绑定")
        bind_note = f"绑定到 {info.root} SN:{info.serial}"

    password = read_password(args, confirm=True)

    kdf_id = C.resolve_kdf(args.kdf) if args.kdf else C.pick_default_kdf()
    overrides: Dict[str, Any] = {}
    if args.argon2_memory:
        overrides["memory_cost"] = int(args.argon2_memory)
    if args.argon2_time:
        overrides["time_cost"] = int(args.argon2_time)
    if args.scrypt_n:
        overrides["n"] = int(args.scrypt_n)

    console.note(f"密钥派生：{C.KDF_NAMES.get(kdf_id, kdf_id)}")
    console.note(f"U 盘绑定：{bind_note}")
    if args.shred_source:
        console.warn("已启用源文件擦除：加密完成后源文件将被覆写删除")

    info = create_vault(
        vault_path,
        password,
        args.paths,
        kdf_id=kdf_id,
        kdf_overrides=overrides,
        vault_name=args.name,
        bind_drive=bind,
        progress=make_progress(console),
        overwrite=args.force,
        shred_source=args.shred_source,
        shred_passes=args.shred_passes,
        follow_symlinks=args.follow_symlinks,
    )
    finish_progress(console)

    if args.json:
        console.dump(info.to_json())
        return EXIT_OK

    console.ok(
        f"已创建容器 {info.path}（{info.entry_count} 个条目，"
        f"明文 {human_size(info.total_size)} → 加密后 {human_size(info.encrypted_size)}）"
    )
    for warn in info.warnings:
        console.warn(warn)
    return EXIT_OK


def cmd_add(args: argparse.Namespace, console: Console) -> int:
    password = read_password(args)
    with open_vault(args.vault, password, ignore_drive_binding=args.ignore_drive_binding) as vault:
        added = vault.add_paths(
            args.paths,
            progress=make_progress(console),
            follow_symlinks=args.follow_symlinks,
            shred_source=args.shred_source,
            shred_passes=args.shred_passes,
        )
        finish_progress(console)
        if args.json:
            console.dump([e.to_json() for e in added])
            return EXIT_OK
        total = sum(e.size for e in added)
        console.ok(f"已追加 {len(added)} 个条目（{human_size(total)}）")
        for warn in vault.warnings:
            console.warn(warn)
    return EXIT_OK


def cmd_list(args: argparse.Namespace, console: Console) -> int:
    password = read_password(args)
    with open_vault(args.vault, password, ignore_drive_binding=args.ignore_drive_binding) as vault:
        entries = vault.entries()
        if args.json:
            console.dump([e.to_json() for e in entries])
            return EXIT_OK
        _print_entries(console, vault, limit=args.limit)
        console.line()
        console.note(
            f"共 {len(entries)} 个条目，明文合计 {human_size(sum(e.size for e in entries))}"
        )
    return EXIT_OK


def cmd_extract(args: argparse.Namespace, console: Console) -> int:
    password = read_password(args)
    names = args.names or None
    with open_vault(args.vault, password, ignore_drive_binding=args.ignore_drive_binding) as vault:
        written = vault.extract(
            names,
            args.dest,
            progress=make_progress(console),
            overwrite=args.force,
        )
        finish_progress(console)
        if args.json:
            console.dump([str(p) for p in written])
            return EXIT_OK
        console.ok(f"已解包 {len(written)} 个文件到 {Path(args.dest).resolve()}")
        if args.verify_after:
            report = vault.verify(progress=make_progress(console))
            finish_progress(console)
            if report.ok:
                console.ok(f"校验通过（{report.entries} 个条目）")
            else:
                console.error(f"校验失败 {len(report.failed)} 项：")
                for item in report.failed:
                    console.note(item)
                return EXIT_ERROR
    return EXIT_OK


def cmd_del(args: argparse.Namespace, console: Console) -> int:
    password = read_password(args)
    if not args.force:
        answer = input(f"确认从容器中删除 {len(args.names)} 个条目？(yes/N) ").strip().lower()
        if answer not in ("yes", "y"):
            console.warn("已取消")
            return EXIT_OK
    with open_vault(args.vault, password, ignore_drive_binding=args.ignore_drive_binding) as vault:
        removed = vault.delete_entries(args.names, progress=make_progress(console))
        finish_progress(console)
        if args.json:
            console.dump(removed)
            return EXIT_OK
        console.ok(f"已删除 {len(removed)} 个条目，容器已整理")
    return EXIT_OK


def cmd_passwd(args: argparse.Namespace, console: Console) -> int:
    old = read_password(args)
    console.note("容器已解锁，请输入新口令")
    new_args = argparse.Namespace(password=None)
    new = read_password(new_args, confirm=True)

    with open_vault(args.vault, old, ignore_drive_binding=args.ignore_drive_binding) as vault:
        kdf_id = C.resolve_kdf(args.kdf) if args.kdf else None
        vault.change_password(new, kdf_id=kdf_id, progress=make_progress(console))
        finish_progress(console)
        console.ok("口令已更新（数据区未重新加密，秒级完成）")
    return EXIT_OK


def cmd_verify(args: argparse.Namespace, console: Console) -> int:
    password = read_password(args)
    with open_vault(args.vault, password, ignore_drive_binding=args.ignore_drive_binding) as vault:
        report = vault.verify(progress=make_progress(console))
        finish_progress(console)
        if args.json:
            console.dump(
                {
                    "entries": report.entries,
                    "bytes": report.bytes,
                    "ok": report.ok,
                    "failed": report.failed,
                }
            )
            return EXIT_OK if report.ok else EXIT_ERROR
        if report.ok:
            console.ok(
                f"全部校验通过：{report.entries} 个条目 / {human_size(report.bytes)}"
            )
            return EXIT_OK
        console.error(f"发现 {len(report.failed)} 项异常：")
        for item in report.failed:
            console.note(item)
        return EXIT_ERROR


def cmd_shred(args: argparse.Namespace, console: Console) -> int:
    if not args.force:
        answer = input(f"确认安全擦除 {len(args.paths)} 个路径？此操作不可撤销 (yes/N) ").strip().lower()
        if answer not in ("yes", "y"):
            console.warn("已取消")
            return EXIT_OK
    total = 0
    for raw in args.paths:
        path = Path(raw).expanduser()
        if path.is_dir():
            console.warn(f"跳过目录（请自行列出其中的文件）：{path}")
            continue
        total += shred_file(path, passes=args.passes, progress=make_progress(console))
        finish_progress(console)
        console.ok(f"已擦除 {path}")
    console.note(f"共覆写 {human_size(total)}")
    return EXIT_OK


def cmd_gui(args: argparse.Namespace, console: Console) -> int:
    from .gui import main as gui_main

    return gui_main()


# --------------------------------------------------------------------------- #
# 参数解析
# --------------------------------------------------------------------------- #


def _add_password_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-p",
        "--password",
        help=f"直接提供口令（会出现在命令历史里，建议改用 {ENV_PASSWORD} 环境变量或交互输入）",
    )
    parser.add_argument(
        "--ignore-drive-binding",
        action="store_true",
        help="忽略 U 盘绑定校验（换盘后强制打开）",
    )


def _shared_options() -> argparse.ArgumentParser:
    """全局选项的“父解析器”。

    每个子命令都把它挂成 parent，这样 ``--json`` 既能写在子命令前面，
    也能写在后面。这里用 ``SUPPRESS`` 作为默认值，避免子解析器的默认值
    把主解析器已经解析出来的结果覆盖掉。
    """
    base = argparse.ArgumentParser(add_help=False)
    base.add_argument(
        "-q", "--quiet", action="store_true", default=argparse.SUPPRESS,
        help="只输出错误信息",
    )
    base.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS,
        help="以 JSON 输出结果",
    )
    base.add_argument(
        "--no-color", action="store_true", default=argparse.SUPPRESS,
        help="禁用彩色输出",
    )
    return base


def build_parser() -> argparse.ArgumentParser:
    shared = _shared_options()
    parser = argparse.ArgumentParser(
        prog="ulocker",
        description="ULocker —— U 盘加密软件：把文件装进 AES-256-GCM 加密容器，可绑定到指定 U 盘。",
        epilog="示例：ulocker new E:\\secret.ulocker D:\\projects  然后  ulocker extract E:\\secret.ulocker -C D:\\restore",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[shared],
    )
    parser.set_defaults(quiet=False, json=False, no_color=False)
    parser.add_argument("-V", "--version", action="version", version=f"ULocker {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="<命令>")

    p = sub.add_parser("drives", parents=[shared], help="列出磁盘（含 U 盘卷序列号）")
    p.add_argument("-r", "--removable-only", action="store_true", help="只看可移动磁盘")
    p.set_defaults(func=cmd_drives)

    p = sub.add_parser("find", parents=[shared], help="在某个磁盘里搜索 .ulocker 容器")
    p.add_argument("where", nargs="?", help="搜索起点，例如 E:\\（留空则自动选可移动磁盘）")
    p.add_argument("--depth", type=int, default=2, help="最大递归深度（默认 2）")
    p.add_argument("--no-recursive", action="store_true", help="只在顶层目录搜索")
    p.set_defaults(func=cmd_find)

    p = sub.add_parser("info", parents=[shared], help="查看容器信息（不带口令只看头部）")
    p.add_argument("vault", help="容器文件路径")
    p.add_argument("--limit", type=int, default=0, help="最多列出多少条目（0 = 全部）")
    _add_password_option(p)
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("new", parents=[shared], help="新建容器并加密文件/目录")
    p.add_argument("vault", help="容器文件路径（可省略扩展名，会自动补 .ulocker）")
    p.add_argument("paths", nargs="*", help="要加密的文件或目录")
    p.add_argument("--name", help="容器显示名（默认取文件名）")
    p.add_argument("-f", "--force", action="store_true", help="覆盖已存在的容器")
    p.add_argument("--kdf", choices=["argon2id", "scrypt"], help="密钥派生算法（默认 argon2id）")
    p.add_argument("--argon2-memory", type=int, help="Argon2id 内存开销（KiB）")
    p.add_argument("--argon2-time", type=int, help="Argon2id 迭代轮数")
    p.add_argument("--scrypt-n", type=int, help="scrypt 的 n 参数")
    p.add_argument("--bind", action="store_true", help="强制绑定到容器所在磁盘")
    p.add_argument("--no-bind", action="store_true", help="不绑定 U 盘")
    p.add_argument("--bind-serial", help="按卷序列号绑定（如 1A2B3C4D）")
    p.add_argument("--shred-source", action="store_true", help="加密后安全擦除源文件")
    p.add_argument("--shred-passes", type=int, default=1, help="源文件覆写遍数（默认 1）")
    p.add_argument("--follow-symlinks", action="store_true", help="跟随符号链接（默认跳过）")
    _add_password_option(p)
    p.set_defaults(func=cmd_new)

    p = sub.add_parser("add", parents=[shared], help="向已有容器追加文件")
    p.add_argument("vault")
    p.add_argument("paths", nargs="+")
    p.add_argument("--shred-source", action="store_true", help="追加后安全擦除源文件")
    p.add_argument("--shred-passes", type=int, default=1)
    p.add_argument("--follow-symlinks", action="store_true")
    _add_password_option(p)
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("list", parents=[shared], help="列出容器中的条目")
    p.add_argument("vault")
    p.add_argument("--limit", type=int, default=0, help="最多列出多少条目（0 = 全部）")
    _add_password_option(p)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("extract", parents=[shared], help="把容器内容解密到目录")
    p.add_argument("vault")
    p.add_argument("names", nargs="*", help="只解包这些条目（默认全部）")
    p.add_argument("-C", "--dest", default=".", help="输出目录（默认当前目录）")
    p.add_argument("-f", "--force", action="store_true", help="同名文件直接覆盖（默认自动改名）")
    p.add_argument("--verify-after", action="store_true", help="解包后再整体校验一遍")
    _add_password_option(p)
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("del", parents=[shared], help="删除容器中的条目并回收空间")
    p.add_argument("vault")
    p.add_argument("names", nargs="+")
    p.add_argument("-f", "--force", action="store_true", help="不再二次确认")
    _add_password_option(p)
    p.set_defaults(func=cmd_del)

    p = sub.add_parser("passwd", parents=[shared], help="修改容器口令")
    p.add_argument("vault")
    p.add_argument("--kdf", choices=["argon2id", "scrypt"], help="顺便切换密钥派生算法")
    _add_password_option(p)
    p.set_defaults(func=cmd_passwd)

    p = sub.add_parser("verify", parents=[shared], help="校验容器完整性")
    p.add_argument("vault")
    _add_password_option(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("shred", parents=[shared], help="安全擦除文件（覆写后删除）")
    p.add_argument("paths", nargs="+")
    p.add_argument("--passes", type=int, default=1, help="覆写遍数（默认 1）")
    p.add_argument("-f", "--force", action="store_true", help="不再二次确认")
    p.set_defaults(func=cmd_shred)

    p = sub.add_parser("gui", parents=[shared], help="启动图形界面")
    p.set_defaults(func=cmd_gui)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE

    console = Console(
        quiet=getattr(args, "quiet", False),
        as_json=getattr(args, "json", False),
        color=False if getattr(args, "no_color", False) else None,
    )

    try:
        return int(args.func(args, console) or EXIT_OK)
    except KeyboardInterrupt:
        finish_progress(console)
        console.error("已中断")
        return 130
    except ULockerError as exc:
        finish_progress(console)
        console.error(str(exc))
        return EXIT_ERROR
    except OSError as exc:
        finish_progress(console)
        console.error(f"文件系统错误：{exc}")
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
