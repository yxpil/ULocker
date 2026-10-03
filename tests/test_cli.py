"""命令行界面的测试。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ulocker.cli import EXIT_ERROR, EXIT_OK, EXIT_USAGE, main

from conftest import OTHER_PASSWORD, PASSWORD


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """避免外部环境变量干扰口令读取路径。"""
    monkeypatch.delenv("ULOCKER_PASSWORD", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)


def run(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def make_source(tmp_path: Path, name: str = "note.txt", body: str = "hello") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


class TestBasic:
    def test_no_arguments_shows_help(self, capsys) -> None:
        code, out, _ = run(capsys)
        assert code == EXIT_USAGE
        assert "ULocker" in out

    def test_version(self, capsys) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0

    def test_unknown_command(self, capsys) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["definitely-not-a-command"])
        assert exc.value.code == 2

    def test_drives_json(self, capsys) -> None:
        code, out, _ = run(capsys, "drives", "--json")
        assert code == EXIT_OK
        payload = json.loads(out)
        assert isinstance(payload, list)

    def test_drives_text(self, capsys) -> None:
        code, out, _ = run(capsys, "drives", "--no-color")
        assert code == EXIT_OK
        assert "挂载点" in out


class TestLifecycle:
    def test_new_list_extract_verify(self, tmp_path: Path, capsys) -> None:
        src = make_source(tmp_path, "机密.txt", "这是机密内容\n")
        vault = tmp_path / "v.ulocker"

        code, out, _ = run(
            capsys,
            "new",
            str(vault),
            str(src),
            "-p",
            PASSWORD,
            "--no-bind",
            "--json",
            "--argon2-memory",
            "64",
            "--argon2-time",
            "1",
        )
        assert code == EXIT_OK
        info = json.loads(out)
        assert info["entry_count"] == 1
        assert vault.exists()

        code, out, _ = run(capsys, "list", str(vault), "-p", PASSWORD, "--json")
        assert code == EXIT_OK
        entries = json.loads(out)
        assert [e["name"] for e in entries] == ["机密.txt"]

        dest = tmp_path / "out"
        code, out, _ = run(
            capsys, "extract", str(vault), "-p", PASSWORD, "-C", str(dest), "--json"
        )
        assert code == EXIT_OK
        written = json.loads(out)
        assert len(written) == 1
        assert (dest / "机密.txt").read_text(encoding="utf-8") == "这是机密内容\n"

        code, out, _ = run(capsys, "verify", str(vault), "-p", PASSWORD, "--json")
        assert code == EXIT_OK
        report = json.loads(out)
        assert report["ok"] is True

    def test_add_and_del(self, tmp_path: Path, capsys) -> None:
        first = make_source(tmp_path, "a.txt", "A")
        second = make_source(tmp_path, "b.txt", "B")
        vault = tmp_path / "v.ulocker"
        run(capsys, "new", str(vault), str(first), "-p", PASSWORD, "--no-bind",
            "--argon2-memory", "64",
            "--argon2-time", "1", "--json")

        code, out, _ = run(capsys, "add", str(vault), str(second), "-p", PASSWORD, "--json")
        assert code == EXIT_OK
        assert len(json.loads(out)) == 1

        code, out, _ = run(capsys, "del", str(vault), "a.txt", "-p", PASSWORD, "-f", "--json")
        assert code == EXIT_OK
        assert json.loads(out) == ["a.txt"]

        code, out, _ = run(capsys, "list", str(vault), "-p", PASSWORD, "--json")
        assert [e["name"] for e in json.loads(out)] == ["b.txt"]

    def test_passwd(self, tmp_path: Path, capsys, monkeypatch) -> None:
        src = make_source(tmp_path)
        vault = tmp_path / "v.ulocker"
        run(capsys, "new", str(vault), str(src), "-p", PASSWORD, "--no-bind",
            "--argon2-memory", "64",
            "--argon2-time", "1", "--json")

        monkeypatch.setenv("ULOCKER_PASSWORD", OTHER_PASSWORD)
        code, _, _ = run(capsys, "passwd", str(vault), "-p", PASSWORD)
        assert code == EXIT_OK
        monkeypatch.delenv("ULOCKER_PASSWORD")

        assert run(capsys, "list", str(vault), "-p", PASSWORD)[0] == EXIT_ERROR
        assert run(capsys, "list", str(vault), "-p", OTHER_PASSWORD)[0] == EXIT_OK

    def test_find(self, tmp_path: Path, capsys) -> None:
        vault = tmp_path / "v.ulocker"
        run(capsys, "new", str(vault), "-p", PASSWORD, "--no-bind",
            "--argon2-memory", "64",
            "--argon2-time", "1", "--json")

        code, out, _ = run(capsys, "find", str(tmp_path), "--json")
        assert code == EXIT_OK
        assert json.loads(out) == [str(vault)]


class TestErrors:
    def test_wrong_password(self, tmp_path: Path, capsys) -> None:
        src = make_source(tmp_path)
        vault = tmp_path / "v.ulocker"
        run(capsys, "new", str(vault), str(src), "-p", PASSWORD, "--no-bind",
            "--argon2-memory", "64",
            "--argon2-time", "1", "--json")

        code, _, err = run(capsys, "list", str(vault), "-p", "wrong password here")
        assert code == EXIT_ERROR
        assert "口令" in err

    def test_missing_vault(self, tmp_path: Path, capsys) -> None:
        code, _, err = run(capsys, "list", str(tmp_path / "nope.ulocker"), "-p", PASSWORD)
        assert code == EXIT_ERROR
        assert "不存在" in err

    def test_new_refuses_overwrite(self, tmp_path: Path, capsys) -> None:
        vault = tmp_path / "v.ulocker"
        common = ("-p", PASSWORD, "--no-bind",
                  "--argon2-memory", "64",
                  "--argon2-time", "1", "--json")
        assert run(capsys, "new", str(vault), *common)[0] == EXIT_OK
        assert run(capsys, "new", str(vault), *common)[0] == EXIT_ERROR
        assert run(capsys, "new", str(vault), "--force", *common)[0] == EXIT_OK

    def test_extract_unknown_entry(self, tmp_path: Path, capsys) -> None:
        vault = tmp_path / "v.ulocker"
        run(capsys, "new", str(vault), "-p", PASSWORD, "--no-bind",
            "--argon2-memory", "64",
            "--argon2-time", "1", "--json")
        code, _, err = run(
            capsys, "extract", str(vault), "ghost.txt", "-p", PASSWORD, "-C", str(tmp_path / "o")
        )
        assert code == EXIT_ERROR
        assert "不存在" in err

    def test_verify_detects_corruption(self, tmp_path: Path, capsys) -> None:
        src = make_source(tmp_path, "a.txt", "payload")
        vault = tmp_path / "v.ulocker"
        run(capsys, "new", str(vault), str(src), "-p", PASSWORD, "--no-bind",
            "--argon2-memory", "64",
            "--argon2-time", "1", "--json")

        from ulocker.vault import peek_vault

        offset = peek_vault(vault)["data_offset"] + 17
        with vault.open("r+b") as fh:
            fh.seek(offset)
            fh.write(bytes([fh.read(1)[0] ^ 0xFF]))

        code, out, _ = run(capsys, "verify", str(vault), "-p", PASSWORD, "--json")
        assert code == EXIT_ERROR
        assert json.loads(out)["ok"] is False

    def test_shred(self, tmp_path: Path, capsys) -> None:
        victim = make_source(tmp_path, "burn.txt", "bye")
        code, _, _ = run(capsys, "shred", str(victim), "-f", "--no-color")
        assert code == EXIT_OK
        assert not victim.exists()


class TestInfoCommand:
    def test_info_without_password(self, tmp_path: Path, capsys) -> None:
        vault = tmp_path / "v.ulocker"
        run(capsys, "new", str(vault), "-p", PASSWORD, "--no-bind",
            "--argon2-memory", "64",
            "--argon2-time", "1", "--json")

        code, out, _ = run(capsys, "info", str(vault), "--json")
        assert code == EXIT_OK
        payload = json.loads(out)
        assert payload["drive_bound"] is False
        assert payload["kdf_name"] == "argon2id"

    def test_info_with_password(self, tmp_path: Path, capsys) -> None:
        src = make_source(tmp_path)
        vault = tmp_path / "v.ulocker"
        run(capsys, "new", str(vault), str(src), "-p", PASSWORD, "--no-bind",
            "--argon2-memory", "64",
            "--argon2-time", "1", "--json")

        code, out, _ = run(capsys, "info", str(vault), "-p", PASSWORD, "--json")
        assert code == EXIT_OK
        payload = json.loads(out)
        assert payload["entry_count"] == 1
        assert payload["kdf_params"]["salt"] == "<已省略>"

    def test_info_text_output(self, tmp_path: Path, capsys) -> None:
        vault = tmp_path / "v.ulocker"
        run(capsys, "new", str(vault), "-p", PASSWORD, "--no-bind",
            "--argon2-memory", "64",
            "--argon2-time", "1", "--json")
        code, out, _ = run(capsys, "info", str(vault), "-p", PASSWORD, "--no-color")
        assert code == EXIT_OK
        assert "密钥派生" in out
        assert "容器为空" in out


class TestShredSourceOption:
    def test_new_with_shred(self, tmp_path: Path, capsys) -> None:
        src = make_source(tmp_path, "gone.txt", "sensitive")
        vault = tmp_path / "v.ulocker"
        code, _, _ = run(
            capsys, "new", str(vault), str(src), "-p", PASSWORD, "--no-bind",
            "--shred-source",
            "--argon2-memory", "64",
            "--argon2-time", "1", "--json",
        )
        assert code == EXIT_OK
        assert not src.exists()
