import os
from pathlib import Path
import pytest
from click.testing import CliRunner

from secretbox.cli import cli


@pytest.fixture
def app_env(tmp_path, tmp_session_dir, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    (home / "data").mkdir()
    monkeypatch.setenv("SECRETBOX_HOME", str(home))
    return home


def test_status_logged_out(app_env):
    r = CliRunner().invoke(cli, ["status"])
    assert r.exit_code == 0
    assert "logged_in: False" in r.output


def test_login_no_files_yet(app_env, gpg_passphrase):
    r = CliRunner().invoke(cli, ["login"], input=f"{gpg_passphrase}\n")
    assert r.exit_code == 3
    assert "add a file first" in r.output.lower()


def test_add_then_list_then_cat(app_env, gpg_passphrase, tmp_path):
    src = tmp_path / "note.txt"
    src.write_text("hello")
    runner = CliRunner()
    r = runner.invoke(cli, ["add", str(src)], input=f"{gpg_passphrase}\n")
    assert r.exit_code == 0, r.output

    r = runner.invoke(cli, ["list"])
    assert r.exit_code == 0
    assert "note.txt" in r.output

    r = runner.invoke(cli, ["login"], input=f"{gpg_passphrase}\n")
    assert r.exit_code == 0

    r = runner.invoke(cli, ["cat", "note.txt"])
    assert r.exit_code == 0
    assert "hello" in r.output


def test_wrong_passphrase_on_login_does_not_write_session(
    app_env, gpg_passphrase, wrong_passphrase, tmp_path
):
    src = tmp_path / "note.txt"
    src.write_text("hello")
    runner = CliRunner()
    runner.invoke(cli, ["add", str(src)], input=f"{gpg_passphrase}\n")

    r = runner.invoke(cli, ["login"], input=f"{wrong_passphrase}\n")
    assert r.exit_code == 1
    r = runner.invoke(cli, ["status"])
    assert "logged_in: False" in r.output


def test_cat_without_login_prompts(app_env, gpg_passphrase, tmp_path):
    src = tmp_path / "note.txt"
    src.write_text("hello")
    runner = CliRunner()
    runner.invoke(cli, ["add", str(src)], input=f"{gpg_passphrase}\n")
    r = runner.invoke(cli, ["cat", "note.txt"], input=f"{gpg_passphrase}\n")
    assert r.exit_code == 0
    assert "hello" in r.output


def test_cat_missing_entry(app_env, gpg_passphrase, tmp_path):
    src = tmp_path / "n.txt"
    src.write_text("x")
    runner = CliRunner()
    runner.invoke(cli, ["add", str(src)], input=f"{gpg_passphrase}\n")
    runner.invoke(cli, ["login"], input=f"{gpg_passphrase}\n")
    r = runner.invoke(cli, ["cat", "nope"])
    assert r.exit_code == 2
    assert "no such entry" in r.output.lower()


def test_add_refuses_overwrite(app_env, gpg_passphrase, tmp_path):
    src1 = tmp_path / "n.txt"
    src1.write_text("v1")
    runner = CliRunner()
    runner.invoke(cli, ["add", str(src1)], input=f"{gpg_passphrase}\n")
    src2 = tmp_path / "n.txt"
    src2.write_text("v2")
    r = runner.invoke(cli, ["add", str(src2)], input=f"{gpg_passphrase}\n")
    assert r.exit_code == 3
    assert "exists" in r.output.lower()


def test_rm_with_yes(app_env, gpg_passphrase, tmp_path):
    src = tmp_path / "n.txt"
    src.write_text("x")
    runner = CliRunner()
    runner.invoke(cli, ["add", str(src)], input=f"{gpg_passphrase}\n")
    r = runner.invoke(cli, ["rm", "n.txt", "--yes"])
    assert r.exit_code == 0
    r = runner.invoke(cli, ["list"])
    assert "n.txt" not in r.output


def test_logout(app_env, gpg_passphrase, tmp_path):
    src = tmp_path / "n.txt"
    src.write_text("x")
    runner = CliRunner()
    runner.invoke(cli, ["add", str(src)], input=f"{gpg_passphrase}\n")
    runner.invoke(cli, ["login"], input=f"{gpg_passphrase}\n")
    r = runner.invoke(cli, ["logout"])
    assert r.exit_code == 0
    r = runner.invoke(cli, ["status"])
    assert "logged_in: False" in r.output
